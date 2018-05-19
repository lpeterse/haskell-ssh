{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server ( serve ) where

import           Control.Concurrent.Async
import           Control.Concurrent.STM.TChan
import           Control.Exception
import           Control.Monad
import           Control.Monad.IO.Class
import           Control.Monad.STM
import qualified Crypto.Cipher.ChaCha          as ChaCha
import qualified Crypto.Hash                   as Hash
import qualified Crypto.MAC.Poly1305           as Poly1305
import qualified Crypto.PubKey.Curve25519      as Curve25519
import qualified Crypto.PubKey.Ed25519         as Ed25519
import           Crypto.Random.Types           (MonadRandom)
import qualified Data.Binary                   as B
import qualified Data.Binary.Get               as B
import qualified Data.Binary.Put               as B
import           Data.Bits
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Lazy          as LBS
import           Data.Monoid                   ((<>))
import           Data.Typeable
import           Data.Word

import           Network.SSH.Constants
import           Network.SSH.DuplexStream
import           Network.SSH.Exception
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Server.Config
import qualified Network.SSH.Server.Config     as Config
import           Network.SSH.Server.Connection
import qualified Network.SSH.Server.Connection as Connection

serve :: (DuplexStream stream) => Config identity -> stream -> IO ()
serve config stream = do
    let serverPrivateKey = hostKey config
        serverPublicKey  = case serverPrivateKey of
            Ed25519PrivateKey pk __ -> PublicKeyEd25519 pk

    -- Generate an Ed25519 keypair for elliptic curve Diffie-Hellman
    -- key exchange.
    serverEphemeralSecretKey <- Curve25519.generateSecretKey
    serverEphemeralPublicKey <- pure (Curve25519.toPublic serverEphemeralSecretKey)

    -- The maximum length of the version string is 255 chars including CR+LF.
    -- Parsing in chunks of 32 bytes in order to not allocate unnecessarly
    -- much memory. The version string is usually short and transmitted within
    -- a single TCP segment.
    (clientVersion, rem1) <- receiveGetter stream B.get (BA.empty :: BA.Bytes)

    -- Reply by sending the server version string.
    sendPutter stream $ B.put version

    -- Send KexInit to client.
    serverKexInit <- kexInit <$> newCookie
    sendPutter stream $ packetize $ B.put serverKexInit

    -- Receive KexInit from client.
    (clientKexInit, rem2) <- receiveGetter stream (unpacketize B.get) rem1

    -- Receive KexEcdhInit from client.
    (KexEcdhInit clientEphemeralPublicKey, rem3) <- receiveGetter stream (unpacketize B.get) rem2

    -- Compute and perform the Diffie-Helman key exchange.
    let dhSecret = Curve25519.dh clientEphemeralPublicKey serverEphemeralSecretKey
        hash = exchangeHash
            clientVersion
            version
            clientKexInit
            serverKexInit
            serverPublicKey
            clientEphemeralPublicKey
            serverEphemeralPublicKey
            dhSecret
        session = SessionId (BS.pack $ BA.unpack hash)
        signature = case serverPrivateKey of
            Ed25519PrivateKey pk sk -> SignatureEd25519 $ Ed25519.sign sk pk hash
        kexEcdhReply = KexEcdhReply {
              kexServerHostKey      = serverPublicKey
            , kexServerEphemeralKey = serverEphemeralPublicKey
            , kexHashSignature      = signature
            }

    -- Complete the key exchange and wait for the client to confirm
    -- with a NewKeys msg.
    sendPutter stream $ packetize $ B.put kexEcdhReply
    sendPutter stream $ packetize $ B.put NewKeys
    (NewKeys, rem4) <- receiveGetter stream (unpacketize B.get) rem3

    -- Derive the required encryption/decryption keys.
    -- The integrity keys etc. are not needed with chacha20.
    let mainKeyCS:headerKeyCS:_ = deriveKeys dhSecret hash "C" session
        mainKeySC:headerKeySC:_ = deriveKeys dhSecret hash "D" session

    -- Initialize cryptographic encoder/decoder.
    -- TODO: Make this simpler.
    let encode = chacha20Poly1305Encode headerKeySC mainKeySC
        decode = (f .) . chacha20Poly1305Decoder headerKeyCS mainKeyCS
            where
                f (DecoderDone p c) = pure (p, c)
                f (DecoderFail e)   = throwIO (SshCryptoErrorException e)
                f (DecoderMore c)   = do
                    cipher <- receive stream 1024
                    when (BA.null cipher) (throwIO SshUnexpectedEndOfInputException)
                    f (c cipher)

    -- The connection is essentially a state machine.
    -- It also contains resources that need to be freed on termination
    -- (like running threads), therefore the bracket pattern.
    withConnection config session $ \connection-> do
        -- The sender is an infinite loop that pulls messages from the connection
        -- object. Produced messages are encoded and sent.
        let sender seqnr = do
                msg <- pullMessage connection
                let plain = buildMessage msg
                    cipher = encode seqnr (plain `asTypeOf` cipher)
                sendAll stream (cipher :: BA.Bytes)
                -- This thread shall terminate gracefully in case the
                -- message was a disconnect message. Per specification
                -- no other messages may follow after a disconnect message.
                case msg of
                    MsgDisconnect {} -> pure ()
                    _                -> sender (seqnr + 1)

        -- The receiver is an infinite loop that waits for input on the stream,
        -- decodes and parses it and pushes it into the connection state object.
        let receiver seqnr initial = do
                (plain, remainder) <- decode seqnr initial
                parseMessage (plain `asTypeOf` remainder) >>= \case
                    MsgDisconnect {} -> pure ()
                    msg -> do
                        pushMessage connection msg
                        receiver (seqnr + 1) remainder

        -- Exactly two threads are necessary to process input and output concurrently.
        sender 3 `race_` receiver 3 rem4

parseMessage :: BA.ByteArrayAccess plain => plain -> IO Message
parseMessage plain = case B.runGetOrFail B.get (LBS.fromStrict (BA.convert plain)) of
    Left (_,_,e)    -> throwIO (SshSyntaxErrorException e)
    Right (_,_,msg) -> pure msg

buildMessage :: BA.ByteArray plain => Message -> plain
buildMessage msg = BA.convert $ LBS.toStrict $ B.runPut $ B.put msg

data Decoder cipher plain
    = DecoderMore (cipher -> Decoder cipher plain)
    | DecoderDone plain cipher
    | DecoderFail String

chacha20Poly1305Encode :: (BA.ByteArrayAccess headerKey, BA.ByteArrayAccess mainKey, BA.ByteArray plain, BA.ByteArray cipher)
                        => headerKey -> mainKey -> Word64 -> plain -> cipher
chacha20Poly1305Encode headerKey mainKey seqnr plain = cipher
    where
        cipher        = BA.convert $ ciph3 <> mac
        plainlen      = BA.length plain                :: Int
        padlen        = let p = 8 - ((1 + plainlen) `mod` 8)
                        in  if p < 4 then p + 8 else p :: Int
        paclen        = 1 + plainlen + padlen          :: Int
        padding       = BA.replicate padlen 0
        padlenBA      = BA.singleton (fromIntegral padlen)
        paclenBA      = BA.pack
            [ fromIntegral $ paclen `shiftR` 24
            , fromIntegral $ paclen `shiftR` 16
            , fromIntegral $ paclen `shiftR`  8
            , fromIntegral $ paclen `shiftR`  0
            ]
        nonceBA       = BA.pack
            [ fromIntegral $ seqnr  `shiftR` 56
            , fromIntegral $ seqnr  `shiftR` 48
            , fromIntegral $ seqnr  `shiftR` 40
            , fromIntegral $ seqnr  `shiftR` 32
            , fromIntegral $ seqnr  `shiftR` 24
            , fromIntegral $ seqnr  `shiftR` 16
            , fromIntegral $ seqnr  `shiftR`  8
            , fromIntegral $ seqnr  `shiftR`  0
            ] :: BA.Bytes
        st1           = ChaCha.initialize 20 mainKey nonceBA
        st2           = ChaCha.initialize 20 headerKey nonceBA
        (poly, st3)   = ChaCha.generate st1 64
        ciph1         = fst $ ChaCha.combine st2 paclenBA
        ciph2         = fst $ ChaCha.combine st3 $ padlenBA <> plain <> padding
        ciph3         = ciph1 <> ciph2
        mac           = BA.convert (Poly1305.auth (BS.take 32 poly) ciph3)

chacha20Poly1305Decoder :: (BA.ByteArrayAccess headerKey, BA.ByteArrayAccess mainKey, BA.ByteArray plain, BA.ByteArray cipher, Show cipher)
                        => headerKey -> mainKey -> Word64 -> cipher -> Decoder cipher plain
chacha20Poly1305Decoder headerKey mainKey seqnr = st0
    where
        st0 cipher
            | BA.length cipher < 4 =
                DecoderMore $ st0 . (cipher <>)
            | otherwise =
                st1 paclen paclenCiph (BA.drop 4 cipher)
            where
                cc = ChaCha.initialize 20 headerKey nonce
                paclenCiph = BA.take 4 cipher
                paclenPlain = fst $ ChaCha.combine cc paclenCiph
                paclen = fromIntegral (BA.index paclenPlain 0) `shiftL` 24
                    .|.  fromIntegral (BA.index paclenPlain 1) `shiftL` 16
                    .|.  fromIntegral (BA.index paclenPlain 2) `shiftL`  8
                    .|.  fromIntegral (BA.index paclenPlain 3) `shiftL`  0

        st1 paclen paclenCiph cipher
            | BA.length cipher < paclen =
                DecoderMore $ st1 paclen paclenCiph . (cipher <>)
            | otherwise =
                st2 paclenCiph (BA.take paclen cipher) (BA.drop paclen cipher)

        st2 paclenCiph pacCiph cipher
            | BA.length cipher < maclen =
                DecoderMore $ st2 paclenCiph pacCiph . (cipher <>)
            | otherwise = if mac == macExpected
                then DecoderDone plain (BA.drop maclen cipher)
                else DecoderFail "message authentication failed"
            where
                maclen      = 16
                cc          = ChaCha.initialize 20 mainKey nonce
                (poly, cc') = ChaCha.generate cc 64
                mac         = Poly1305.Auth (BA.convert $ BA.take maclen cipher)
                macExpected = Poly1305.auth (BS.take 32 poly) (paclenCiph <> pacCiph)
                plain       = unpad $ fst $ ChaCha.combine cc' pacCiph
                unpad ba    = case BA.uncons ba of
                    Nothing    -> BA.convert ba -- invalid input, unavoidable anyway
                    Just (h,t) -> BA.convert $ BA.take (BA.length t - fromIntegral h) t

        nonce = BA.pack
            [ fromIntegral $ seqnr  `shiftR` 56
            , fromIntegral $ seqnr  `shiftR` 48
            , fromIntegral $ seqnr  `shiftR` 40
            , fromIntegral $ seqnr  `shiftR` 32
            , fromIntegral $ seqnr  `shiftR` 24
            , fromIntegral $ seqnr  `shiftR` 16
            , fromIntegral $ seqnr  `shiftR`  8
            , fromIntegral $ seqnr  `shiftR`  0
            ] :: BA.Bytes

-------------------------------------------------------------------------------
-- Misc
-------------------------------------------------------------------------------

packetize :: B.Put -> B.Put
packetize payload = mconcat
  [ B.putWord32be $ fromIntegral packetLen
  , B.putWord8    $ fromIntegral paddingLen
  , payload
  , padding
  ]
  where
    packetLen  = 1 + payloadLen + paddingLen
    payloadLen = fromIntegral $ LBS.length (B.runPut payload)
    paddingLen = 16 - (4 + 1 + payloadLen) `mod` 8
    padding    = B.putByteString (BS.replicate paddingLen 0)

unpacketize :: B.Get a -> B.Get a
unpacketize parser = do
  packetLen <- fromIntegral <$> B.getWord32be
  B.isolate packetLen $ do
    paddingLen <- fromIntegral <$> B.getWord8
    x <- parser
    B.skip paddingLen
    pure x

exchangeHash ::
  Version ->               -- client version string
  Version ->               -- server version string
  KexInit ->               -- client kex init msg
  KexInit ->               -- server kex init msg
  PublicKey ->             -- server host key
  Curve25519.PublicKey ->  -- client ephemeral key
  Curve25519.PublicKey ->  -- server ephemeral key
  Curve25519.DhSecret ->   -- dh secret
  Hash.Digest Hash.SHA256
exchangeHash (Version vc) (Version vs) ic is ks qc qs k
  = Hash.hash $ LBS.toStrict $ B.runPut $ mconcat
  [ B.putWord32be              vcLen
  , B.putByteString            vc
  , B.putWord32be              vsLen
  , B.putByteString            vs
  , B.putWord32be              icLen
  , B.put                      ic
  , B.putWord32be              isLen
  , B.put                      is
  , B.put                      ks
  , curve25519BlobBuilder      qc
  , curve25519BlobBuilder      qs
  , putMpint (BA.unpack k)
  ] :: Hash.Digest Hash.SHA256
  where
    vcLen = fromIntegral $     BS.length vc
    vsLen = fromIntegral $     BS.length vs
    icLen = fromIntegral $ LBS.length (B.runPut $ B.put ic)
    isLen = fromIntegral $ LBS.length (B.runPut $ B.put is)

    curve25519BlobBuilder :: Curve25519.PublicKey -> B.Put
    curve25519BlobBuilder key =
      B.putWord32be 32 <> B.putByteString (BS.pack $ BA.unpack key)

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> BS.ByteString -> SessionId -> [BA.ScrubbedBytes]
deriveKeys sec hash i (SessionId sess) = BA.pack . BA.unpack <$> k1 : f [k1]
  where
    k1   = Hash.hashFinalize    $
      flip Hash.hashUpdate sess $
      Hash.hashUpdate st i :: Hash.Digest Hash.SHA256
    f ks = kx : f (ks ++ [kx])
      where
        kx = Hash.hashFinalize (foldl Hash.hashUpdate st ks)
    st =
      flip Hash.hashUpdate hash $
      Hash.hashUpdate Hash.hashInit secmpint
    secmpint =
      LBS.toStrict $ B.runPut $ putMpint $ BA.unpack sec

putMpint :: [Word8] -> B.Put
putMpint xs = zs
  where
    prepend [] = []
    prepend (a:as)
      | a >= 128  = 0:a:as
      | otherwise = a:as
    ys = BS.pack $ prepend $ dropWhile (==0) xs
    zs = B.putWord32be (fromIntegral $ BS.length ys) <> B.putByteString ys
