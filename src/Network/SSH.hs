{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH where

import           Control.Monad            (void, when)
import           Crypto.Error
import qualified Crypto.Error             as DH
import qualified Crypto.Hash              as Hash
import qualified Crypto.Hash.Algorithms   as Hash
import qualified Crypto.PubKey.Curve25519 as DH
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA.PKCS15
import qualified Data.Binary              as B
import qualified Data.Binary.Get          as B
import qualified Data.Binary.Put          as B
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as LBS
import           Data.Foldable
import           Data.Int
import qualified Data.List                as L
import           Data.Monoid
import           Data.Word

import           Network.SSH.Constants
import           Network.SSH.Message

data KexMsg
  = KexMsg
  { cookie                                  :: BS.ByteString
  , key_algorithms                          :: [BS.ByteString]
  , server_host_key_algorithms              :: [BS.ByteString]
  , encryption_algorithms_client_to_server  :: [BS.ByteString]
  , encryption_algorithms_server_to_client  :: [BS.ByteString]
  , mac_algorithms_client_to_server         :: [BS.ByteString]
  , mac_algorithms_server_to_client         :: [BS.ByteString]
  , compression_algorithms_client_to_server :: [BS.ByteString]
  , compression_algorithms_server_to_client :: [BS.ByteString]
  , languages_client_to_server              :: [BS.ByteString]
  , languages_server_to_client              :: [BS.ByteString]
  , first_kex_packet_follows                :: Bool
  } deriving (Eq, Ord, Show)

serverKexInit :: KexMsg
serverKexInit = KexMsg
  { cookie
  = "\155=\ACK\150\169p\164\v\t\245\223\224\EOT\233\200\SO"
  , key_algorithms
  = [ "curve25519-sha256@libssh.org" ]
  , server_host_key_algorithms
  = [ "ssh-ed25519" ]
  , encryption_algorithms_client_to_server
  = [ "chacha20-poly1305@openssh.com" ]
  , encryption_algorithms_server_to_client
  = [ "chacha20-poly1305@openssh.com" ]
  , mac_algorithms_client_to_server
  = [ "umac-64-etm@openssh.com" ]
  , mac_algorithms_server_to_client
  = [ "umac-64-etm@openssh.com" ]
  , compression_algorithms_client_to_server
  = [ "none" ]
  , compression_algorithms_server_to_client
  = [ "none" ]
  , languages_client_to_server
  = []
  , languages_server_to_client
  = []
  , first_kex_packet_follows
  = False
  }



kexInitParser :: B.Get KexMsg
kexInitParser = do
  void $ B.getWord8
  kex <- KexMsg
    <$> B.getByteString 16
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> ( B.getWord8 >>= \case { 0x00 -> pure False; _ -> pure True } )
  void $ B.getWord32be -- reserved for future extensions
  pure kex
  where
    nameList = do
      n <- fromIntegral . min maxPacketSize <$> B.getWord32be -- avoid undefined conversion
      BS.split 0x2c <$> B.getByteString n

kexInitBuilder :: KexMsg -> B.Put
kexInitBuilder msg = mconcat
  [ B.putByteString (cookie msg)
  , nameListBuilder (key_algorithms msg)
  , nameListBuilder (server_host_key_algorithms msg)
  , nameListBuilder (encryption_algorithms_client_to_server msg)
  , nameListBuilder (encryption_algorithms_server_to_client msg)
  , nameListBuilder (mac_algorithms_client_to_server msg)
  , nameListBuilder (mac_algorithms_server_to_client msg)
  , nameListBuilder (compression_algorithms_client_to_server msg)
  , nameListBuilder (compression_algorithms_server_to_client msg)
  , nameListBuilder (languages_client_to_server msg)
  , nameListBuilder (languages_server_to_client msg)
  , B.putWord8 $ if first_kex_packet_follows msg then 0x01 else 0x00
  , B.putWord32be 0x00000000
  ]

data KexReply
  = KexReply
  { serverPublicHostKey      :: Ed25519.PublicKey
  , serverPublicEphemeralKey :: Curve25519.PublicKey
  , exchangeHashSignature    :: Ed25519.Signature
  } deriving (Show)

nameListBuilder :: [BS.ByteString] -> B.Put
nameListBuilder xs =
  B.putWord32be (fromIntegral $ g xs)
  <> mconcat (B.putByteString <$> L.intersperse "," xs)
  where
    g [] = 0
    g xs = sum (BS.length <$> xs) + length xs - 1

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
  packetLen <- fromIntegral . min maxPacketSize <$> B.getWord32be
  B.isolate packetLen $ do
    paddingLen <- fromIntegral <$> B.getWord8
    x <- parser
    B.skip paddingLen
    pure x

kexReplyBuilder :: KexReply -> B.Put
kexReplyBuilder reply = mconcat
  [ B.putWord8        31 -- message type
  , B.putWord32be     51 -- host key len
  , B.putWord32be     11 -- host key algorithm name len
  , B.putByteString   "ssh-ed25519"
  , B.putWord32be     32 -- host key data len
  , B.putByteString $ BS.pack $ BA.unpack (serverPublicHostKey reply)
  , B.putWord32be     32 -- ephemeral key len
  , B.putByteString $ BS.pack $ BA.unpack (serverPublicEphemeralKey reply)
  , B.putWord32be   $ 4 + 11 + 4 + fromIntegral signatureLen
  , B.putWord32be     11 -- algorithm name len
  , B.putByteString   "ssh-ed25519"
  , B.putWord32be   $ fromIntegral signatureLen
  , B.putByteString   signature
  ]
  where
    signature    = BS.pack $ BA.unpack (exchangeHashSignature reply)
    signatureLen = BS.length signature

newKeysBuilder :: B.Put
newKeysBuilder = B.putWord8 21

exchangeHash ::
  Version ->               -- client version string
  Version ->               -- server version string
  KexMsg ->                -- client kex msg
  KexMsg ->                -- server kex msg
  Ed25519.PublicKey ->     -- server host key
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
  , B.putWord8                   20 -- SSH2_MSG_KEXINIT
  , kexInitBuilder             ic
  , B.putWord32be              isLen
  , B.putWord8                   20 -- SSH2_MSG_KEXINIT
  , kexInitBuilder             is
  , ed25519PublicKeyBuilder    ks
  , curve25519BlobBuilder      qc
  , curve25519BlobBuilder      qs
  , curve25519DhSecretBuilder  k
  ] :: Hash.Digest Hash.SHA256
  where
    vcLen = fromIntegral $     BS.length vc
    vsLen = fromIntegral $     BS.length vs
    icLen = fromIntegral $ 1 + builderLength (kexInitBuilder ic)
    isLen = fromIntegral $ 1 + builderLength (kexInitBuilder is)

ed25519PublicKeyBuilder :: Ed25519.PublicKey -> B.Put
ed25519PublicKeyBuilder key = mconcat
  [ B.putWord32be     51 -- host key len
  , B.putWord32be     11 -- host key algorithm name len
  , B.putByteString   "ssh-ed25519"
  , B.putWord32be     32 -- host key data len
  , B.putByteString $ BS.pack $ BA.unpack key
  ]

rsaPublicKeyBuilder     :: RSA.PublicKey -> B.Put
rsaPublicKeyBuilder (RSA.PublicKey _ n e) =
  B.putWord32be (fromIntegral $ LBS.length lbs) <> B.putLazyByteString lbs
  where
    lbs = B.runPut $ mconcat
      [ string "ssh-rsa"
      , integer n
      , integer e
      ]
    string  x = B.putWord32be (fromIntegral $ BS.length x)  <> B.putByteString x
    integer x = B.putWord32be (fromIntegral $ BS.length bs) <> B.putByteString bs
      where
        bs = BS.pack $ g $ f x []
        f 0 acc = acc
        f i acc = let (q,r) = quotRem i 256
                  in  f q (fromIntegral r : acc)
        g []        = []
        g xxs@(x:_) | x > 128   = 0:xxs
                    | otherwise = xxs

curve25519BlobBuilder :: Curve25519.PublicKey -> B.Put
curve25519BlobBuilder key =
  B.putWord32be 32 <> B.putByteString (BS.pack $ BA.unpack key)

curve25519DhSecretBuilder  :: Curve25519.DhSecret -> B.Put
curve25519DhSecretBuilder sec = do
  bignum2bytes (BA.unpack sec)
  where
    -- FIXME: not constant time
    bignum2bytes xs = zs
      where
        prepend [] = []
        prepend (a:as)
          | a >= 128  = 0:a:as
          | otherwise = a:as
        ys = BS.pack $ prepend $ dropWhile (==0) xs
        zs = B.putWord32be (fromIntegral $ BS.length ys) <> B.putByteString ys

kexRequestParser :: B.Get DH.PublicKey
kexRequestParser = do
  msg <- B.getWord8
  when (msg /= 30) (fail "expected SSH_MSG_KEX_ECDH_INIT")
  keySize <- B.getWord32be
  when (keySize /= 32) (fail "expected key size to be 32 bytes")
  bs <- B.getByteString 32
  case DH.publicKey bs of
    DH.CryptoPassed a -> pure a
    DH.CryptoFailed e -> fail (show e)

mpintLenBuilder :: Integer -> (Int, B.Put) -> (Int, B.Put)
mpingLenBuilder 0 x = x
mpintLenBuilder i (!len, !bld) = mpintLenBuilder q (len + 4, B.putWord32be (fromIntegral r) <> bld)
  where
    (q,r) = i `quotRem` 0x0100000000

maxPacketSize :: Word32
maxPacketSize = 32767

builderLength :: B.Put -> Int64
builderLength =
  LBS.length . B.runPut

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> BS.ByteString -> SessionId -> [Hash.Digest Hash.SHA256]
deriveKeys sec hash i (SessionId sess) =
  k1:(f [k1])
  where
    k1   = Hash.hashFinalize    $
      flip Hash.hashUpdate sess $
      flip Hash.hashUpdate i st
    f ks = kx:(f $ ks ++ [kx])
      where
        kx = Hash.hashFinalize (foldl Hash.hashUpdate st ks)
    st =
      flip Hash.hashUpdate hash $
      flip Hash.hashUpdate secmpint
      Hash.hashInit
    secmpint =
      LBS.toStrict $ B.runPut $ curve25519DhSecretBuilder sec

verifyAuthSignature :: SessionId -> UserName -> ServiceName -> Algorithm -> PublicKey -> Signature -> Bool
verifyAuthSignature sessionIdentifier userName serviceName algorithm publicKey signature =
  case (publicKey,signature) of
    (PublicKeyEd25519 k, SignatureEd25519 s) -> Ed25519.verify k signedData s
    (PublicKeyRSA     k, SignatureRSA     s) -> RSA.PKCS15.verify (Just Hash.SHA1) k signedData s
    _                                        -> False
  where
    signedData :: BS.ByteString
    signedData = LBS.toStrict $ B.runPut $ mconcat
      [ B.put           sessionIdentifier
      , B.putWord8      50
      , B.put           userName
      , B.put           serviceName
      , B.putWord32be   9
      , B.putByteString "publickey"
      , B.putWord8      1
      , B.put           algorithm
      , B.put           publicKey
      ]
