{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.KeyExchange where

import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Exception            (throwIO)
import           Control.Monad                (void)
import           Control.Monad.STM            (STM, atomically)
import qualified Crypto.Cipher.ChaCha         as ChaCha
import qualified Crypto.Hash                  as Hash
import qualified Crypto.MAC.Poly1305          as Poly1305
import qualified Crypto.PubKey.Curve25519     as Curve25519
import qualified Crypto.PubKey.Ed25519        as Ed25519
import           Data.Bits
import qualified Data.ByteArray               as BA
import qualified Data.ByteString              as BS
import           Data.List
import qualified Data.List.NonEmpty           as NEL
import           Data.Monoid                  ((<>))
import           System.Clock

import           Network.SSH.Algorithms
import           Network.SSH.Constants
import           Network.SSH.Encoding
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport
import           Network.SSH.Stream

data KexStep
    = KexStart
    | KexProcessInit KexInit
    | KexProcessEcdhInit KexEcdhInit

performInitialKeyExchange :: (DuplexStream stream)
    => Config identity -> TransportState stream
    -> IO (SessionId, STM Message, KexStep -> IO ())
performInitialKeyExchange config state = do
    -- Receive the client version string and immediately reply
    -- with the server version string if the client version string is valid.
    clientVersion <- receiveVersion (transportStream state)
    void $ sendAll (transportStream state) $ runPut $ put version

    out <- newTChanIO
    msid <- newEmptyMVar
    handle <- newKexStepHandler config state clientVersion version (atomically . writeTChan out) msid
    handle KexStart
    sendPlain state =<< hookSend =<< atomically (readTChan out)
    MsgKexInit cki <- hookRecv =<< receivePlain state
    handle (KexProcessInit cki)
    MsgKexEcdhInit clientKexEcdhInit <- hookRecv =<< receivePlain state
    handle (KexProcessEcdhInit clientKexEcdhInit)
    sendPlain state =<< hookSend =<< atomically (readTChan out) -- KexEcdhReply
    sendPlain state =<< hookSend =<< atomically (readTChan out) -- KexNewKeys
    MsgKexNewKeys _ <- hookRecv =<< receivePlain state
    session <- readMVar msid
    pure (session, readTChan out, handle)
    where
        hookSend msg = onSend config msg >> pure msg
        hookRecv msg = onReceive config msg >> pure msg

-- The rekeying watchdog is an inifinite loop that initiates
-- a key re-exchange when either a certain amount of time has passed or
-- when either the input or output stream has exceeded its threshold
-- of bytes sent/received.
askRekeyingRequired :: Config identity -> TransportState stream -> IO Bool
askRekeyingRequired config state = do
    t  <- fromIntegral . sec <$> getTime Monotonic
    t0 <- readMVar (transportLastRekeyingTime state)
    s  <- readMVar (transportBytesSent state)
    s0 <- readMVar (transportLastRekeyingDataSent state)
    r  <- readMVar (transportBytesReceived state)
    r0 <- readMVar (transportLastRekeyingDataReceived state)
    pure $ if   | intervalExceeded  t t0 -> True
                | thresholdExceeded s s0 -> True
                | thresholdExceeded r r0 -> True
                | otherwise              -> False
    where
        -- For reasons of fool-proofness the rekeying interval/threshold
        -- shall never be greater than 1 hour or 1GB.
        -- NB: This is security critical as some algorithms like ChaCha20
        -- use the packet counter as nonce and an overflow will lead to
        -- nonce reuse!
        interval  = min (maxTimeBeforeRekey config) 3600
        threshold = min (maxDataBeforeRekey config) (1024 * 1024 * 1024)
        intervalExceeded  t t0 = t > t0 && t - t0 > interval
        thresholdExceeded x x0 = x > x0 && x - x0 > threshold

newKexStepHandler :: (DuplexStream stream)
    => Config identity -> TransportState stream -> Version -> Version
    -> (Message -> IO ()) -> MVar SessionId -> IO (KexStep -> IO ())
newKexStepHandler config state clientVersion serverVersion sendMsg msid = do
  continuation <- newEmptyMVar

  let noKexInProgress = \case
          KexStart -> do
              ski <- newKexInit config
              sendMsg (MsgKexInit ski)
              void $ swapMVar continuation (waitingForKexInit ski)
          KexProcessInit cki -> do
              ski <- newKexInit config
              sendMsg (MsgKexInit ski)
              void $ swapMVar continuation (waitingForKexEcdhInit ski cki)
          KexProcessEcdhInit {} ->
              throwIO $ Disconnect DisconnectProtocolError "unexpected KexEcdhInit" ""

      waitingForKexInit ski = \case
          KexStart ->
              pure () -- already in progress
          KexProcessInit cki ->
              void $ swapMVar continuation (waitingForKexEcdhInit ski cki)
          KexProcessEcdhInit {} ->
              throwIO $ Disconnect DisconnectProtocolError "unexpected KexEcdhInit" ""

      waitingForKexEcdhInit ski cki = \case
          KexStart ->
              pure () -- already in progress
          KexProcessInit {} ->
              throwIO $ Disconnect DisconnectProtocolError "unexpected KexInit" ""
          KexProcessEcdhInit (KexEcdhInit clientEphemeralPublicKey) -> do
              completeEcdhExchange ski cki clientEphemeralPublicKey
              void $ swapMVar continuation noKexInProgress

  putMVar continuation noKexInProgress
  pure $ \step-> do
        handle <- readMVar continuation
        handle step
    where
        completeEcdhExchange ski cki clientEphemeralPublicKey = do
            kexAlgorithm   <- commonKexAlgorithm   ski cki
            encAlgorithmCS <- commonEncAlgorithmCS ski cki
            encAlgorithmSC <- commonEncAlgorithmSC ski cki

            -- TODO: Dispatch here when implementing support for more algorithms.
            case (kexAlgorithm, encAlgorithmCS, encAlgorithmSC) of
                (Curve25519Sha256AtLibsshDotOrg, Chacha20Poly1305AtOpensshDotCom, Chacha20Poly1305AtOpensshDotCom) ->
                    completeCurve25519KeyExchange ski cki clientEphemeralPublicKey

        completeCurve25519KeyExchange ski cki clientEphemeralPublicKey = do
            -- Generate a Curve25519 keypair for elliptic curve Diffie-Hellman key exchange.
            serverEphemeralSecretKey <- Curve25519.generateSecretKey
            serverEphemeralPublicKey <- pure $ Curve25519.toPublic serverEphemeralSecretKey

            KeyPairEd25519 pubKey secKey <- do
                let isEd25519 KeyPairEd25519 {} = True
                    -- TODO: Required when more algorithms are implemented.
                    -- isEd25519 _                 = False
                case NEL.filter isEd25519 (hostKeys config) of
                    (x:_) -> pure x
                    _     -> undefined -- impossible

            let secret = Curve25519.dh
                    clientEphemeralPublicKey
                    serverEphemeralSecretKey

            let hash = exchangeHash
                    clientVersion
                    serverVersion
                    cki
                    ski
                    (PublicKeyEd25519 pubKey)
                    clientEphemeralPublicKey
                    serverEphemeralPublicKey
                    secret

            -- The reply is shall be sent with the old encryption context.
            -- This is the case as long as the KexNewKeys message has not
            -- been transmitted.
            sendMsg $ MsgKexEcdhReply KexEcdhReply {
                        kexServerHostKey      = PublicKeyEd25519 pubKey
                    ,   kexServerEphemeralKey = serverEphemeralPublicKey
                    ,   kexHashSignature      = SignatureEd25519 $ Ed25519.sign
                                                    secKey
                                                    pubKey
                                                    hash
                    }

            session <- tryReadMVar msid >>= \case
                Just s -> pure s
                Nothing -> do
                    let s = SessionId $ BA.convert hash
                    putMVar msid s
                    pure s

            -- Derive the required encryption/decryption keys.
            -- The integrity keys etc. are not needed with chacha20.
            let mainKeyCS:headerKeyCS:_ = deriveKeys secret hash "C" session
                mainKeySC:headerKeySC:_ = deriveKeys secret hash "D" session

            void $ swapMVar (transportSender state) $
                sendEncrypted state headerKeySC mainKeySC

            void $ swapMVar (transportReceiver state) $ do
                receiveEncrypted state headerKeyCS mainKeyCS

            void $ swapMVar (transportLastRekeyingTime         state) =<< fromIntegral . sec <$> getTime Monotonic
            void $ swapMVar (transportLastRekeyingDataSent     state) =<< readMVar (transportBytesSent     state)
            void $ swapMVar (transportLastRekeyingDataReceived state) =<< readMVar (transportBytesReceived state)

            -- The encryption context shall be switched no earlier than
            -- before the new keys message has been transmitted.
            -- It's the sender's thread responsibility to switch the context.
            sendMsg (MsgKexNewKeys KexNewKeys)

commonKexAlgorithm :: KexInit -> KexInit -> IO KeyExchangeAlgorithm
commonKexAlgorithm ski cki = case kexAlgorithms cki `intersect` kexAlgorithms ski of
    ("curve25519-sha256@libssh.org":_) -> pure Curve25519Sha256AtLibsshDotOrg
    _ -> throwIO (Disconnect DisconnectKeyExchangeFailed "no common kex algorithm" "")

commonEncAlgorithmCS :: KexInit -> KexInit -> IO EncryptionAlgorithm
commonEncAlgorithmCS ski cki = case kexEncryptionAlgorithmsClientToServer cki `intersect` kexEncryptionAlgorithmsClientToServer ski of
    ("chacha20-poly1305@openssh.com":_) -> pure Chacha20Poly1305AtOpensshDotCom
    _ -> throwIO (Disconnect DisconnectKeyExchangeFailed "no common encryption algorithm (client to server)" "")

commonEncAlgorithmSC :: KexInit -> KexInit -> IO EncryptionAlgorithm
commonEncAlgorithmSC ski cki = case kexEncryptionAlgorithmsServerToClient cki `intersect` kexEncryptionAlgorithmsServerToClient ski of
    ("chacha20-poly1305@openssh.com":_) -> pure Chacha20Poly1305AtOpensshDotCom
    _ -> throwIO (Disconnect DisconnectKeyExchangeFailed "no common encryption algorithm (server to client)" "")

newKexInit :: Config identity -> IO KexInit
newKexInit config = do
    cookie <- newCookie
    pure KexInit
        {   kexCookie                              = cookie
        ,   kexAlgorithms                          = NEL.toList $ fmap f (keyExchangeAlgorithms config)
        ,   kexServerHostKeyAlgorithms             = NEL.toList $ NEL.nub $ fmap g (hostKeys config)
        ,   kexEncryptionAlgorithmsClientToServer  = NEL.toList $ fmap h (encryptionAlgorithms config)
        ,   kexEncryptionAlgorithmsServerToClient  = NEL.toList $ fmap h (encryptionAlgorithms config)
        ,   kexMacAlgorithmsClientToServer         = []
        ,   kexMacAlgorithmsServerToClient         = []
        ,   kexCompressionAlgorithmsClientToServer = ["none"]
        ,   kexCompressionAlgorithmsServerToClient = ["none"]
        ,   kexLanguagesClientToServer             = []
        ,   kexLanguagesServerToClient             = []
        ,   kexFirstPacketFollows                  = False
        }
    where
        f Curve25519Sha256AtLibsshDotOrg  = "curve25519-sha256@libssh.org"
        g KeyPairEd25519 {}               = "ssh-ed25519"
        h Chacha20Poly1305AtOpensshDotCom = "chacha20-poly1305@openssh.com"

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
    = Hash.hash $ runPut $ do
        putString vc
        putString vs
        putWord32 (len ic)
        put       ic
        putWord32 (len is)
        put       is
        put       ks
        put       qc
        put       qs
        putAsMPInt k

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> BS.ByteString -> SessionId -> [BA.ScrubbedBytes]
deriveKeys secret hash i (SessionId sess) = BA.convert <$> k1 : f [k1]
    where
    k1   = Hash.hashFinalize    $
        flip Hash.hashUpdate sess $
        Hash.hashUpdate st i :: Hash.Digest Hash.SHA256
    f ks = kx : f (ks ++ [kx])
        where
        kx = Hash.hashFinalize (foldl Hash.hashUpdate st ks)
    st =
        flip Hash.hashUpdate hash $
        Hash.hashUpdate Hash.hashInit (runPut $ putAsMPInt secret)

sendEncrypted :: (OutputStream stream, BA.ByteArrayAccess headerKey, BA.ByteArrayAccess mainKey)
              => TransportState stream -> headerKey -> mainKey -> BS.ByteString -> IO ()
sendEncrypted state headerKey mainKey plain = do
    seqnr <- readMVar (transportPacketsSent state)
    sent  <- sendAll (transportStream state) (encode seqnr)
    modifyMVar_ (transportBytesSent state) (\i-> pure $! i + fromIntegral sent)
    modifyMVar_ (transportPacketsSent state) (\i-> pure $! i + 1)
    where
        encode seqnr = ciph3 <> mac
            where
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
                nonceBA = BA.pack
                    [ 0
                    , 0
                    , 0
                    , 0
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

receiveEncrypted :: (InputStream stream, BA.ByteArrayAccess headerKey, BA.ByteArrayAccess mainKey)
    => TransportState stream -> headerKey -> mainKey -> IO BS.ByteString
receiveEncrypted state headerKey mainKey = do
    -- The sequence number is always the lower 32 bits of the number of
    -- packets received - 1. By specification, it wraps around every 2^32 packets.
    -- Special care must be taken wrt to rekeying as the sequence number
    -- is used as nonce in the ChaCha20Poly1305 encryption mode.
    seqnr <- readMVar (transportPacketsReceived state)
    let nonce = BA.pack
            [ 0
            , 0
            , 0
            , 0
            , fromIntegral $ seqnr  `shiftR` 24
            , fromIntegral $ seqnr  `shiftR` 16
            , fromIntegral $ seqnr  `shiftR`  8
            , fromIntegral $ seqnr  `shiftR`  0
            ] :: BA.Bytes

    paclenCiph <- receiveAll (transportStream state) 4
    let ccMain          = ChaCha.initialize 20 mainKey   nonce
    let ccHeader        = ChaCha.initialize 20 headerKey nonce
    let (poly, ccMain') = ChaCha.generate ccMain 64
    let paclenPlain = fst $ ChaCha.combine ccHeader paclenCiph
    let maclen = 16
    let paclen = fromIntegral (BA.index paclenPlain 0) `shiftL` 24
            .|.  fromIntegral (BA.index paclenPlain 1) `shiftL` 16
            .|.  fromIntegral (BA.index paclenPlain 2) `shiftL`  8
            .|.  fromIntegral (BA.index paclenPlain 3) `shiftL`  0

    pac <- receiveAll (transportStream state) paclen
    mac <- receiveAll (transportStream state) maclen

    modifyMVar_ (transportBytesReceived state) (\i-> pure $! i + 4 + fromIntegral paclen + fromIntegral maclen)
    modifyMVar_ (transportPacketsReceived state) (\i-> pure $! i + 1)

    let authTagReceived = Poly1305.Auth $ BA.convert mac
    let authTagExpected = Poly1305.auth (BS.take 32 poly) (paclenCiph <> pac)

    if authTagReceived /= authTagExpected
        then throwIO $ Disconnect DisconnectMacError "" ""
        else do
            let plain = fst (ChaCha.combine ccMain' pac)
            case BS.uncons plain of
                Nothing    -> throwIO $ Disconnect DisconnectProtocolError "packet structure" ""
                Just (h,t) -> pure $ BS.take (BS.length t - fromIntegral h) t

-- The maximum length of the version string is 255 chars including CR+LF.
-- The version string is usually short and transmitted within
-- a single TCP segment. The concatenation is therefore unlikely to happen
-- for regular use cases, but nonetheless required for correctness.
-- It is furthermore assumed that the client does not send any more data
-- after the version string before having received a response from the server;
-- otherwise parsing will fail. This is done in order to not having to deal with leftovers.
receiveVersion :: (InputStream stream) => stream -> IO Version
receiveVersion stream = receive stream 255 >>= f
    where
        f bs
            | BS.last bs == 0x0a  = runGet get bs
            | BS.length bs == 255 = throwIO $ Disconnect DisconnectProtocolVersionNotSupported "" ""
            | otherwise           = receive stream (255 - BS.length bs) >>= f . (bs <>)
