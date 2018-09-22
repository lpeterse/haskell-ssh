{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.KeyExchange where

import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TVar
import           Control.Exception            (throwIO)
import           Control.Monad                (void)
import           Control.Monad.STM            (atomically)
import qualified Crypto.Hash                  as Hash
import qualified Crypto.PubKey.Curve25519     as Curve25519
import qualified Crypto.PubKey.Ed25519        as Ed25519
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
import           Network.SSH.Server.Transport.Encryption
import           Network.SSH.Server.Transport.Internal
import           Network.SSH.Stream

data KexStep
    = KexStart
    | KexProcessInit KexInit
    | KexProcessEcdhInit KexEcdhInit

performInitialKeyExchange ::
    Config identity -> TransportState -> (Message -> IO ()) -> Version -> Version
    -> IO (SessionId, KexStep -> IO ())
performInitialKeyExchange config state enqueueMessage clientVersion serverVersion = do
    msid <- newEmptyMVar
    handler <- newKexStepHandler config state clientVersion serverVersion enqueueMessage msid
    handler KexStart
    MsgKexInit cki <- receiveMessage state
    handler (KexProcessInit cki)
    MsgKexEcdhInit clientKexEcdhInit <- receiveMessage state
    handler (KexProcessEcdhInit clientKexEcdhInit)
    session <- readMVar msid
    pure (session, handler)

-- The rekeying watchdog is an inifinite loop that initiates
-- a key re-exchange when either a certain amount of time has passed or
-- when either the input or output stream has exceeded its threshold
-- of bytes sent/received.
askRekeyingRequired :: Config identity -> TransportState -> IO Bool
askRekeyingRequired config state = do
    t  <- fromIntegral . sec <$> getTime Monotonic
    atomically $ do
        t0 <- readTVar (transportLastRekeyingTime state)
        s  <- readTVar (transportBytesSent state)
        s0 <- readTVar (transportLastRekeyingDataSent state)
        r  <- readTVar (transportBytesReceived state)
        r0 <- readTVar (transportLastRekeyingDataReceived state)
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

newKexStepHandler :: Config identity -> TransportState -> Version -> Version
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
            KexStart -> do
                pure () -- already in progress
            KexProcessInit cki ->
                void $ swapMVar continuation (waitingForKexEcdhInit ski cki)
            KexProcessEcdhInit {} ->
                throwIO $ Disconnect DisconnectProtocolError "unexpected KexEcdhInit" ""

        waitingForKexEcdhInit ski cki = \case
            KexStart -> do
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

                setCryptoContexts state $ chacha20poly1305 $ deriveKeys secret hash session

                atomically . writeTVar (transportLastRekeyingTime         state) =<< fromIntegral . sec <$> getTime Monotonic
                atomically $ writeTVar (transportLastRekeyingDataSent     state) =<< readTVar (transportBytesSent     state)
                atomically $ writeTVar (transportLastRekeyingDataReceived state) =<< readTVar (transportBytesReceived state)

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

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> SessionId -> BS.ByteString -> [BA.ScrubbedBytes]
deriveKeys secret hash (SessionId sess) i = BA.convert <$> k1 : f [k1]
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

-- The maximum length of the version string is 255 chars including CR+LF.
-- The version string is usually short and transmitted within
-- a single TCP segment. The concatenation is therefore unlikely to happen
-- for regular use cases, but nonetheless required for correctness.
-- It is furthermore assumed that the client does not send any more data
-- after the version string before having received a response from the server;
-- otherwise parsing will fail. This is done in order to not having to deal with leftovers.
receiveClientVersion :: (InputStream stream) => stream -> IO Version
receiveClientVersion stream = receive stream 257 >>= f
    where
        f bs
            | BS.null bs          = throwException
            | BS.length bs >= 257 = throwException
            | BS.last bs   ==  10 = case runGet get bs of
                Nothing -> throwException
                Just v  -> pure v
            | otherwise = do
                bs' <- receive stream (255 - BS.length bs)
                if BS.null bs'
                    then throwException
                    else f (bs <> bs')
        throwException = throwIO $ Disconnect DisconnectProtocolVersionNotSupported "" ""

sendServerVersion :: (OutputStream stream) => stream -> IO Version
sendServerVersion stream = do
    void $ sendAll stream $ runPut $ put version
    pure version
