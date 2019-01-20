{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE MultiWayIf                #-}
{-# LANGUAGE TupleSections             #-}
{-# LANGUAGE LambdaCase                #-}
module Network.SSH.Transport
    ( Transport()
    , TransportConfig (..)
    , Disconnected (..)
    , clientVersion
    , serverVersion
    , getBytesSent
    , getBytesReceived
    , getPacketsSent
    , getPacketsReceived
    , getKexCount
    , withClientTransport
    , withServerTransport
    , plainEncryptionContext
    , plainDecryptionContext
    , newChaCha20Poly1305EncryptionContext
    , newChaCha20Poly1305DecryptionContext
    )
where

import           Control.Applicative
import           Control.Concurrent             ( threadDelay )
import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Exception              ( throwIO, handle, catch, fromException)
import           Control.Monad                  ( when, void, join )
import           Control.Monad.STM
import           Data.Default
import           Data.List
import           Data.Monoid                    ( (<>) )
import           Data.Word
import           GHC.Clock
import qualified Crypto.Hash                   as Hash
import qualified Crypto.PubKey.Curve25519      as Curve25519
import qualified Crypto.PubKey.Ed25519         as Ed25519
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Short         as SBS
import qualified Data.List.NonEmpty            as NEL

import           Network.SSH.Algorithms
import qualified Network.SSH.Builder           as B
import           Network.SSH.Agent
import           Network.SSH.Constants
import           Network.SSH.Duration
import           Network.SSH.Transport.Crypto
import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Message
import           Network.SSH.Name
import           Network.SSH.Stream

data Transport
    = Transport
    { tConfig                   :: TransportConfig
    , tClientVersion            :: Version
    , tServerVersion            :: Version
    , tBytesSent                :: MVar Word64
    , tPacketsSent              :: MVar Word64
    , tBytesReceived            :: MVar Word64
    , tPacketsReceived          :: MVar Word64
    , tEncryptionCtx            :: MVar EncryptionContext
    , tEncryptionCtxNext        :: MVar EncryptionContext
    , tDecryptionCtx            :: MVar DecryptionContext
    , tDecryptionCtxNext        :: MVar DecryptionContext
    , tKexContinuation          :: MVar KexContinuation
    , tSessionId                :: MVar SessionId
    , tKexCount                 :: MVar Word64
    , tKexLastTime              :: MVar Word64
    , tKexLastDataSent          :: MVar Word64
    , tKexLastDataReceived      :: MVar Word64
    }

data TransportConfig
    = TransportConfig
    { version                 :: Version
    , serverHostKeyAlgorithms :: NEL.NonEmpty HostKeyAlgorithm
    , kexAlgorithms           :: NEL.NonEmpty KeyExchangeAlgorithm
    , encryptionAlgorithms    :: NEL.NonEmpty EncryptionAlgorithm
    , kexTimeout              :: Duration
    , maxTimeBeforeRekey      :: Word64
    , maxDataBeforeRekey      :: Word64
    , onSend                  :: BS.ByteString -> IO ()
    , onReceive               :: BS.ByteString -> IO ()
    }

instance Default TransportConfig where
    def = TransportConfig
        { version                  = defaultVersion
        , serverHostKeyAlgorithms  = pure SshEd25519
        , kexAlgorithms            = pure Curve25519Sha256AtLibsshDotOrg
        , encryptionAlgorithms     = pure Chacha20Poly1305AtOpensshDotCom
        , kexTimeout               = seconds 10
        , maxTimeBeforeRekey       = 3600
        , maxDataBeforeRekey       = 1000 * 1000 * 1000
        , onSend                   = const (pure ())
        , onReceive                = const (pure ())
        }

data KexStep
    = Init       KexInit
    | EcdhInit   KexEcdhInit
    | EcdhReply  KexEcdhReply

newtype KexContinuation = KexContinuation (Maybe KexStep -> IO KexContinuation)

instance MessageStream Transport where
    sendMessage t msg = do
        kexTriggerWhenNecessary t
        transportSendMessage t msg
    receiveMessage t = do
        kexTriggerWhenNecessary t
        transportReceiveMessage t

-------------------------------------------------------------------------------
-- PUBLIC FUNCTIONS
-------------------------------------------------------------------------------

clientVersion :: Transport -> Version
clientVersion = tClientVersion

serverVersion :: Transport -> Version
serverVersion = tServerVersion

getBytesSent :: Transport -> IO Word64
getBytesSent = readMVar . tBytesSent

getBytesReceived :: Transport -> IO Word64
getBytesReceived = readMVar . tBytesReceived

getPacketsSent :: Transport -> IO Word64
getPacketsSent = readMVar . tPacketsSent

getPacketsReceived :: Transport -> IO Word64
getPacketsReceived = readMVar . tPacketsReceived

getKexCount :: Transport -> IO Word64
getKexCount = readMVar . tKexCount

withClientTransport ::
    (DuplexStream stream) =>
    TransportConfig -> stream ->
    (Transport -> SessionId -> PublicKey -> IO a) -> IO (Either Disconnect a)
withClientTransport config stream runWith = withFinalExceptionHandler do
    -- The client starts by sending its own version and then waits
    -- for the server to respond.
    sendVersion stream (version config)
    sv <- receiveVersion stream
    env <- newTransport config stream (version config) sv
    withRespondingExceptionHandler env do
        (sessionId, hostKey) <- withTimeout
            (kexTimeout config)
            (kexClientInitialize stream env)
        a <- runWith env sessionId hostKey
        transportSendMessage env (Disconnected DisconnectByApplication mempty mempty)
        pure a

withServerTransport ::
    (DuplexStream stream) =>
    TransportConfig -> stream -> Agent ->
    (Transport -> SessionId -> IO a) -> IO (Either Disconnect a) -- FIXME
withServerTransport config stream agent runWith = withFinalExceptionHandler do
    -- Receive the peer version and reject immediately if this
    -- is not an SSH connection attempt (before allocating
    -- any more resources); respond with the server version string.
    cv <- receiveVersion stream
    sendVersion stream (version config)
    env <- newTransport config stream cv (version config)
    withRespondingExceptionHandler env do
        sessionId <- withTimeout
            (kexTimeout config)
            (kexServerInitialize stream env agent)
        a <- runWith env sessionId
        transportSendMessage env (Disconnected DisconnectByApplication mempty mempty)
        pure a

-------------------------------------------------------------------------------
-- PRIVATE FUNCTIONS
-------------------------------------------------------------------------------

withTimeout :: Duration -> IO a -> IO a
withTimeout t action = race timeout action >>= \case
    Left () -> throwIO exceptionKexTimeout
    Right a -> pure a
    where
        timeout = threadDelay $ fromIntegral $ asMicroSeconds t

transportSendMessage :: Encoding msg => Transport -> msg -> IO ()
transportSendMessage env msg =
    modifyMVar_ (tEncryptionCtx env) $ \sendEncrypted -> do
        onSend (tConfig env) (runPut payload)
        packets <- modifyMVar (tPacketsSent env) $ \p -> pure . (,p) $! p + 1
        sent <- sendEncrypted packets payload
        modifyMVar_ (tBytesSent env) $ \bytes -> pure $! bytes + fromIntegral sent
        if B.babLength payload == 1 && runGet (runPut payload) == Just KexNewKeys
            then readMVar (tEncryptionCtxNext env)
            else pure sendEncrypted
    where
        payload = put msg

transportReceiveMessage :: Decoding msg => Transport -> IO msg
transportReceiveMessage env = do
    maybe (transportReceiveMessage env) pure =<< transportReceiveMessageMaybe env

transportReceiveMessageMaybe :: Decoding msg => Transport -> IO (Maybe msg)
transportReceiveMessageMaybe env =
    modifyMVar (tDecryptionCtx env) $ \decrypt -> do
        packets <- readMVar (tPacketsReceived env)
        (bytesReceived, plainText) <- decrypt packets
        onReceive (tConfig env) plainText
        modifyMVar_ (tPacketsReceived env) $ \pacs -> pure $! pacs + 1
        modifyMVar_ (tBytesReceived env) $ \bytes -> pure $! bytes + fromIntegral bytesReceived
        -- Throw exception when this is a Disconnect message.
        case runGet plainText of
            Just (Disconnected r m _) -> throwIO $ Disconnect Remote r (DisconnectMessage $ SBS.fromShort m)
            Nothing                   -> pure ()
        -- In case this is a KexNewKeys message the next
        -- available decryption context shall be activated.
        decryptNext <- case runGet plainText of
            Just KexNewKeys -> readMVar (tDecryptionCtxNext env)
            Nothing         -> pure decrypt
        -- Run effects of other Kex messages.
        join $ runGetter plainText
            $   (kexContinue env . Init <$> get)
            <|> (kexContinue env . EcdhInit <$> get)
            <|> (kexContinue env . EcdhReply <$> get)
            <|> pure (pure ())
        -- Try to decode message to the expected type (including transport messages!).
        -- Otherwise return Nothing is this was a transport layer message.
        -- Only throw exception if this message was neither
        -- expected nor a transport layer message.
        case runGetter plainText $ (Just <$> get)
                <|> ((get :: Get Debug)         >> pure Nothing)
                <|> ((get :: Get Ignore)        >> pure Nothing)
                <|> ((get :: Get Unimplemented) >> pure Nothing)
                <|> ((get :: Get KexInit)       >> pure Nothing)
                <|> ((get :: Get KexEcdhInit)   >> pure Nothing)
                <|> ((get :: Get KexEcdhReply)  >> pure Nothing)
                <|> ((get :: Get KexNewKeys)    >> pure Nothing) of
            Just mmsg -> pure (decryptNext, mmsg)
            Nothing  -> throwIO $ exceptionUnexpectedMessage plainText

-------------------------------------------------------------------------------
-- KEY EXCHANGE (SERVER)
-------------------------------------------------------------------------------

kexServerInitialize :: (DuplexStream stream) => stream -> Transport -> Agent -> IO SessionId
kexServerInitialize stream env agent = do
    cookie <- newCookie
    putMVar (tKexContinuation env) $ kexServerContinuation stream env cookie agent
    kexTrigger env
    waitUntilKexComplete
    where
        waitUntilKexComplete = transportReceiveMessageMaybe env >>= \case
            Nothing -> waitUntilKexComplete
            Just KexNewKeys -> tryReadMVar (tSessionId env) >>= \case
                Nothing -> throwIO exceptionKexInvalidTransition
                Just sid -> pure sid

-- NB: Uses transportSendMessage to avoid rekeying-loop
kexServerContinuation :: (DuplexStream stream) => stream -> Transport -> Cookie -> Agent -> KexContinuation
kexServerContinuation stream env cookie agent = serverKex0
    where
        -- Being in this state means no kex is currently in progress.
        -- Kex may be started by either passing Nothing which means
        -- it is initialized locally. Passing (Just cki) means
        -- the other side initializes it. A race wherein both sides
        -- initiate a kex simultaneously may occur: This is expected
        -- and the algorithm can handle it.
        -- The `kexSetMilestone` call snapshots the the bytes sent/
        -- receive and the current time in order to keep track of
        -- when the next kex becomes necessary.
        serverKex0 :: KexContinuation
        serverKex0 = KexContinuation $ \mstep -> do
            kexSetMilestone env
            let ski = kexInit (tConfig env) cookie
            case mstep of
                Nothing -> do
                    transportSendMessage env ski
                    pure (serverKex1 ski)
                Just (Init cki) -> do
                    transportSendMessage env ski
                    pure (serverKex2 cki ski)
                _ -> throwIO exceptionKexInvalidTransition

        serverKex1 :: KexInit -> KexContinuation
        serverKex1 ski = KexContinuation $ \case
            Nothing-> do
                pure (serverKex1 ski)
            Just (Init cki) ->
                pure (serverKex2 cki ski)
            _ -> throwIO exceptionKexInvalidTransition

        serverKex2 :: KexInit -> KexInit -> KexContinuation
        serverKex2 cki ski = KexContinuation $ \case
            Nothing -> do
                pure (serverKex2 cki ski)
            Just (EcdhInit (KexEcdhInit cek)) -> do
                emitEcdhReply cki ski cek
                pure serverKex0
            _ -> throwIO exceptionKexInvalidTransition

        emitEcdhReply :: KexInit -> KexInit -> Curve25519.PublicKey -> IO ()
        emitEcdhReply cki ski cek = do
            kexAlgorithm     <- kexCommonKexAlgorithm ski cki
            encAlgorithmCS   <- kexCommonEncAlgorithm ski cki kexEncryptionAlgorithmsClientToServer
            encAlgorithmSC   <- kexCommonEncAlgorithm ski cki kexEncryptionAlgorithmsServerToClient
            getIdentities agent >>= \case
                []    -> throwIO exceptionKexNoSignature
                (shk,_):_ -> case (kexAlgorithm, encAlgorithmCS, encAlgorithmSC) of
                    (Curve25519Sha256AtLibsshDotOrg, Chacha20Poly1305AtOpensshDotCom, Chacha20Poly1305AtOpensshDotCom) -> do
                        sekSecret <- Curve25519.generateSecretKey
                        let cv   = tClientVersion env
                            sv   = tServerVersion env
                            sek  = Curve25519.toPublic sekSecret
                            sec  = Curve25519.dh cek sekSecret
                            hash = kexHash cv sv cki ski shk cek sek sec
                        sig <- maybe (throwIO exceptionKexNoSignature) pure =<< signDigest agent shk hash def
                        sid <- trySetSessionId env (SessionId $ SBS.toShort $ BA.convert hash)
                        setChaCha20Poly1305Context $ kexKeys sec hash sid
                        transportSendMessage env (KexEcdhReply shk sek sig)
                        transportSendMessage env KexNewKeys

        setChaCha20Poly1305Context :: KeyStreams -> IO ()
        setChaCha20Poly1305Context (KeyStreams keys) = do
            modifyMVar_ (tEncryptionCtxNext env) $ const
                $ newChaCha20Poly1305EncryptionContext stream headerKeySC mainKeySC
            modifyMVar_ (tDecryptionCtxNext env) $ const
                $ newChaCha20Poly1305DecryptionContext stream headerKeyCS mainKeyCS
            where
                -- Derive the required encryption/decryption keys.
                -- The integrity keys etc. are not needed with chacha20.
                mainKeyCS : headerKeyCS : _ = keys "C"
                mainKeySC : headerKeySC : _ = keys "D"

-------------------------------------------------------------------------------
-- KEY EXCHANGE (CLIENT)
-------------------------------------------------------------------------------

kexClientInitialize :: (DuplexStream stream) => stream -> Transport -> IO (SessionId, PublicKey)
kexClientInitialize stream env = do
    cookie <- newCookie
    mHostKey <- newEmptyMVar
    putMVar (tKexContinuation env) $ kexClientContinuation stream env cookie mHostKey
    kexTrigger env
    sid <- waitUntilKexComplete
    hostKey <- readMVar mHostKey -- Assertion: The host key is non-empty after key exchange
    pure (sid, hostKey)
    where
        waitUntilKexComplete = transportReceiveMessageMaybe env >>= \case
            Nothing -> waitUntilKexComplete
            Just KexNewKeys -> tryReadMVar (tSessionId env) >>= \case
                Nothing -> throwIO exceptionKexInvalidTransition
                Just sid -> pure sid

-- NB: Uses transportSendMessage to avoid rekeying-loop
kexClientContinuation :: (DuplexStream stream) => stream -> Transport  -> Cookie -> MVar PublicKey -> KexContinuation
kexClientContinuation stream env cookie mHostKey = clientKex0
    where
        -- See `serverKex0` for documentation.
        clientKex0 :: KexContinuation
        clientKex0 = KexContinuation $ \mstep -> do
            kexSetMilestone env
            let cki = kexInit (tConfig env) cookie
            case mstep of
                Nothing -> do
                    transportSendMessage env cki
                    pure (clientKex1 cki)
                Just (Init ski) -> do
                    cekSecret <- Curve25519.generateSecretKey
                    let cek = Curve25519.toPublic cekSecret
                    transportSendMessage env cki
                    transportSendMessage env (KexEcdhInit cek)
                    pure (clientKex2 cki ski cek cekSecret)
                _ -> throwIO exceptionKexInvalidTransition

        clientKex1 :: KexInit -> KexContinuation
        clientKex1 cki = KexContinuation $ \case
            Nothing ->
                pure (clientKex1 cki)
            Just (Init ski) -> do
                cekSecret <- Curve25519.generateSecretKey
                let cek = Curve25519.toPublic cekSecret
                transportSendMessage env (KexEcdhInit cek)
                pure (clientKex2 cki ski cek cekSecret)
            _ -> throwIO exceptionKexInvalidTransition

        clientKex2 :: KexInit -> KexInit -> Curve25519.PublicKey -> Curve25519.SecretKey -> KexContinuation
        clientKex2 cki ski cek cekSecret = KexContinuation $ \case
            Nothing ->
                pure (clientKex2 cki ski cek cekSecret)
            Just (EcdhReply ecdhReply) -> do
                consumeEcdhReply cki ski cek cekSecret ecdhReply
                pure clientKex0
            _ -> throwIO exceptionKexInvalidTransition

        consumeEcdhReply :: KexInit -> KexInit -> Curve25519.PublicKey -> Curve25519.SecretKey -> KexEcdhReply -> IO ()
        consumeEcdhReply cki ski cek cekSecret ecdhReply = do
            kexAlgorithm   <- kexCommonKexAlgorithm ski cki
            encAlgorithmCS <- kexCommonEncAlgorithm ski cki kexEncryptionAlgorithmsClientToServer
            encAlgorithmSC <- kexCommonEncAlgorithm ski cki kexEncryptionAlgorithmsServerToClient
            case (kexAlgorithm, encAlgorithmCS, encAlgorithmSC) of
                (Curve25519Sha256AtLibsshDotOrg, Chacha20Poly1305AtOpensshDotCom, Chacha20Poly1305AtOpensshDotCom) ->
                    kexWithVerifiedSignature shk hash sig $ do
                        -- The session id does not change after the first key exchange.
                        -- The next operation eventually initializes it and returns
                        -- the existing session id otherwise.
                        sid <- trySetSessionId env (SessionId $ SBS.toShort $ BA.convert hash)
                        -- The host key variable can only be set during the initial key exchange.
                        -- According to standard, the host keys may change but it is ignored here.
                        -- This is secure under the assumption that the authenticated channel over
                        -- which subsequent key exchanges take place is not compromised.
                        void $ tryPutMVar mHostKey shk
                        setChaCha20Poly1305Context $ kexKeys sec hash sid
                        transportSendMessage env KexNewKeys
            where
                cv   = tClientVersion env
                sv   = tServerVersion env
                shk  = kexServerHostKey ecdhReply
                sek  = kexServerEphemeralKey ecdhReply
                sec  = Curve25519.dh sek cekSecret
                sig  = kexHashSignature ecdhReply
                hash = kexHash cv sv cki ski shk cek sek sec

        setChaCha20Poly1305Context :: KeyStreams -> IO ()
        setChaCha20Poly1305Context (KeyStreams keys) = do
            modifyMVar_ (tEncryptionCtxNext env) $ const
                $ newChaCha20Poly1305EncryptionContext stream headerKeyCS mainKeyCS
            modifyMVar_ (tDecryptionCtxNext env) $ const
                $ newChaCha20Poly1305DecryptionContext stream headerKeySC mainKeySC
            where
                -- Derive the required encryption/decryption keys.
                -- The integrity keys etc. are not needed with chacha20.
                mainKeyCS : headerKeyCS : _ = keys "C"
                mainKeySC : headerKeySC : _ = keys "D"

-------------------------------------------------------------------------------
-- KEY EXCHANGE (GENERIC)
-------------------------------------------------------------------------------

kexTrigger :: Transport -> IO ()
kexTrigger env = do
    modifyMVar_ (tKexContinuation env) $ \(KexContinuation f) -> f Nothing

kexTriggerWhenNecessary :: Transport -> IO ()
kexTriggerWhenNecessary env = do
    required <- kexRekeyingRequired env
    when required (kexTrigger env)

kexSetMilestone :: Transport -> IO ()
kexSetMilestone env = do
    void $ modifyMVar_ (tKexCount env) $ \count -> pure $! count + 1
    void $ swapMVar (tKexLastTime         env) =<< getEpochSeconds
    void $ swapMVar (tKexLastDataSent     env) =<< readMVar (tBytesSent     env)
    void $ swapMVar (tKexLastDataReceived env) =<< readMVar (tBytesReceived env)

kexContinue :: Transport -> KexStep -> IO ()
kexContinue env step = do
    modifyMVar_ (tKexContinuation env) $ \(KexContinuation f) -> f (Just step)

kexCommonKexAlgorithm :: KexInit -> KexInit -> IO KeyExchangeAlgorithm
kexCommonKexAlgorithm ski cki = case kexKexAlgorithms cki `intersect` kexKexAlgorithms ski of
    (x:_)
        | x == name Curve25519Sha256AtLibsshDotOrg -> pure Curve25519Sha256AtLibsshDotOrg
    _ -> throwIO exceptionKexNoCommonKexAlgorithm

kexCommonEncAlgorithm :: KexInit -> KexInit -> (KexInit -> [Name]) -> IO EncryptionAlgorithm
kexCommonEncAlgorithm ski cki f = case f cki `intersect` f ski of
    (x:_)
        | x == name Chacha20Poly1305AtOpensshDotCom -> pure Chacha20Poly1305AtOpensshDotCom
    _ -> throwIO exceptionKexNoCommonEncryptionAlgorithm

kexInit :: TransportConfig -> Cookie -> KexInit
kexInit config cookie = KexInit
    {   kexCookie                              = cookie
    ,   kexServerHostKeyAlgorithms             = NEL.toList $ fmap name (serverHostKeyAlgorithms config)
    ,   kexKexAlgorithms                       = NEL.toList $ fmap name (kexAlgorithms config)
    ,   kexEncryptionAlgorithmsClientToServer  = NEL.toList $ fmap name (encryptionAlgorithms config)
    ,   kexEncryptionAlgorithmsServerToClient  = NEL.toList $ fmap name (encryptionAlgorithms config)
    ,   kexMacAlgorithmsClientToServer         = []
    ,   kexMacAlgorithmsServerToClient         = []
    ,   kexCompressionAlgorithmsClientToServer = [name None]
    ,   kexCompressionAlgorithmsServerToClient = [name None]
    ,   kexLanguagesClientToServer             = []
    ,   kexLanguagesServerToClient             = []
    ,   kexFirstPacketFollows                  = False
    }

kexRekeyingRequired :: Transport -> IO Bool
kexRekeyingRequired env = do
    tNow <- getEpochSeconds
    t    <- readMVar (tKexLastTime env)
    sNow <- readMVar (tBytesSent env)
    s    <- readMVar (tKexLastDataSent env)
    rNow <- readMVar (tBytesReceived env)
    r    <- readMVar (tKexLastDataReceived env)
    pure $ t + interval  <= tNow
        || s + threshold <= sNow
        || r + threshold <= rNow
  where
    -- For reasons of fool-proofness the rekeying interval/threshold
    -- shall never be greater than 1 hour or 1GB.
    -- NB: This is security critical as some algorithms like ChaCha20
    -- use the packet counter as nonce and an overflow will lead to
    -- nonce reuse!
    interval  = min (maxTimeBeforeRekey $ tConfig env) 3600
    threshold = min (maxDataBeforeRekey $ tConfig env) (1024 * 1024 * 1024)

kexHash ::
    Version ->               -- client version string
    Version ->               -- server version string
    KexInit ->               -- client kex init msg
    KexInit ->               -- server kex init msg
    PublicKey ->             -- server host key
    Curve25519.PublicKey ->  -- client ephemeral key
    Curve25519.PublicKey ->  -- server ephemeral key
    Curve25519.DhSecret ->   -- dh secret
    Hash.Digest Hash.SHA256
kexHash (Version vc) (Version vs) ic is ks qc qs k
    = Hash.hash $ runPut $
        putShortString         vc <>
        putShortString         vs <>
        B.word32BE       (len ic) <>
        put                    ic <>
        B.word32BE       (len is) <>
        put                    is <>
        putPublicKey           ks <>
        putCurve25519PublicKey qc <>
        putCurve25519PublicKey qs <>
        putAsMPInt             k
    where
        len = fromIntegral . B.length . put

kexKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> SessionId -> KeyStreams
kexKeys secret hash (SessionId sess) = KeyStreams $ \i -> BA.convert <$> k1 i : f [k1 i]
    where
        k1 i = Hash.hashFinalize $
            flip Hash.hashUpdate (SBS.fromShort sess) $
            Hash.hashUpdate st i :: Hash.Digest Hash.SHA256
        f ks = kx : f (ks ++ [kx])
            where
            kx = Hash.hashFinalize (foldl Hash.hashUpdate st ks)
        st =
            flip Hash.hashUpdate hash $
            Hash.hashUpdate Hash.hashInit (runPut $ putAsMPInt secret)

kexWithVerifiedSignature :: BA.ByteArrayAccess hash => PublicKey -> hash -> Signature -> IO a -> IO a
kexWithVerifiedSignature key hash sig action = case (key, sig) of
    (PublicKeyEd25519 k, SignatureEd25519 s)
        | Ed25519.verify k hash s -> action
    _ -> throwIO exceptionKexInvalidSignature

-------------------------------------------------------------------------------
-- UTIL
-------------------------------------------------------------------------------

sendVersion :: (OutputStream stream) => stream -> Version -> IO ()
sendVersion stream v = do
    sendAll stream $ runPut $ put v

-- The maximum length of the version string is 255 chars including CR+LF.
-- The version string is usually short and transmitted within
-- a single TCP segment.
receiveVersion :: (InputStream stream) => stream -> IO Version
receiveVersion stream = do
    bs <- peek stream 255
    when (BS.null bs) e0
    case BS.elemIndex 0x0a bs of
        Nothing -> e1
        Just i  -> maybe e1 pure . runGet =<< receive stream (i+1)
    where
        e0 = throwIO exceptionConnectionLost
        e1 = throwIO exceptionProtocolVersionNotSupported

getEpochSeconds :: IO Word64
getEpochSeconds = (`div` 1000000000) <$> getMonotonicTimeNSec

trySetSessionId :: Transport -> SessionId -> IO SessionId
trySetSessionId env sidDef =
    tryReadMVar (tSessionId env) >>= \case
        Nothing  -> putMVar (tSessionId env) sidDef >> pure sidDef
        Just sid -> pure sid

withFinalExceptionHandler :: IO (Either Disconnect a) -> IO (Either Disconnect a)
withFinalExceptionHandler =
    handle $ \e -> maybe (throwIO e) (pure . Left) (fromException e)

withRespondingExceptionHandler :: Transport -> IO a -> IO (Either Disconnect a)
withRespondingExceptionHandler env run = (Right <$> run) `catch` \e-> case e of
    Disconnect _ DisconnectConnectionLost _ -> pure (Left e)
    Disconnect Local r (DisconnectMessage m) ->
        withAsync (threadDelay (1000*1000)) $ \thread1 ->
        withAsync (transportSendMessage env $ Disconnected r (SBS.toShort m) mempty) $ \thread2 -> do
            atomically $ void (waitCatchSTM thread1) <|> void (waitCatchSTM thread2)
            pure (Left e)
    _ -> pure (Left e)

newTransport :: DuplexStream stream
    => TransportConfig -> stream -> Version -> Version -> IO Transport
newTransport config stream cv sv = do
    xBytesSent           <- newMVar 0
    xPacketsSent         <- newMVar 0
    xBytesReceived       <- newMVar 0
    xPacketsReceived     <- newMVar 0
    xEncryptionCtx       <- newMVar (plainEncryptionContext stream)
    xEncryptionCtxNext   <- newMVar (plainEncryptionContext stream)
    xDecryptionCtx       <- newMVar (plainDecryptionContext stream)
    xDecryptionCtxNext   <- newMVar (plainDecryptionContext stream)
    xKexContinuation     <- newEmptyMVar
    xSessionId           <- newEmptyMVar
    xKexCount            <- newMVar 0
    xKexTime             <- newMVar =<< getEpochSeconds
    xKexSent             <- newMVar 0
    xKexRcvd             <- newMVar 0
    pure Transport
        { tConfig                   = config
        , tClientVersion            = cv
        , tServerVersion            = sv
        , tBytesSent                = xBytesSent
        , tPacketsSent              = xPacketsSent
        , tBytesReceived            = xBytesReceived
        , tPacketsReceived          = xPacketsReceived
        , tEncryptionCtx            = xEncryptionCtx
        , tEncryptionCtxNext        = xEncryptionCtxNext
        , tDecryptionCtx            = xDecryptionCtx
        , tDecryptionCtxNext        = xDecryptionCtxNext
        , tKexContinuation          = xKexContinuation
        , tSessionId                = xSessionId
        , tKexCount                 = xKexCount
        , tKexLastTime              = xKexTime
        , tKexLastDataSent          = xKexSent
        , tKexLastDataReceived      = xKexRcvd
        }
