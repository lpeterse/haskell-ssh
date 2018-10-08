{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE MultiWayIf                #-}
{-# LANGUAGE TupleSections             #-}
{-# LANGUAGE LambdaCase                #-}
module Network.SSH.Transport
    ( Transport()
    , TransportConfig (..)
    , Disconnected (..)
    , withTransport
    )
where

import           Control.Applicative
import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TVar
import           Control.Exception              ( throwIO, handle, catch, fromException)
import           Control.Monad                  ( when, void )
import           Control.Monad.STM
import           Data.Bits
import           Data.Default
import           Data.List
import           Data.Monoid                    ( (<>) )
import           Data.Word
import           GHC.Clock
import           Foreign.Ptr
import qualified Crypto.Cipher.ChaCha          as ChaCha
import qualified Crypto.Hash                   as Hash
import qualified Crypto.MAC.Poly1305           as Poly1305
import qualified Crypto.PubKey.Curve25519      as Curve25519
import qualified Crypto.PubKey.Ed25519         as Ed25519
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import qualified Data.List.NonEmpty            as NEL
import           Data.Memory.PtrMethods

import           Network.SSH.Algorithms
import qualified Network.SSH.Builder           as B
import           Network.SSH.AuthAgent
import           Network.SSH.Constants
import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Message
import           Network.SSH.Stream

data Transport
    = forall stream. DuplexStream stream => TransportEnv
    { tStream                   :: stream
    , tConfig                   :: TransportConfig
    , tAuthAgent                :: Maybe AuthAgent
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
    , tLastRekeyingTime         :: MVar Word64
    , tLastRekeyingDataSent     :: MVar Word64
    , tLastRekeyingDataReceived :: MVar Word64
    }

data TransportConfig
    = TransportConfig
    { serverHostKeyAlgorithms :: NEL.NonEmpty HostKeyAlgorithm
    , kexAlgorithms           :: NEL.NonEmpty KeyExchangeAlgorithm
    , encryptionAlgorithms    :: NEL.NonEmpty EncryptionAlgorithm
    , maxTimeBeforeRekey      :: Word64
    , maxDataBeforeRekey      :: Word64
    , onSend                  :: BS.ByteString -> IO ()
    , onReceive               :: BS.ByteString -> IO ()
    }

instance Default TransportConfig where
    def = TransportConfig
        { serverHostKeyAlgorithms  = pure SshEd25519
        , kexAlgorithms            = pure Curve25519Sha256AtLibsshDotOrg
        , encryptionAlgorithms     = pure Chacha20Poly1305AtOpensshDotCom
        , maxTimeBeforeRekey       = 3600
        , maxDataBeforeRekey       = 1000 * 1000 * 1000
        , onSend                   = const (pure ())
        , onReceive                = const (pure ())
        }

newtype KeyStreams = KeyStreams (BS.ByteString -> [BA.Bytes])

type DecryptionContext = Word64 -> (Int -> IO BS.ByteString) -> IO BS.ByteString
type EncryptionContext = Word64 -> B.ByteArrayBuilder -> IO BS.ByteString

data KexStep
    = Init       KexInit
    | EcdhInit   KexEcdhInit
    | EcdhReply  KexEcdhReply

newtype KexContinuation = KexContinuation (Maybe KexStep -> IO KexContinuation)

instance MessageStream Transport where
    sendMessage t msg = do
        kexIfNecessary t
        transportSendMessage t msg
    receiveMessage t = do
        kexIfNecessary t
        transportReceiveMessage t

withTransport ::
    (DuplexStream stream) =>
    TransportConfig -> Maybe AuthAgent -> stream ->
    (Transport -> SessionId -> IO a) -> IO (Either Disconnect a)
withTransport config magent stream runWith = withFinalExceptionHandler $ do
    (clientVersion, serverVersion) <- case magent of
        -- Receive the peer version and reject immediately if this
        -- is not an SSH connection attempt (before allocating
        -- any more resources); respond with the server version string.
        Just {} -> do
            cv <- receiveVersion stream
            sv <- sendVersion stream
            pure (cv, sv)
        -- Start with sending local version and then wait for response.
        Nothing -> do
            cv <- sendVersion stream
            sv <- receiveVersion stream
            pure (cv, sv)
    xBytesSent           <- newMVar 0
    xPacketsSent         <- newMVar 0
    xBytesReceived       <- newMVar 0
    xPacketsReceived     <- newMVar 0
    xEncryptionCtx       <- newMVar plainEncryptionContext
    xEncryptionCtxNext   <- newMVar plainEncryptionContext
    xDecryptionCtx       <- newMVar plainDecryptionContext
    xDecryptionCtxNext   <- newMVar plainDecryptionContext
    xKexContinuation     <- newEmptyMVar
    xSessionId           <- newEmptyMVar
    xRekeyTime           <- newMVar =<< getEpochSeconds
    xRekeySent           <- newMVar 0
    xRekeyRcvd           <- newMVar 0
    let env = TransportEnv
            { tStream                   = stream
            , tConfig                   = config
            , tAuthAgent                = magent
            , tClientVersion            = clientVersion
            , tServerVersion            = serverVersion
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
            , tLastRekeyingTime         = xRekeyTime
            , tLastRekeyingDataSent     = xRekeySent
            , tLastRekeyingDataReceived = xRekeyRcvd
            }
    withRespondingExceptionHandler env $ do
        sessionId <- kexInitialize env
        a <- runWith env sessionId
        sendMessage env (Disconnected DisconnectByApplication mempty mempty)
        pure a
    where
        withFinalExceptionHandler :: IO (Either Disconnect a) -> IO (Either Disconnect a)
        withFinalExceptionHandler =
            handle $ \e -> maybe (throwIO e) (pure . Left) (fromException e)

        withRespondingExceptionHandler :: Transport -> IO a -> IO (Either Disconnect a)
        withRespondingExceptionHandler env run = (Right <$> run) `catch` \e-> case e of
            Disconnect _ DisconnectConnectionLost _ -> pure (Left e)
            Disconnect Local r (DisconnectMessage m) ->
                withAsync (transportSendMessage env $ Disconnected r m mempty) $ \thread -> do
                    t <- registerDelay (1000*1000)
                    atomically $ void (waitCatchSTM thread) <|> (readTVar t >>= check)
                    pure (Left e)
            _ -> pure (Left e)

transportSendMessage :: Encoding msg => Transport -> msg -> IO ()
transportSendMessage env msg =
    transportSendRawMessage env (put msg)

transportSendRawMessage :: Transport -> B.ByteArrayBuilder -> IO ()
transportSendRawMessage env@TransportEnv { tStream = stream } plainText =
    modifyMVar_ (tEncryptionCtx env) $ \encrypt -> do
        onSend (tConfig env) (runPut plainText)
        -- NB: Increase packet counter before sending in order
        --     to avoid nonce reuse in exceptional cases!
        packets <- modifyMVar (tPacketsSent env) $ \p -> pure . (,p) $! p + 1
        cipherText <- encrypt packets plainText
        sendAll stream cipherText
        modifyMVar_ (tBytesSent env) $ \bytes -> pure $! bytes + fromIntegral (BS.length cipherText)
        case tryParse (runPut plainText) of
            Nothing         -> pure encrypt
            Just KexNewKeys -> readMVar (tEncryptionCtxNext env)

transportReceiveMessage :: Encoding msg => Transport -> IO msg
transportReceiveMessage env = do
    raw <- transportReceiveRawMessage env
    maybe (throwIO $ exceptionUnexpectedMessage raw) pure (tryParse raw)

transportReceiveRawMessage :: Transport -> IO BS.ByteString
transportReceiveRawMessage env =
    maybe (transportReceiveRawMessage env) pure =<< transportReceiveRawMessageMaybe env

transportReceiveRawMessageMaybe :: Transport -> IO (Maybe BS.ByteString)
transportReceiveRawMessageMaybe env@TransportEnv { tStream = stream } =
    modifyMVar (tDecryptionCtx env) $ \decrypt -> do
        packets <- readMVar (tPacketsReceived env)
        plainText <- decrypt packets (receiveAll mempty)
        onReceive (tConfig env) plainText
        modifyMVar_ (tPacketsReceived env) $ \pacs  -> pure $! pacs + 1
        case interpreter plainText of
            Just i  -> i >> pure (decrypt, Nothing)
            Nothing -> case tryParse plainText of
                Just KexNewKeys  -> do
                    (,Nothing) <$> readMVar (tDecryptionCtxNext env)
                Nothing -> pure (decrypt, Just plainText)
    where
        receiveAll :: BS.ByteString -> Int -> IO BS.ByteString
        receiveAll acc requested
            | BS.length acc >= requested = pure acc
            | otherwise = do
                bs <- receive stream requested
                when (BS.null bs) (throwIO exceptionConnectionLost)
                modifyMVar_ (tBytesReceived env) $ \bytes ->
                    pure $! bytes + fromIntegral (BS.length bs)
                receiveAll (acc <> bs) (requested - BS.length bs)

        interpreter plainText = f i0 <|> f i1 <|> f i2 <|> f i3 <|> f i4 <|> f i5 <|> f i6
            where
                f i = i <$> tryParse plainText
                i0 (Disconnected r m _) = throwIO $ Disconnect Remote r (DisconnectMessage m)
                i1 Debug             {} = pure ()
                i2 Ignore            {} = pure ()
                i3 Unimplemented     {} = pure ()
                i4 x@KexInit         {} = kexContinue env (Init x)
                i5 x@KexEcdhInit     {} = kexContinue env (EcdhInit x)
                i6 x@KexEcdhReply    {} = kexContinue env (EcdhReply x)

-------------------------------------------------------------------------------
-- CRYPTO ---------------------------------------------------------------------
-------------------------------------------------------------------------------

setChaCha20Poly1305Context :: Transport -> KeyStreams -> IO ()
setChaCha20Poly1305Context env (KeyStreams keys) = do
    void $ swapMVar (tEncryptionCtxNext env) $! case tAuthAgent env of
        Just {} -> chaCha20Poly1305EncryptionContext headerKeySC mainKeySC
        Nothing -> chaCha20Poly1305EncryptionContext headerKeyCS mainKeyCS
    void $ swapMVar (tDecryptionCtxNext env) $! case tAuthAgent env of
        Just {} -> chaCha20Poly1305DecryptionContext headerKeyCS mainKeyCS
        Nothing -> chaCha20Poly1305DecryptionContext headerKeySC mainKeySC
    where
    -- Derive the required encryption/decryption keys.
    -- The integrity keys etc. are not needed with chacha20.
    mainKeyCS : headerKeyCS : _ = keys "C"
    mainKeySC : headerKeySC : _ = keys "D"

plainEncryptionContext :: EncryptionContext
plainEncryptionContext _ plainText = pure $ runPut (putPacked plainText)

plainDecryptionContext :: DecryptionContext
plainDecryptionContext _ getCipherText = do
    paclen <- runGet getWord32 =<< getCipherText 4
    when (paclen > maxPacketLength) (throwIO exceptionPacketLengthExceeded)
    BS.drop 1 <$> getCipherText (fromIntegral paclen)

chaCha20Poly1305EncryptionContext :: BA.ByteArrayAccess key => key -> key -> Word64 -> B.ByteArrayBuilder -> IO BS.ByteString
chaCha20Poly1305EncryptionContext headerKey mainKey packetsSent plainBuilder = do
    let headSt   = ChaCha.initialize 20 headerKey nonceBA
    let headCiph = fst $ ChaCha.generate headSt 4 :: BA.Bytes
    let mainSt   = ChaCha.initialize 20 mainKey nonceBA
    let mainCiph = fst $ ChaCha.generate mainSt (64 + packetLen) :: BA.Bytes
    BA.alloc (headerLen + packetLen + macLen) $ \ptr ->
        BA.withByteArray headCiph $ \headCiphPtr ->
        BA.withByteArray mainCiph $ \mainCiphPtr -> do
            -- Header
            B.copyToPtr (B.word32BE $ fromIntegral packetLen) ptr
            memXor ptr ptr headCiphPtr headerLen
            -- Payload
            B.copyToPtr (B.word8 $ fromIntegral paddingLen) (plusPtr ptr headerLen)
            B.copyToPtr plainBuilder (plusPtr ptr $ headerLen + 1)
            memSet (plusPtr ptr $ headerLen + 1 + plainLen) 0 paddingLen
            memXor (plusPtr ptr headerLen) (plusPtr ptr headerLen) (plusPtr mainCiphPtr 64) packetLen
            let auth = Poly1305.auth (BA.MemView mainCiphPtr 32) (BA.MemView ptr $ headerLen + packetLen)
            BA.copyByteArrayToPtr auth (plusPtr ptr $ headerLen + packetLen)
            pure ()
    where
    headerLen  = 4
    macLen     = 16
    plainLen   = B.babLength plainBuilder :: Int
    packetLen  = 1 + plainLen + paddingLen
    paddingLen = if p < 4 then p + 8 else p
        where
            p = 8 - ((1 + plainLen) `mod` 8)
    nonceBA     = nonce packetsSent

chaCha20Poly1305DecryptionContext :: BA.ByteArrayAccess key => key -> key -> Word64 -> (Int -> IO BS.ByteString) -> IO BS.ByteString
chaCha20Poly1305DecryptionContext headerKey mainKey packetsReceived getCipher = do
    cipherLen <- getCipher 4

    let nonceBA         = nonce packetsReceived
        ccMain          = ChaCha.initialize 20 mainKey nonceBA
        ccHeader        = ChaCha.initialize 20 headerKey nonceBA
        (poly, ccMain') = ChaCha.generate ccMain 64
        paclen          = fromWord32be $ fst $ ChaCha.combine ccHeader cipherLen
        maclen          = 16

    -- Receive both and then split/slice to reduce memory allocation/fragmentation.
    (cipherPac,mac) <- BS.splitAt paclen <$> getCipher (paclen + maclen)

    -- Check message integrity with Poly1305 authentication tag.
    let authTagReceived = Poly1305.Auth $ BA.convert mac :: Poly1305.Auth
        authTagExpected = Poly1305.auth (BS.take 32 poly) (cipherLen <> cipherPac)
    when (authTagReceived /= authTagExpected) (throwIO exceptionMacError)

    let plainPac = fst (ChaCha.combine ccMain' cipherPac)
    maybe (throwIO exceptionInvalidPacket)
        (\(h,t) -> pure  $ BS.take (BS.length t - fromIntegral h) t)
        (BS.uncons plainPac)
    where
        fromWord32be ba =
                 fromIntegral (BA.index ba 0) `shiftL` 24
            .|.  fromIntegral (BA.index ba 1) `shiftL` 16
            .|.  fromIntegral (BA.index ba 2) `shiftL` 8
            .|.  fromIntegral (BA.index ba 3) `shiftL` 0

-- The sequence number is always the lower 32 bits of the number of
-- packets received - 1. By specification, it wraps around every 2^32 packets.
-- Special care must be taken wrt to rekeying as the sequence number
-- is used as nonce in the ChaCha20Poly1305 encryption mode.
nonce :: Word64 -> BA.Bytes
nonce i = BA.pack
    [ 0, 0, 0, 0
    , fromIntegral $ i `shiftR` 24
    , fromIntegral $ i `shiftR` 16
    , fromIntegral $ i `shiftR` 8
    , fromIntegral $ i `shiftR` 0
    ]

-------------------------------------------------------------------------------
-- KEY EXCHANGE ---------------------------------------------------------------
-------------------------------------------------------------------------------

kexInitialize :: Transport -> IO SessionId
kexInitialize env = do
    cookie <- newCookie
    putMVar (tKexContinuation env) $ case tAuthAgent env of
        Just aa -> kexServerContinuation env cookie aa
        Nothing -> kexClientContinuation env cookie
    kexTrigger env
    dontAcceptMessageUntilKexComplete
    where
        dontAcceptMessageUntilKexComplete = do
            transportReceiveRawMessageMaybe env >>= \case
                Just _  -> throwIO exceptionKexInvalidTransition
                Nothing -> tryReadMVar (tSessionId env) >>= \case
                    Nothing -> dontAcceptMessageUntilKexComplete
                    Just sid -> pure sid

kexTrigger :: Transport -> IO ()
kexTrigger env = do
    modifyMVar_ (tKexContinuation env) $ \(KexContinuation f) -> f Nothing

kexIfNecessary :: Transport -> IO ()
kexIfNecessary env = do
    kexRekeyingRequired env >>= \case
        False -> pure ()
        True -> do
            void $ swapMVar (tLastRekeyingTime         env) =<< getEpochSeconds
            void $ swapMVar (tLastRekeyingDataSent     env) =<< readMVar (tBytesSent     env)
            void $ swapMVar (tLastRekeyingDataReceived env) =<< readMVar (tBytesReceived env)
            kexTrigger env

kexContinue :: Transport -> KexStep -> IO ()
kexContinue env step = do
    modifyMVar_ (tKexContinuation env) $ \(KexContinuation f) -> f (Just step)

-- NB: Uses transportSendMessage to avoid rekeying-loop
kexClientContinuation :: Transport -> Cookie -> KexContinuation
kexClientContinuation env cookie = clientKex0
    where
        clientKex0 :: KexContinuation
        clientKex0 = KexContinuation $ \case
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
            where
                cki = kexInit (tConfig env) cookie

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
                        sid <- trySetSessionId env (BA.convert hash)
                        setChaCha20Poly1305Context env $ kexKeys sec hash sid
                        transportSendMessage env KexNewKeys
            where
                cv   = tClientVersion env
                sv   = tServerVersion env
                shk  = kexServerHostKey ecdhReply
                sek  = kexServerEphemeralKey ecdhReply
                sec  = Curve25519.dh sek cekSecret
                sig  = kexHashSignature ecdhReply
                hash = kexHash cv sv cki ski shk cek sek sec

-- NB: Uses transportSendMessage to avoid rekeying-loop
kexServerContinuation :: Transport -> Cookie -> AuthAgent -> KexContinuation
kexServerContinuation env cookie authAgent = serverKex0
    where
        serverKex0 :: KexContinuation
        serverKex0 = KexContinuation $ \case
            Nothing -> do
                transportSendMessage env ski
                pure (serverKex1 ski)
            Just (Init cki) -> do
                transportSendMessage env ski
                pure (serverKex2 cki ski)
            _ -> throwIO exceptionKexInvalidTransition
            where
                ski = kexInit (tConfig env) cookie

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
            getPublicKeys authAgent >>= \case
                []    -> throwIO exceptionKexNoSignature
                shk:_ -> case (kexAlgorithm, encAlgorithmCS, encAlgorithmSC) of
                    (Curve25519Sha256AtLibsshDotOrg, Chacha20Poly1305AtOpensshDotCom, Chacha20Poly1305AtOpensshDotCom) -> do
                        sekSecret <- Curve25519.generateSecretKey
                        let cv   = tClientVersion env
                            sv   = tServerVersion env
                            sek  = Curve25519.toPublic sekSecret
                            sec  = Curve25519.dh cek sekSecret
                            hash = kexHash cv sv cki ski shk cek sek sec
                        sig <- maybe (throwIO exceptionKexNoSignature) pure =<< signHash authAgent shk hash
                        sid <- trySetSessionId env (SessionId $ BA.convert hash)
                        setChaCha20Poly1305Context env $ kexKeys sec hash sid
                        transportSendMessage env (KexEcdhReply shk sek sig)
                        transportSendMessage env KexNewKeys

kexCommonKexAlgorithm :: KexInit -> KexInit -> IO KeyExchangeAlgorithm
kexCommonKexAlgorithm ski cki = case kexKexAlgorithms cki `intersect` kexKexAlgorithms ski of
    (x:_)
        | x == algorithmName Curve25519Sha256AtLibsshDotOrg -> pure Curve25519Sha256AtLibsshDotOrg
    _ -> throwIO exceptionKexNoCommonKexAlgorithm

kexCommonEncAlgorithm :: KexInit -> KexInit -> (KexInit -> [BS.ByteString]) -> IO EncryptionAlgorithm
kexCommonEncAlgorithm ski cki f = case f cki `intersect` f ski of
    (x:_)
        | x == algorithmName Chacha20Poly1305AtOpensshDotCom -> pure Chacha20Poly1305AtOpensshDotCom
    _ -> throwIO exceptionKexNoCommonEncryptionAlgorithm

kexInit :: TransportConfig -> Cookie -> KexInit
kexInit config cookie = KexInit
    {   kexCookie                              = cookie
    ,   kexServerHostKeyAlgorithms             = NEL.toList $ fmap algorithmName (serverHostKeyAlgorithms config)
    ,   kexKexAlgorithms                       = NEL.toList $ fmap algorithmName (kexAlgorithms config)
    ,   kexEncryptionAlgorithmsClientToServer  = NEL.toList $ fmap algorithmName (encryptionAlgorithms config)
    ,   kexEncryptionAlgorithmsServerToClient  = NEL.toList $ fmap algorithmName (encryptionAlgorithms config)
    ,   kexMacAlgorithmsClientToServer         = []
    ,   kexMacAlgorithmsServerToClient         = []
    ,   kexCompressionAlgorithmsClientToServer = [algorithmName None]
    ,   kexCompressionAlgorithmsServerToClient = [algorithmName None]
    ,   kexLanguagesClientToServer             = []
    ,   kexLanguagesServerToClient             = []
    ,   kexFirstPacketFollows                  = False
    }

kexRekeyingRequired :: Transport -> IO Bool
kexRekeyingRequired env = do
    tNow <- getEpochSeconds
    t    <- readMVar (tLastRekeyingTime env)
    sNow <- readMVar (tBytesSent env)
    s    <- readMVar (tLastRekeyingDataSent env)
    rNow <- readMVar (tBytesReceived env)
    r    <- readMVar (tLastRekeyingDataReceived env)
    pure $ t + interval  < tNow
        || s + threshold < sNow
        || r + threshold < rNow
  where
    -- For reasons of fool-proofness the rekeying interval/threshold
    -- shall never be greater than 1 hour or 1GB.
    -- NB: This is security critical as some algorithms like ChaCha20
    -- use the packet counter as nonce and an overflow will lead to
    -- nonce reuse!
    interval  = min (maxTimeBeforeRekey $ tConfig env) 3600
    threshold = min (maxDataBeforeRekey $ tConfig env) (1024 * 1024 * 1024)

trySetSessionId :: Transport -> SessionId -> IO SessionId
trySetSessionId env sidDef =
    tryReadMVar (tSessionId env) >>= \case
        Nothing  -> putMVar (tSessionId env) sidDef >> pure sidDef
        Just sid -> pure sid

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
        putString vc <>
        putString vs <>
        putWord32 (len ic) <>
        put       ic <>
        putWord32 (len is) <>
        put       is <>
        put       ks <>
        put       qc <>
        put       qs <>
        putAsMPInt k

kexKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> SessionId -> KeyStreams
kexKeys secret hash (SessionId sess) = KeyStreams $ \i -> BA.convert <$> k1 i : f [k1 i]
    where
        k1 i = Hash.hashFinalize $
            flip Hash.hashUpdate sess $
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
-- UTIL -----------------------------------------------------------------------
-------------------------------------------------------------------------------

sendVersion :: (OutputStream stream) => stream -> IO Version
sendVersion stream = do
    void $ sendAll stream $ runPut $ put version
    pure version

-- The maximum length of the version string is 255 chars including CR+LF.
-- The version string is usually short and transmitted within
-- a single TCP segment.
receiveVersion :: (InputStream stream) => stream -> IO Version
receiveVersion stream = do
    bs <- peek stream 255
    when (BS.null bs) e0
    case BS.elemIndex 0x0a bs of
        Nothing -> e1
        Just i  -> maybe e1 pure . tryParse =<< receive stream (i+1)
    where
        e0 = throwIO exceptionConnectionLost
        e1 = throwIO exceptionProtocolVersionNotSupported

sendAll :: (OutputStream stream) => stream -> BS.ByteString -> IO ()
sendAll stream bs = sendAll' 0
    where
        sendAll' offset
            | offset >= BS.length bs = pure ()
            | otherwise = do
                sent <- send stream (BS.drop offset bs)
                when (sent <= 0) (throwIO exceptionConnectionLost)
                sendAll' (offset + sent)

getEpochSeconds :: IO Word64
getEpochSeconds = (`div` 1000000000) <$> getMonotonicTimeNSec