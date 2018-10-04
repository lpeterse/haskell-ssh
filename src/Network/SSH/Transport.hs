{-# LANGUAGE ExistentialQuantification, OverloadedStrings, MultiWayIf, TupleSections, LambdaCase #-}
module Network.SSH.Transport
    ( Transport()
    , TransportConfig (..)
    , Disconnected (..)
    , withTransport
    )
where

import           Control.Applicative
import           Control.Concurrent.MVar
import           Control.Concurrent.Async
import           Control.Monad.STM
import           Control.Concurrent.STM.TVar
import           Control.Exception              ( Exception, throwIO, handle, fromException)
import           Control.Monad                  ( when, void )
import qualified Crypto.Cipher.ChaCha          as ChaCha
import qualified Crypto.Hash                   as Hash
import qualified Crypto.MAC.Poly1305           as Poly1305
import qualified Crypto.PubKey.Curve25519      as Curve25519
import qualified Crypto.PubKey.Ed25519         as Ed25519
import           Data.Bits
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import           Data.List
import qualified Data.List.NonEmpty            as NEL
import           Data.Monoid                    ( (<>) )
import           Data.Word
import           GHC.Clock

import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Stream
import           Network.SSH.Message
import           Network.SSH.Constants
import           Network.SSH.Algorithms
import           Network.SSH.Key

data Transport
    = forall stream. DuplexStream stream => TransportEnv
    { tStream                   :: stream
    , tConfig                   :: TransportConfig
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
    = TransportServerConfig
    { tHostKeys          :: NEL.NonEmpty KeyPair
    , tKexAlgorithms     :: NEL.NonEmpty KeyExchangeAlgorithm
    , tEncAlgorithms     :: NEL.NonEmpty EncryptionAlgorithm
    , tOnSend            :: BS.ByteString -> IO ()
    , tOnReceive         :: BS.ByteString -> IO ()
    }
    | TransportClientConfig
    { tHostKeyAlgorithms :: NEL.NonEmpty HostKeyAlgorithm
    , tKexAlgorithms     :: NEL.NonEmpty KeyExchangeAlgorithm
    , tEncAlgorithms     :: NEL.NonEmpty EncryptionAlgorithm
    , tOnSend            :: BS.ByteString -> IO ()
    , tOnReceive         :: BS.ByteString -> IO ()
    }

newtype KeyStreams = KeyStreams (BS.ByteString -> [BA.ScrubbedBytes])

type DecryptionContext = Word64 -> (Int -> IO BS.ByteString) -> IO BS.ByteString
type EncryptionContext = Word64 -> BS.ByteString -> IO BS.ByteString

data KexStep
    = Init       KexInit
    | EcdhInit   KexEcdhInit
    | EcdhReply  KexEcdhReply

newtype KexContinuation = KexContinuation (Maybe KexStep -> IO KexContinuation)

data Disconnected
    = Disconnected       Disconnect
    | DisconnectedByPeer Disconnect
    deriving (Show)

instance Exception Disconnected where

instance MessageStream Transport where
    sendMessage t msg = do
        kexIfNecessary t
        transportSendMessage t msg
    receiveMessage t = do
        kexIfNecessary t
        transportReceiveMessage t

withTransport :: (DuplexStreamPeekable stream) => TransportConfig -> stream -> (Transport -> SessionId -> IO a) -> IO (Either Disconnected a)
withTransport config stream runWith = withFinalExceptionHandler $ do
    (clientVersion, serverVersion) <- case config of
        -- Receive the peer version and reject immediately if this
        -- is not an SSH connection attempt (before allocating
        -- any more resources); respond with the server version string.
        TransportServerConfig {} -> do
            cv <- receiveVersion stream
            sv <- sendVersion stream
            pure (cv, sv)
        -- Start with sending local version and then wait for response.
        TransportClientConfig {} -> do
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
    xRekeyTime           <- newMVar =<< ((`div` 1000000000) <$> getMonotonicTimeNSec)
    xRekeySent           <- newMVar 0
    xRekeyRcvd           <- newMVar 0
    let env = TransportEnv
            { tStream                   = stream
            , tConfig                   = config
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
        sessionId <- runInitialKeyExchange env
        a <- runWith env sessionId
        sendMessage env (Disconnect DisconnectByApplication mempty mempty)
        pure a
    where
        withFinalExceptionHandler :: IO (Either Disconnected a) -> IO (Either Disconnected a)
        withFinalExceptionHandler = handle $ \e -> case fromException e of
            Nothing -> throwIO e
            Just d@Disconnect {} -> pure $ Left $ Disconnected d

        withRespondingExceptionHandler :: Transport -> IO a -> IO (Either Disconnected a)
        withRespondingExceptionHandler env run = h $ g (Right <$> run)
            where
                h = handle $ pure . Left
                g = handle $ \e-> do 
                    case e of
                        Disconnect DisconnectConnectionLost _ _ -> pure ()
                        _ -> withAsync (sendMessage env e) $ \thread -> do
                                t <- registerDelay 1000000
                                atomically $ void (waitCatchSTM thread) <|> (readTVar t >>= check)
                    pure $ Left $ Disconnected e

transportSendMessage :: Encoding msg => Transport -> msg -> IO ()
transportSendMessage env msg =
    transportSendRawMessage env $ runPut (put msg)

transportReceiveMessage :: Encoding msg => Transport -> IO msg
transportReceiveMessage env = do
    raw <- transportReceiveRawMessage env
    maybe exception pure (tryParse raw)
    where
        exception = throwProtocolError "invalid/unexpected message"

transportSendRawMessage :: Transport -> BS.ByteString -> IO ()
transportSendRawMessage env@TransportEnv { tStream = stream } plainText =
    modifyMVar_ (tEncryptionCtx env) $ \encrypt -> do
        tOnSend (tConfig env) plainText
        packets <- readMVar (tPacketsSent env)
        cipherText <- encrypt packets plainText
        -- NB: Increase packet counter before sending in order
        --     to avoid nonce reuse in exceptional cases!
        modifyMVar_ (tPacketsSent env) $ \pacs  -> pure $! pacs + 1
        sent <- sendAll stream cipherText
        modifyMVar_ (tBytesSent env)   $ \bytes -> pure $! bytes + fromIntegral sent
        case tryParse plainText of
            Nothing         -> pure encrypt
            Just KexNewKeys -> readMVar (tEncryptionCtxNext env)

transportReceiveRawMessage :: Transport -> IO BS.ByteString
transportReceiveRawMessage env =
    maybe (transportReceiveRawMessage env) pure =<< transportReceiveRawMessageMaybe env

transportReceiveRawMessageMaybe :: Transport -> IO (Maybe BS.ByteString)
transportReceiveRawMessageMaybe env@TransportEnv { tStream = stream } =
    modifyMVar (tDecryptionCtx env) $ \decrypt -> do
        packets <- readMVar (tPacketsReceived env)
        plainText <- decrypt packets receiveAll'
        tOnReceive (tConfig env) plainText
        modifyMVar_ (tPacketsReceived env) $ \pacs  -> pure $! pacs + 1
        case interpreter plainText of
            Just i  -> i >> pure (decrypt, Nothing)
            Nothing -> case tryParse plainText of
                Just KexNewKeys  -> do
                    (,Nothing) <$> readMVar (tDecryptionCtxNext env)
                Nothing -> pure (decrypt, Just plainText)
    where
        receiveAll' i = do
            bs <- receiveAll stream i
            modifyMVar_ (tBytesReceived env) $ \bytes ->
                pure $! bytes + fromIntegral (BS.length bs)
            pure bs

        interpreter plainText = f i0 <|> f i1 <|> f i2 <|> f i3 <|> f i4 <|> f i5 <|> f i6
            where
                f i = i <$> tryParse plainText
                i0 x@Disconnect   {} = throwIO $ DisconnectedByPeer x
                i1 Debug          {} = pure ()
                i2 Ignore         {} = pure ()
                i3 Unimplemented  {} = pure ()
                i4 x@KexInit      {} = kexContinue env (Init x)
                i5 x@KexEcdhInit  {} = kexContinue env (EcdhInit x)
                i6 x@KexEcdhReply {} = kexContinue env (EcdhReply x)

-------------------------------------------------------------------------------
-- CRYPTO ---------------------------------------------------------------------
-------------------------------------------------------------------------------

setChaCha20Poly1305Context :: Transport -> KeyStreams -> IO ()
setChaCha20Poly1305Context env (KeyStreams keys) = do
    void $ swapMVar (tEncryptionCtxNext env) $! case tConfig env of
        TransportServerConfig {} -> chaCha20Poly1305EncryptionContext headerKeySC mainKeySC
        TransportClientConfig {} -> chaCha20Poly1305EncryptionContext headerKeyCS mainKeyCS
    void $ swapMVar (tDecryptionCtxNext env) $! case tConfig env of
        TransportServerConfig {} -> chaCha20Poly1305DecryptionContext headerKeyCS mainKeyCS
        TransportClientConfig {} -> chaCha20Poly1305DecryptionContext headerKeySC mainKeySC
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
    when (paclen > maxPacketLength) $
        throwProtocolError "max packet length exceeded"
    BS.drop 1 <$> getCipherText (fromIntegral paclen)

chaCha20Poly1305EncryptionContext :: BA.ByteArrayAccess key => key -> key -> Word64 -> BS.ByteString -> IO BS.ByteString
chaCha20Poly1305EncryptionContext headerKey mainKey packetsSent plain = pure $ ciph3 <> mac
    where
    plainlen = BA.length plain :: Int
    padlen =
        let p = 8 - ((1 + plainlen) `mod` 8)
        in  if p < 4 then p + 8 else p :: Int
    paclen   = 1 + plainlen + padlen :: Int
    padding  = BA.replicate padlen 0
    padlenBA = BA.singleton (fromIntegral padlen)
    paclenBA = BA.pack
        [ fromIntegral $ paclen `shiftR` 24
        , fromIntegral $ paclen `shiftR` 16
        , fromIntegral $ paclen `shiftR` 8
        , fromIntegral $ paclen `shiftR` 0
        ]
    nonceBA     = nonce packetsSent
    st1         = ChaCha.initialize 20 mainKey nonceBA
    st2         = ChaCha.initialize 20 headerKey nonceBA
    (poly, st3) = ChaCha.generate st1 64
    ciph1       = fst $ ChaCha.combine st2 paclenBA
    ciph2       = fst $ ChaCha.combine st3 $ padlenBA <> plain <> padding
    ciph3       = ciph1 <> ciph2
    mac         = BA.convert (Poly1305.auth (BS.take 32 poly) ciph3)

chaCha20Poly1305DecryptionContext :: BA.ByteArrayAccess key => key -> key -> Word64 -> (Int -> IO BS.ByteString) -> IO BS.ByteString
chaCha20Poly1305DecryptionContext headerKey mainKey packetsReceived getCipher = do
    paclenCiph <- getCipher 4

    let nonceBA         = nonce packetsReceived
    let ccMain = ChaCha.initialize 20 mainKey nonceBA
    let ccHeader = ChaCha.initialize 20 headerKey nonceBA
    let (poly, ccMain') = ChaCha.generate ccMain 64
    let paclenPlain = fst $ ChaCha.combine ccHeader paclenCiph
    let maclen          = 16
    let paclen =
            fromIntegral (BA.index paclenPlain 0)
                `shiftL` 24
                .|.      fromIntegral (BA.index paclenPlain 1)
                `shiftL` 16
                .|.      fromIntegral (BA.index paclenPlain 2)
                `shiftL` 8
                .|.      fromIntegral (BA.index paclenPlain 3)
                `shiftL` 0

    pac <- getCipher paclen
    mac <- getCipher maclen

    let authTagReceived = Poly1305.Auth $ BA.convert mac
    let authTagExpected =
            Poly1305.auth (BS.take 32 poly) (paclenCiph <> pac)

    if authTagReceived /= authTagExpected
        then throwIO $ Disconnect DisconnectMacError "" ""
        else do
            let plain = fst (ChaCha.combine ccMain' pac)
            case BS.uncons plain of
                Nothing     -> throwProtocolError "packet structure"
                Just (h, t) -> pure $ BS.take (BS.length t - fromIntegral h) t

-- The sequence number is always the lower 32 bits of the number of
-- packets received - 1. By specification, it wraps around every 2^32 packets.
-- Special care must be taken wrt to rekeying as the sequence number
-- is used as nonce in the ChaCha20Poly1305 encryption mode.
nonce :: Word64 -> BA.Bytes
nonce i =
    BA.pack
        [ 0
        , 0
        , 0
        , 0
        , fromIntegral $ i `shiftR` 24
        , fromIntegral $ i `shiftR` 16
        , fromIntegral $ i `shiftR` 8
        , fromIntegral $ i `shiftR` 0
        ] :: BA.Bytes

-------------------------------------------------------------------------------
-- KEY EXCHANGE ---------------------------------------------------------------
-------------------------------------------------------------------------------

runInitialKeyExchange :: Transport -> IO SessionId
runInitialKeyExchange env = do
    cookie <- newCookie
    putMVar (tKexContinuation env) $ case tConfig env of
        TransportClientConfig {} -> kexClientContinuation env cookie
        TransportServerConfig {} -> kexServerContinuation env cookie
    kexTrigger env
    dontAcceptMessageUntilKexComplete
    where
        dontAcceptMessageUntilKexComplete = do
            transportReceiveRawMessageMaybe env >>= \case
                Just _  -> errorInvalidTransition
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
            void $ swapMVar (tLastRekeyingTime         env) =<< ((`div` 1000000000) <$> getMonotonicTimeNSec)
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
            _ -> errorInvalidTransition
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
            _ -> errorInvalidTransition

        clientKex2 :: KexInit -> KexInit -> Curve25519.PublicKey -> Curve25519.SecretKey -> KexContinuation
        clientKex2 cki ski cek cekSecret = KexContinuation $ \case
            Nothing ->
                pure (clientKex2 cki ski cek cekSecret)
            Just (EcdhReply ecdhReply) -> do
                consumeEcdhReply cki ski cek cekSecret ecdhReply
                pure clientKex0
            _ -> errorInvalidTransition

        consumeEcdhReply :: KexInit -> KexInit -> Curve25519.PublicKey -> Curve25519.SecretKey -> KexEcdhReply -> IO ()
        consumeEcdhReply cki ski cek cekSecret ecdhReply = do
            kexAlgorithm   <- commonKexAlgorithm   ski cki
            encAlgorithmCS <- commonEncAlgorithmCS ski cki
            encAlgorithmSC <- commonEncAlgorithmSC ski cki
            case (kexAlgorithm, encAlgorithmCS, encAlgorithmSC) of
                (Curve25519Sha256AtLibsshDotOrg, Chacha20Poly1305AtOpensshDotCom, Chacha20Poly1305AtOpensshDotCom) ->
                    withVerifiedSignature shk hash sig $ do
                        sid <- trySetSessionId env (BA.convert hash)
                        setChaCha20Poly1305Context env $ deriveKeys sec hash sid
                        transportSendMessage env KexNewKeys
            where
                cv   = tClientVersion env
                sv   = tServerVersion env
                shk  = kexServerHostKey ecdhReply
                sek  = kexServerEphemeralKey ecdhReply
                sec  = Curve25519.dh sek cekSecret
                sig  = kexHashSignature ecdhReply
                hash = exchangeHash cv sv cki ski shk cek sek sec

-- NB: Uses transportSendMessage to avoid rekeying-loop
kexServerContinuation :: Transport -> Cookie -> KexContinuation
kexServerContinuation env cookie = serverKex0
    where
        serverKex0 :: KexContinuation
        serverKex0 = KexContinuation $ \case
            Nothing -> do
                transportSendMessage env ski
                pure (serverKex1 ski)
            Just (Init cki) -> do
                transportSendMessage env ski
                pure (serverKex2 cki ski)
            _ -> errorInvalidTransition
            where
                ski = kexInit (tConfig env) cookie

        serverKex1 :: KexInit -> KexContinuation
        serverKex1 ski = KexContinuation $ \case
            Nothing-> do
                pure (serverKex1 ski)
            Just (Init cki) ->
                pure (serverKex2 cki ski)
            _ -> errorInvalidTransition

        serverKex2 :: KexInit -> KexInit -> KexContinuation
        serverKex2 cki ski = KexContinuation $ \case
            Nothing -> do
                pure (serverKex2 cki ski)
            Just (EcdhInit (KexEcdhInit cek)) -> do
                emitEcdhReply cki ski cek
                pure serverKex0
            _ -> errorInvalidTransition

        emitEcdhReply :: KexInit -> KexInit -> Curve25519.PublicKey -> IO ()
        emitEcdhReply cki ski cek = do
            kexAlgorithm   <- commonKexAlgorithm   ski cki
            encAlgorithmCS <- commonEncAlgorithmCS ski cki
            encAlgorithmSC <- commonEncAlgorithmSC ski cki
            case (kexAlgorithm, encAlgorithmCS, encAlgorithmSC) of
                (Curve25519Sha256AtLibsshDotOrg, Chacha20Poly1305AtOpensshDotCom, Chacha20Poly1305AtOpensshDotCom) -> do
                    sekSecret <- Curve25519.generateSecretKey
                    let cv   = tClientVersion env
                        sv   = tServerVersion env
                        skp  = NEL.head (tHostKeys $ tConfig env)
                        shk  = toPublicKey skp
                        sek  = Curve25519.toPublic sekSecret
                        sec  = Curve25519.dh cek sekSecret
                        hash = exchangeHash cv sv cki ski shk cek sek sec
                    withSignature skp hash $ \sig -> do
                        sid <- trySetSessionId env (SessionId $ BA.convert hash)
                        setChaCha20Poly1305Context env $ deriveKeys sec hash sid
                        transportSendMessage env (KexEcdhReply shk sek sig)
                        transportSendMessage env KexNewKeys

commonKexAlgorithm :: KexInit -> KexInit -> IO KeyExchangeAlgorithm
commonKexAlgorithm ski cki = case kexAlgorithms cki `intersect` kexAlgorithms ski of
    ("curve25519-sha256@libssh.org":_) -> pure Curve25519Sha256AtLibsshDotOrg
    _ -> throwIO (Disconnect DisconnectKeyExchangeFailed "no common kex algorithm" mempty)

commonEncAlgorithmCS :: KexInit -> KexInit -> IO EncryptionAlgorithm
commonEncAlgorithmCS ski cki = case kexEncryptionAlgorithmsClientToServer cki `intersect` kexEncryptionAlgorithmsClientToServer ski of
    ("chacha20-poly1305@openssh.com":_) -> pure Chacha20Poly1305AtOpensshDotCom
    _ -> throwIO (Disconnect DisconnectKeyExchangeFailed "no common encryption algorithm (client to server)" mempty)

commonEncAlgorithmSC :: KexInit -> KexInit -> IO EncryptionAlgorithm
commonEncAlgorithmSC ski cki = case kexEncryptionAlgorithmsServerToClient cki `intersect` kexEncryptionAlgorithmsServerToClient ski of
    ("chacha20-poly1305@openssh.com":_) -> pure Chacha20Poly1305AtOpensshDotCom
    _ -> throwIO (Disconnect DisconnectKeyExchangeFailed "no common encryption algorithm (server to client)" mempty)

kexInit :: TransportConfig -> Cookie -> KexInit
kexInit config cookie = case config of
    TransportServerConfig { tKexAlgorithms = kexAlgos, tEncAlgorithms = encAlgos, tHostKeys = hostKeys } ->
        ki kexAlgos encAlgos (fmap hostAlgo hostKeys)
    TransportClientConfig { tKexAlgorithms = kexAlgos, tEncAlgorithms = encAlgos, tHostKeyAlgorithms = hostAlgos } ->
        ki kexAlgos encAlgos hostAlgos
    where
        ki kexAlgos encAlgos hostAlgos = KexInit
            {   kexCookie                              = cookie
            ,   kexAlgorithms                          = NEL.toList $ fmap algorithmName kexAlgos
            ,   kexServerHostKeyAlgorithms             = NEL.toList $ fmap algorithmName hostAlgos
            ,   kexEncryptionAlgorithmsClientToServer  = NEL.toList $ fmap algorithmName encAlgos
            ,   kexEncryptionAlgorithmsServerToClient  = NEL.toList $ fmap algorithmName encAlgos
            ,   kexMacAlgorithmsClientToServer         = []
            ,   kexMacAlgorithmsServerToClient         = []
            ,   kexCompressionAlgorithmsClientToServer = [algorithmName None]
            ,   kexCompressionAlgorithmsServerToClient = [algorithmName None]
            ,   kexLanguagesClientToServer             = []
            ,   kexLanguagesServerToClient             = []
            ,   kexFirstPacketFollows                  = False
            }
        hostAlgo KeyPairEd25519 {} = SshEd25519

kexRekeyingRequired :: Transport -> IO Bool
kexRekeyingRequired env = do
    t <-  (`div` 1000000000) <$> getMonotonicTimeNSec
    t0 <- readMVar (tLastRekeyingTime env)
    s  <- readMVar (tBytesSent env)
    s0 <- readMVar (tLastRekeyingDataSent env)
    r  <- readMVar (tBytesReceived env)
    r0 <- readMVar (tLastRekeyingDataReceived env)
    pure $ if
        | intervalExceeded t t0  -> True
        | thresholdExceeded s s0 -> True
        | thresholdExceeded r r0 -> True
        | otherwise              -> False
  where
    -- For reasons of fool-proofness the rekeying interval/threshold
    -- shall never be greater than 1 hour or 1GB.
    -- NB: This is security critical as some algorithms like ChaCha20
    -- use the packet counter as nonce and an overflow will lead to
    -- nonce reuse!
    -- FIXME: honor config option
    interval  = 6 -- min (maxTimeBeforeRekey config) 3600
    threshold = 1024 * 1024 * 1024 -- min (maxDataBeforeRekey config) (1024 * 1024 * 1024)
    intervalExceeded t t0 = t > t0 && t - t0 > interval
    thresholdExceeded x x0 = x > x0 && x - x0 > threshold

trySetSessionId :: Transport -> SessionId -> IO SessionId
trySetSessionId env sidDef =
    tryReadMVar (tSessionId env) >>= \case
        Nothing  -> putMVar (tSessionId env) sidDef >> pure sidDef
        Just sid -> pure sid

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

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> SessionId -> KeyStreams
deriveKeys secret hash (SessionId sess) = KeyStreams $ \i -> BA.convert <$> (k1 i) : f [k1 i]
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

withSignature :: BA.ByteArrayAccess hash => KeyPair -> hash -> (Signature -> IO a) -> IO a
withSignature key hash handler = case key of
    KeyPairEd25519 pk sk -> handler $ SignatureEd25519 $ Ed25519.sign sk pk hash

withVerifiedSignature :: BA.ByteArrayAccess hash => PublicKey -> hash -> Signature -> IO a -> IO a
withVerifiedSignature key hash sig action = case (key, sig) of
    (PublicKeyEd25519 k, SignatureEd25519 s)
        | Ed25519.verify k hash s -> action
    _ -> errorInvalidSignature

-------------------------------------------------------------------------------
-- UTIL -----------------------------------------------------------------------
-------------------------------------------------------------------------------

errorInvalidTransition :: IO a
errorInvalidTransition = throwIO $
    Disconnect DisconnectKeyExchangeFailed "invalid transition" mempty

errorInvalidSignature :: IO a
errorInvalidSignature = throwIO $
    Disconnect DisconnectKeyExchangeFailed "invalid signature" mempty

errorNotImplemented :: IO a
errorNotImplemented = throwIO $
    Disconnect DisconnectByApplication "not implemented" mempty

throwProtocolError :: BS.ByteString -> IO a
throwProtocolError e = throwIO $ Disconnect DisconnectProtocolError e mempty

-- The maximum length of the version string is 255 chars including CR+LF.
-- The version string is usually short and transmitted within
-- a single TCP segment. The concatenation is therefore unlikely to happen
-- for regular use cases, but nonetheless required for correctness.
-- It is furthermore assumed that the client does not send any more data
-- after the version string before having received a response from the server;
-- otherwise parsing will fail. This is done in order to not having to deal with leftovers.
-- FIXME: use some kind of peek on the stream
receiveVersion :: (InputStreamPeekable stream) => stream -> IO Version
receiveVersion stream = do
    bs <- peek stream 255
    when (BS.null bs) e0
    case BS.elemIndex 0x0a bs of
        Nothing -> e1
        Just i  -> maybe e1 pure . tryParse =<< receive stream (i+1)
    where
        e0 = throwIO exceptionConnectionLost
        e1 = throwIO exceptionProtocolVersionNotSupported

sendVersion :: (OutputStream stream) => stream -> IO Version
sendVersion stream = do
    void $ sendAll stream $ runPut $ put version
    pure version
