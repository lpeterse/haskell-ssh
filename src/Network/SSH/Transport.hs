{-# LANGUAGE ExistentialQuantification, OverloadedStrings, MultiWayIf, GeneralizedNewtypeDeriving, TupleSections, LambdaCase #-}
module Network.SSH.Transport
    ( MonadTransport (..)
    , TransportEnv()
    , KeyStreams (..)
    , withTransport
    )
where

import           Control.Applicative
import           Control.Concurrent.MVar
import           Control.Exception              ( throwIO )
import           Control.Monad                  ( when, void )
import           Control.Monad.Catch            ( MonadThrow, MonadCatch, MonadMask )
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Reader
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
--import           System.Clock

import           Network.SSH.Encoding
import           Network.SSH.Stream
import           Network.SSH.Message
import           Network.SSH.Constants
import           Network.SSH.Algorithms
import           Network.SSH.Key

class MonadTransport m where
    sendRawMessage :: BS.ByteString -> m ()
    receiveRawMessage :: m BS.ByteString

newtype TransportM a = TransportM (ReaderT TransportEnv IO a)
    deriving (Functor, Applicative, Monad, MonadIO, MonadThrow, MonadCatch, MonadMask)

data TransportEnv
    = forall stream. DuplexStream stream => TransportEnv
    { tStream            :: stream
    , tConfig            :: TransportConfig
    , tClientVersion     :: Version
    , tServerVersion     :: Version
    , tBytesSent         :: MVar Word64
    , tPacketsSent       :: MVar Word64
    , tBytesReceived     :: MVar Word64
    , tPacketsReceived   :: MVar Word64
    , tEncryptionCtx     :: MVar EncryptionContext
    , tEncryptionCtxNext :: MVar EncryptionContext
    , tDecryptionCtx     :: MVar DecryptionContext
    , tDecryptionCtxNext :: MVar DecryptionContext
    , tKexContinuation   :: MVar KexContinuation
    }

data TransportConfig
    = TransportServerConfig
    { tHostKeys        :: NEL.NonEmpty KeyPair
    , tKexAlgorithms   :: NEL.NonEmpty KeyExchangeAlgorithm
    , tEncAlgorithms   :: NEL.NonEmpty EncryptionAlgorithm
    }
    | TransportClientConfig

instance MonadTransport TransportM where
    sendRawMessage bs = TransportM $ ask >>= \env-> liftIO (transportSendRawMessage env bs)
    receiveRawMessage = TransportM $ ask >>= \env-> liftIO (transportReceiveRawMessage env)

newtype KeyStreams = KeyStreams (BS.ByteString -> [BA.ScrubbedBytes])

type DecryptionContext = Word64 -> (Int -> IO BS.ByteString) -> IO BS.ByteString
type EncryptionContext = Word64 -> BS.ByteString -> IO BS.ByteString

data KexStep
    = Start
    | Init     KexInit
    | InitEcdh KexEcdhInit

newtype KexContinuation = KexContinuation (KexStep -> IO KexContinuation)

runTransportM :: TransportEnv -> TransportM a -> IO a
runTransportM st (TransportM r) = runReaderT r st

withTransport :: (DuplexStream stream) => TransportConfig -> stream -> TransportM () -> IO ()
withTransport config stream transportM = do
    xBytesSent           <- newMVar 0
    xPacketsSent         <- newMVar 0
    xBytesReceived       <- newMVar 0
    xPacketsReceived     <- newMVar 0
    xEncryptionCtx       <- newMVar plainEncryptionContext
    xEncryptionCtxNext   <- newMVar plainEncryptionContext
    xDecryptionCtx       <- newMVar plainDecryptionContext
    xDecryptionCtxNext   <- newMVar plainDecryptionContext
    xKexContinuation     <- newEmptyMVar
    let env = TransportEnv
            { tStream            = stream
            , tConfig            = config
            , tClientVersion     = version -- FIXME
            , tServerVersion     = version
            , tBytesSent         = xBytesSent
            , tPacketsSent       = xPacketsSent
            , tBytesReceived     = xBytesReceived
            , tPacketsReceived   = xPacketsReceived
            , tEncryptionCtx     = xEncryptionCtx
            , tEncryptionCtxNext = xEncryptionCtxNext
            , tDecryptionCtx     = xDecryptionCtx
            , tDecryptionCtxNext = xDecryptionCtxNext
            , tKexContinuation   = xKexContinuation
            }
    cookie <- newCookie
    sessionMVar <- newEmptyMVar
    putMVar xKexContinuation (kexContinuation env cookie sessionMVar)
    runTransportM env transportM

transportSendMessage :: Encoding msg => TransportEnv -> msg -> IO ()
transportSendMessage env msg =
    transportSendRawMessage env $ runPut (put msg) 

transportSendRawMessage :: TransportEnv -> BS.ByteString -> IO ()
transportSendRawMessage env@TransportEnv { tStream = stream } plainText =
    modifyMVar_ (tEncryptionCtx env) $ \encrypt -> do
        packets <- readMVar (tPacketsSent env)
        cipherText <- encrypt packets plainText
        sent <- sendAll stream cipherText
        modifyMVar_ (tBytesSent env)   $ \bytes -> pure $! bytes + fromIntegral sent
        modifyMVar_ (tPacketsSent env) $ \pacs  -> pure $! pacs + 1
        case tryParse plainText of
            Nothing         -> pure encrypt
            Just KexNewKeys -> readMVar (tEncryptionCtxNext env)

transportReceiveRawMessage :: TransportEnv -> IO BS.ByteString
transportReceiveRawMessage env@TransportEnv { tStream = stream } =
    maybe (transportReceiveRawMessage env) pure =<< receiveMaybe
    where
        receiveMaybe = modifyMVar (tDecryptionCtx env) $ \decrypt -> do
            packets <- readMVar (tPacketsReceived env)
            plainText <- decrypt packets receiveAll'
            modifyMVar_ (tPacketsReceived env) $ \pacs  -> pure $! pacs + 1
            case interpreter plainText of
                Just i  -> i >> pure (decrypt, Nothing)
                Nothing -> case tryParse plainText of
                    Just KexNewKeys  -> (,Nothing) <$> readMVar (tDecryptionCtxNext env)
                    Nothing -> pure (decrypt, Just plainText)

        receiveAll' i = do
            bs <- receiveAll stream i
            modifyMVar_ (tBytesReceived env) $ \bytes ->
                pure $! bytes + fromIntegral (BS.length bs)
            pure bs

        interpreter plainText = f i0 <|> f i1 <|> f i2 <|> f i3 <|> f i4 <|> f i5
            where
                f i = i <$> tryParse plainText
                i0 Disconnect {} = print "DISCONNECT"
                i1 Debug {} = pure ()
                i2 Ignore {} = pure ()
                i3 Unimplemented {} = pure ()
                i4 KexInit {} = pure ()
                i5 KexEcdhInit {} = pure ()

-------------------------------------------------------------------------------
-- CRYPTO ---------------------------------------------------------------------
-------------------------------------------------------------------------------

setChaCha20Poly1305Context :: TransportEnv -> KeyStreams -> IO ()
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
    when (paclen > maxPacketLength) $ throwIO $ Disconnect
        DisconnectProtocolError
        "max packet length exceeded"
        mempty
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
                Nothing -> throwIO $ Disconnect DisconnectProtocolError
                                                "packet structure"
                                                ""
                Just (h, t) ->
                    pure $ BS.take (BS.length t - fromIntegral h) t

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

kexContinuation :: TransportEnv -> Cookie -> MVar SessionId -> KexContinuation
kexContinuation env cookie sessionMVar = kex0
    where
        kex0 :: KexContinuation
        kex0 = KexContinuation $ \case
            Start -> do
                let ski = kexInit (tConfig env) cookie
                transportSendMessage env ski
                -- updateRekeyTracking transport
                pure (kex1 ski)
            Init cki -> do
                let ski = kexInit (tConfig env) cookie
                transportSendMessage env ski
                pure (kex2 ski cki)
            InitEcdh {} ->
                throwIO $ Disconnect DisconnectProtocolError "unexpected KexEcdhInit" mempty

        kex1 :: KexInit -> KexContinuation
        kex1 ski = KexContinuation $ \case
            Start -> do
                pure (kex1 ski) -- already in progress
            Init cki ->
                pure (kex2 cki ski)
            InitEcdh {} ->
                throwIO $ Disconnect DisconnectProtocolError "unexpected KexEcdhInit" mempty

        kex2 :: KexInit -> KexInit -> KexContinuation
        kex2 cki ski = KexContinuation $ \case
            Start -> do
                pure (kex2 cki ski) -- already in progress
            Init {} ->
                throwIO $ Disconnect DisconnectProtocolError "unexpected KexInit" mempty
            InitEcdh (KexEcdhInit clientEphemeralPublicKey) -> do
                completeEcdhExchange cki ski clientEphemeralPublicKey
                pure kex0

        completeEcdhExchange :: KexInit -> KexInit -> Curve25519.PublicKey -> IO ()
        completeEcdhExchange cki ski clientEphemeralPublicKey = do
            kexAlgorithm   <- commonKexAlgorithm   ski cki
            encAlgorithmCS <- commonEncAlgorithmCS ski cki
            encAlgorithmSC <- commonEncAlgorithmSC ski cki

            -- TODO: Dispatch here when implementing support for more algorithms.
            case (kexAlgorithm, encAlgorithmCS, encAlgorithmSC) of
                (Curve25519Sha256AtLibsshDotOrg, Chacha20Poly1305AtOpensshDotCom, Chacha20Poly1305AtOpensshDotCom) ->
                    completeCurve25519KeyExchange ski ski clientEphemeralPublicKey

        completeCurve25519KeyExchange :: KexInit -> KexInit -> Curve25519.PublicKey -> IO ()
        completeCurve25519KeyExchange cki ski clientEphemeralPublicKey = do
            -- Generate a Curve25519 keypair for elliptic curve Diffie-Hellman key exchange.
            serverEphemeralSecretKey <- Curve25519.generateSecretKey
            serverEphemeralPublicKey <- pure $ Curve25519.toPublic serverEphemeralSecretKey

            KeyPairEd25519 pubKey secKey <- do
                let isEd25519 KeyPairEd25519 {} = True
                    -- TODO: Required when more algorithms are implemented.
                    -- isEd25519 _                 = False
                case NEL.filter isEd25519 (tHostKeys $ tConfig env) of -- FIXME
                    (x:_) -> pure x
                    _     -> undefined -- impossible

            let secret = Curve25519.dh
                    clientEphemeralPublicKey
                    serverEphemeralSecretKey

            let hash = exchangeHash
                    (tClientVersion env)
                    (tServerVersion env)
                    cki
                    ski
                    (PublicKeyEd25519 pubKey)
                    clientEphemeralPublicKey
                    serverEphemeralPublicKey
                    secret

            -- The reply is shall be sent with the old encryption context.
            -- This is the case as long as the KexNewKeys message has not
            -- been transmitted.
            let hostKey = PublicKeyEd25519 pubKey
                ephmKey = serverEphemeralPublicKey
                signature = SignatureEd25519 $ Ed25519.sign secKey pubKey hash
            transportSendMessage env (KexEcdhReply hostKey ephmKey signature)

            session <- tryReadMVar sessionMVar >>= \case
                Just s -> pure s
                Nothing -> 
                    let s = SessionId (BA.convert hash)
                    in  putMVar sessionMVar s >> pure s

            setChaCha20Poly1305Context env $ deriveKeys secret hash session

            -- The encryption context shall be switched no earlier than
            -- before the new keys message has been transmitted.
            -- It's the sender's thread responsibility to switch the context.
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
kexInit TransportServerConfig { tKexAlgorithms = kexAlgos, tEncAlgorithms = encAlgos, tHostKeys = hostKeys } cookie =
    KexInit
        {   kexCookie                              = cookie
        ,   kexAlgorithms                          = NEL.toList $ fmap f kexAlgos
        ,   kexServerHostKeyAlgorithms             = NEL.toList $ NEL.nub $ fmap g hostKeys
        ,   kexEncryptionAlgorithmsClientToServer  = NEL.toList $ fmap h encAlgos
        ,   kexEncryptionAlgorithmsServerToClient  = NEL.toList $ fmap h encAlgos
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
