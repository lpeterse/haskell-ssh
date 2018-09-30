{-# LANGUAGE ExistentialQuantification, OverloadedStrings, MultiWayIf #-}
module Network.SSH.Server.Transport
    ( Transport()
    , Role (..)
    , KeyStreams (..)
    , withTransport
    , sendMessage
    , receiveMessage
    , switchEncryptionContext
    , switchDecryptionContext
    , sendServerVersion
    , receiveClientVersion
    , askRekeyingRequired
    , updateRekeyTracking
    , setChaCha20Poly1305Context
    )
where

import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Applicative
import           Control.Monad.STM              ( atomically, check )
import           Control.Monad                  ( when, void )
import           Control.Concurrent.Async
import           System.Clock
import           Control.Exception              ( throwIO, fromException, catch )
import qualified Crypto.Cipher.ChaCha          as ChaCha
import qualified Crypto.MAC.Poly1305           as Poly1305
import           Data.Bits
import           Data.Function                  ( fix )
import           Data.Maybe
import           Data.Word
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import           Data.Monoid                    ( (<>) )

import           Network.SSH.Encoding
import           Network.SSH.Stream
import           Network.SSH.Message
import           Network.SSH.Constants
import           Network.SSH.Server.Config

data Transport
    = forall stream. (DuplexStream stream) => Transport
    {   transportStream                   :: stream
    ,   transportQueue                    :: TChan Message
    ,   transportPacketsReceived          :: TVar Word64
    ,   transportBytesReceived            :: TVar Word64
    ,   transportPacketsSent              :: TVar Word64
    ,   transportBytesSent                :: TVar Word64
    ,   transportLastRekeyingTime         :: TVar Word64
    ,   transportLastRekeyingDataSent     :: TVar Word64
    ,   transportLastRekeyingDataReceived :: TVar Word64
    ,   transportEncryptionContext        :: TVar EncryptionContext
    ,   transportEncryptionContextNext    :: TVar EncryptionContext
    ,   transportDecryptionContext        :: TVar DecryptionContext
    ,   transportDecryptionContextNext    :: TVar DecryptionContext
    }

data Role = Client| Server
newtype KeyStreams = KeyStreams (BS.ByteString -> [BA.ScrubbedBytes])
type DecryptionContext = Word64 -> (Int -> IO BS.ByteString) -> IO BS.ByteString
type EncryptionContext = Word64 -> BS.ByteString -> IO BS.ByteString

withTransport :: DuplexStream stream => Config identity -> stream -> (Transport -> IO a) -> IO a
withTransport config stream runWith = do
    queue      <- newTChanIO
    packsSent  <- newTVarIO 0
    bytesSent  <- newTVarIO 0
    packsRcvd  <- newTVarIO 0
    bytesRcvd  <- newTVarIO 0
    rekeyTime  <- newTVarIO =<< fromIntegral . sec <$> getTime Monotonic
    rekeySent  <- newTVarIO 0
    rekeyRcvd  <- newTVarIO 0
    encCtx     <- newTVarIO plainEncryptionContext
    encCtxNext <- newTVarIO plainEncryptionContext
    decCtx     <- newTVarIO plainDecryptionContext
    decCtxNext <- newTVarIO plainDecryptionContext
    let transport = Transport
            { transportStream                   = stream
            , transportQueue                    = queue
            , transportPacketsSent              = packsSent
            , transportBytesSent                = bytesSent
            , transportPacketsReceived          = packsRcvd
            , transportBytesReceived            = bytesRcvd
            , transportLastRekeyingTime         = rekeyTime
            , transportLastRekeyingDataSent     = rekeySent
            , transportLastRekeyingDataReceived = rekeyRcvd
            , transportEncryptionContext        = encCtx
            , transportEncryptionContextNext    = encCtxNext
            , transportDecryptionContext        = decCtx
            , transportDecryptionContextNext    = decCtxNext
            }
    disconnect <- newEmptyTMVarIO
    withAsync (runSender transport disconnect) $ \thread ->
        link thread >> runWith transport `catch` \e -> do
            -- In case of an exception, the sender thread shall try to
            -- deliver a disconnect message to the client before terminating.
            -- It might happen that the message cannot be sent in time or
            -- the sending itself fails with an exception or the sender thread
            -- is already dead. All cases have been considered and are
            -- handled here: In no case does this procedure take longer than 1 second.
            atomically $ putTMVar disconnect $ fromMaybe
                (Disconnect DisconnectByApplication mempty mempty)
                (fromException e)
            timeout <- (\t -> readTVar t >>= check) <$> registerDelay 1000000
            atomically $ timeout <|> void (waitCatchSTM thread)
            throwIO e
     where
        -- The sender is an infinite loop that waits for messages to be sent
        -- from either the transport or the connection layer.
        -- The sender is also aware of switching the encryption context
        -- when encountering KexNewKeys messages.
        runSender transport disconnect = fix $ \continue -> do
            msg <- atomically $ (MsgDisconnect <$> readTMVar disconnect)
                            <|> readTChan (transportQueue transport)
            onSend config msg
            sendMessageNotThreadSafe transport msg
            case msg of
                -- This thread shall terminate gracefully in case the
                -- message was a disconnect message. By specification
                -- no other messages may follow after a disconnect message.
                MsgDisconnect d -> pure d
                -- A key re-exchange is taken into effect right after
                -- the MsgKexNewKey message.
                MsgKexNewKeys{} -> switchEncryptionContext transport >> continue
                _               -> continue

switchEncryptionContext :: Transport -> IO ()
switchEncryptionContext transport = atomically $ do
    writeTVar (transportEncryptionContext transport)
        =<< readTVar (transportEncryptionContextNext transport)

switchDecryptionContext :: Transport -> IO ()
switchDecryptionContext transport = atomically $ do
    writeTVar (transportDecryptionContext transport)
        =<< readTVar (transportDecryptionContextNext transport)

setChaCha20Poly1305Context :: Transport -> Role -> KeyStreams -> IO ()
setChaCha20Poly1305Context transport role (KeyStreams keys) = atomically $ do
    writeTVar (transportEncryptionContextNext transport) $! case role of
        Server -> chaCha20Poly1305EncryptionContext headerKeySC mainKeySC
        Client -> chaCha20Poly1305EncryptionContext headerKeyCS mainKeyCS
    writeTVar (transportDecryptionContextNext transport) $! case role of
        Server -> chaCha20Poly1305DecryptionContext headerKeyCS mainKeyCS
        Client -> chaCha20Poly1305DecryptionContext headerKeySC mainKeySC
    where
    -- Derive the required encryption/decryption keys.
    -- The integrity keys etc. are not needed with chacha20.
    mainKeyCS : headerKeyCS : _ = keys "C"
    mainKeySC : headerKeySC : _ = keys "D"

sendMessage :: ToMessage msg => Transport -> msg -> IO ()
sendMessage transport msg = do
    atomically $ writeTChan (transportQueue transport) (toMessage msg)

sendMessageNotThreadSafe :: Transport -> Message -> IO ()
sendMessageNotThreadSafe transport@Transport { transportStream = stream } msg = do
    encrypt     <- readTVarIO (transportEncryptionContext transport)
    bytesSent   <- readTVarIO (transportBytesSent transport)
    packetsSent <- readTVarIO (transportPacketsSent transport)
    cipherText  <- encrypt packetsSent plainText
    void $ sendAll stream cipherText
    atomically $ writeTVar (transportBytesSent transport)   $! bytesSent + fromIntegral (BS.length cipherText)
    atomically $ writeTVar (transportPacketsSent transport) $! packetsSent + 1
    where
        plainText = runPut (put msg) :: BS.ByteString

receiveMessage :: Encoding msg => Transport -> IO msg
receiveMessage transport@Transport { transportStream = stream } = do
    packetsReceived <- readTVarIO (transportPacketsReceived transport)
    atomically $ modifyTVar' (transportPacketsReceived transport) (+ 1)
    decrypt   <- readTVarIO (transportDecryptionContext transport)
    plainText <- decrypt packetsReceived receiveAll'
    case runGet get plainText of
        Nothing -> throwIO $ Disconnect DisconnectProtocolError mempty mempty
        Just msg -> pure msg
  where
    receiveAll' i = do
        bs <- receiveAll stream i
        atomically $ modifyTVar' (transportBytesReceived transport)
                                 (+ fromIntegral (BS.length bs))
        pure bs

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
        | BS.null bs = throwException
        | BS.length bs >= 257 = throwException
        | BS.last bs == 10 = case runGet get bs of
            Nothing -> throwException
            Just v  -> pure v
        | otherwise = do
            bs' <- receive stream (255 - BS.length bs)
            if BS.null bs' then throwException else f (bs <> bs')
    throwException =
        throwIO $ Disconnect DisconnectProtocolVersionNotSupported "" ""

sendServerVersion :: (OutputStream stream) => stream -> IO Version
sendServerVersion stream = do
    void $ sendAll stream $ runPut $ put version
    pure version

-- The rekeying watchdog is an inifinite loop that initiates
-- a key re-exchange when either a certain amount of time has passed or
-- when either the input or output stream has exceeded its threshold
-- of bytes sent/received.
askRekeyingRequired :: Config identity -> Transport -> IO Bool
askRekeyingRequired config transport = do
    t <- fromIntegral . sec <$> getTime Monotonic
    atomically $ do
        t0 <- readTVar (transportLastRekeyingTime transport)
        s  <- readTVar (transportBytesSent transport)
        s0 <- readTVar (transportLastRekeyingDataSent transport)
        r  <- readTVar (transportBytesReceived transport)
        r0 <- readTVar (transportLastRekeyingDataReceived transport)
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
    interval  = min (maxTimeBeforeRekey config) 3600
    threshold = min (maxDataBeforeRekey config) (1024 * 1024 * 1024)
    intervalExceeded t t0 = t > t0 && t - t0 > interval
    thresholdExceeded x x0 = x > x0 && x - x0 > threshold

updateRekeyTracking :: Transport -> IO ()
updateRekeyTracking transport = do
    atomically . writeTVar (transportLastRekeyingTime         transport) =<< fromIntegral . sec <$> getTime Monotonic
    atomically $ writeTVar (transportLastRekeyingDataSent     transport) =<< readTVar (transportBytesSent     transport)
    atomically $ writeTVar (transportLastRekeyingDataReceived transport) =<< readTVar (transportBytesReceived transport)

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