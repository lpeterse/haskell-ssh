{-# LANGUAGE ExistentialQuantification, OverloadedStrings, MultiWayIf #-}
module Network.SSH.Server.Transport
    ( Transport()
    , withTransport
    , sendMessage
    , receiveMessage
    , switchEncryptionContext
    , switchDecryptionContext
    , sendServerVersion
    , receiveClientVersion
    , askRekeyingRequired
    )
where

import           Control.Concurrent.STM.TVar
import           Control.Monad.STM              ( atomically )
import           Control.Monad                  ( void )
import qualified Data.ByteString               as BS
import           System.Clock
import           Control.Exception              ( throwIO )

import           Network.SSH.Encoding
import           Network.SSH.Stream
import           Network.SSH.Message
import           Network.SSH.Constants
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport.Internal
import           Network.SSH.Server.Transport.Encryption

withTransport :: DuplexStream stream => stream -> (Transport -> IO a) -> IO a
withTransport stream runWith = do
    transport <-
        Transport stream
        <$> newTVarIO 0
        <*> newTVarIO 0
        <*> newTVarIO 0
        <*> newTVarIO 0
        <*> (newTVarIO =<< fromIntegral . sec <$> getTime Monotonic)
        <*> newTVarIO 0
        <*> newTVarIO 0
        <*> newTVarIO plainEncryptionContext
        <*> newTVarIO plainEncryptionContext
        <*> newTVarIO plainDecryptionContext
        <*> newTVarIO plainDecryptionContext
    runWith transport

switchEncryptionContext :: Transport -> IO ()
switchEncryptionContext transport = atomically $ do
    writeTVar (transportEncryptionContext transport)
        =<< readTVar (transportEncryptionContextNext transport)

switchDecryptionContext :: Transport -> IO ()
switchDecryptionContext transport = atomically $ do
    writeTVar (transportDecryptionContext transport)
        =<< readTVar (transportDecryptionContextNext transport)

sendMessage :: (Show msg, Encoding msg) => Transport -> msg -> IO ()
sendMessage transport@Transport { transportStream = stream } msg = do
    let plainText = runPut (put msg) :: BS.ByteString
    encrypt     <- readTVarIO (transportEncryptionContext transport)
    bytesSent   <- readTVarIO (transportBytesSent transport)
    packetsSent <- readTVarIO (transportPacketsSent transport)
    cipherText  <- encrypt packetsSent plainText
    void $ sendAll stream cipherText
    atomically $ writeTVar (transportBytesSent transport)   $! bytesSent + fromIntegral (BS.length cipherText)
    atomically $ writeTVar (transportPacketsSent transport) $! packetsSent + 1

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
