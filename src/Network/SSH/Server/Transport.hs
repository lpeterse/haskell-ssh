{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.Transport where

import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Exception            (throwIO)
import           Control.Monad                (when)
import           Control.Monad.STM            (STM, orElse)
import qualified Data.ByteString              as BS
import           Data.Word
import           System.Clock

import           Network.SSH.Constants
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Server.Types
import           Network.SSH.Stream

data TransportState stream
    = TransportState
    {   transportStream                   :: stream
    ,   transportClientVersion            :: Version
    ,   transportServerVersion            :: Version
    ,   transportPacketsReceived          :: MVar Word64
    ,   transportBytesReceived            :: MVar Word64
    ,   transportPacketsSent              :: MVar Word64
    ,   transportBytesSent                :: MVar Word64
    ,   transportLastRekeyingTime         :: MVar Word64
    ,   transportLastRekeyingDataSent     :: MVar Word64
    ,   transportLastRekeyingDataReceived :: MVar Word64
    ,   transportSender                   :: MVar (BS.ByteString -> IO ())
    ,   transportReceiver                 :: MVar (IO BS.ByteString)
    }

newTransportState :: DuplexStream stream => stream -> Version -> Version -> IO (TransportState stream)
newTransportState stream clientVersion serverVersion = do
    s <- newEmptyMVar
    r <- newEmptyMVar
    state <- TransportState stream clientVersion serverVersion
        <$> newMVar 0
        <*> newMVar 0
        <*> newMVar 0
        <*> newMVar 0
        <*> (newMVar =<< fromIntegral . sec <$> getTime Monotonic)
        <*> newMVar 0
        <*> newMVar 0
        <*> pure s
        <*> pure r
    putMVar s (sendPlain state)
    putMVar r (receivePlain state)
    pure state

sendPlain :: (OutputStream stream, Encoding msg) => TransportState stream -> msg -> IO ()
sendPlain state msg = do
    sent <- sendAll (transportStream state) $ runPut $ putPacked msg
    modifyMVar_ (transportBytesSent state) (\i-> pure $! i + fromIntegral sent)
    modifyMVar_ (transportPacketsSent state) (\i-> pure $! i + 1)

receivePlain :: (InputStream stream, Encoding msg) => TransportState stream -> IO msg
receivePlain state = do
    let stream = transportStream state
    paclen <- runGet getWord32 =<< receiveAll stream 4
    when (paclen > maxPacketLength) $
        throwIO $ Disconnect DisconnectProtocolError "max packet length exceeded" ""
    msg <- runGet (skip 1 >> get) =<< receiveAll stream (fromIntegral paclen)
    modifyMVar_ (transportBytesReceived state) (\i-> pure $! i + 4 + fromIntegral paclen)
    modifyMVar_ (transportPacketsReceived state) (\i-> pure $! i + 1)
    pure msg

send :: Connection identity -> Message -> STM ()
send connection =
    writeTChan (connOutput connection)

disconnectWith :: Connection identity -> DisconnectReason -> STM ()
disconnectWith connection reason =
    putTMVar (connDisconnected connection) (Disconnect reason mempty mempty) `orElse` pure ()
