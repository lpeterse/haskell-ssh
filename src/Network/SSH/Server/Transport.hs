{-# LANGUAGE OverloadedStrings, ExistentialQuantification #-}
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

data TransportState
    = forall stream. DuplexStream stream => TransportState
    {   transportStream                   :: stream
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

withTransportState :: DuplexStream stream => stream -> (TransportState -> IO a) -> IO a
withTransportState stream with = do
    s <- newEmptyMVar
    r <- newEmptyMVar
    state <- TransportState stream
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
    with state

sendPlain :: (Encoding msg) => TransportState -> msg -> IO ()
sendPlain state@TransportState { transportStream = s } msg = do
    sent <- sendAll s $ runPut $ putPacked msg
    modifyMVar_ (transportBytesSent state) (\i-> pure $! i + fromIntegral sent)
    modifyMVar_ (transportPacketsSent state) (\i-> pure $! i + 1)

receivePlain :: (Encoding msg) => TransportState -> IO msg
receivePlain state@TransportState { transportStream = s } = do
    paclen <- runGet getWord32 =<< receiveAll s 4
    when (paclen > maxPacketLength) $
        throwIO $ Disconnect DisconnectProtocolError "max packet length exceeded" ""
    msg <- runGet (skip 1 >> get) =<< receiveAll s (fromIntegral paclen)
    modifyMVar_ (transportBytesReceived state) (\i-> pure $! i + 4 + fromIntegral paclen)
    modifyMVar_ (transportPacketsReceived state) (\i-> pure $! i + 1)
    pure msg

send :: Connection identity -> Message -> STM ()
send connection =
    writeTChan (connOutput connection)

disconnectWith :: Connection identity -> DisconnectReason -> STM ()
disconnectWith connection reason =
    putTMVar (connDisconnected connection) (Disconnect reason mempty mempty) `orElse` pure ()
