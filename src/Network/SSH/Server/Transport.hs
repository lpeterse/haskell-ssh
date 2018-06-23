module Network.SSH.Server.Transport where

import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Exception            (throwIO)
import           Control.Monad                (forever, unless, when)
import           Control.Monad.STM            (STM, atomically, orElse)
import qualified Data.ByteString              as BS
import           Data.Word

import           Network.SSH.Constants
import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Message
import           Network.SSH.Server.Types
import           Network.SSH.Stream

data TransportState stream
    = TransportState
    {   transportStream                      :: stream
    ,   transportClientVersion               :: Version
    ,   transportServerVersion               :: Version
    ,   transportPacketsReceived             :: MVar Word64
    ,   transportBytesReceived               :: MVar Word64
    ,   transportBytesReceivedOnLastRekeying :: MVar Word64
    ,   transportPacketsSent                 :: MVar Word64
    ,   transportBytesSent                   :: MVar Word64
    ,   transportBytesSentOnLastRekeying     :: MVar Word64
    ,   transportSender                      :: MVar (BS.ByteString -> IO ())
    ,   transportReceiver                    :: MVar (IO BS.ByteString)
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
    len <- runGet getWord32 =<< receiveAll stream 4
    when (len > maxPacketLength) $
        throwIO SshMaxPacketLengthExceededException
    msg <- runGet (skip 1 >> get) =<< receiveAll stream (fromIntegral len)
    modifyMVar_ (transportBytesReceived state) (\i-> pure $! i + 4 + fromIntegral len)
    modifyMVar_ (transportPacketsReceived state) (\i-> pure $! i + 1)
    pure msg

send :: Connection identity -> Message -> STM ()
send connection =
    writeTChan (connOutput connection)

disconnectWith :: Connection identity -> DisconnectReason -> STM ()
disconnectWith connection reason =
    putTMVar (connDisconnected connection) (Disconnect reason mempty mempty) `orElse` pure ()
