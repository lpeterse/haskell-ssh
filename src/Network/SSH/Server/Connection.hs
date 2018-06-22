module Network.SSH.Server.Connection
    ( Connection ()
    , withConnection
    , pushMessage
    , pullMessage
    , pullMessageSTM
    ) where

import           Control.Applicative
import           Control.Concurrent
import           Control.Concurrent.Async
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Concurrent.STM.TVar
import           Control.Exception
import           Control.Monad                (forever, unless, when)
import           Control.Monad.STM
import qualified Data.ByteString              as BS
import           Data.Function                (fix)
import qualified Data.Map.Strict              as M
import           Data.Maybe
import           Data.Text                    as T
import           Data.Text.Encoding           as T
import           Data.Typeable
import           System.Exit

import           Network.SSH.Constants
import           Network.SSH.Exception
import           Network.SSH.Message
import qualified Network.SSH.Server.Channel   as Channel
import           Network.SSH.Server.Config
import qualified Network.SSH.Server.Service   as Service
import           Network.SSH.Server.Types
import qualified Network.SSH.Server.UserAuth  as UserAuth

withConnection :: Config identity -> SessionId -> (Connection identity -> IO ()) -> IO ()
withConnection cfg sid = bracket before after
    where
        before = Connection
            <$> pure cfg
            <*> pure sid
            <*> newTVarIO Nothing
            <*> newTVarIO mempty
            <*> newTChanIO
            <*> newTChanIO
            <*> newEmptyTMVarIO
        after connection = do
            pure ()

pullMessage :: Connection identity -> IO Message
pullMessage connection = atomically $ pullMessageSTM connection

pullMessageSTM :: Connection identity -> STM Message
pullMessageSTM connection = disconnectMessage <|> nextMessage
    where
        disconnectMessage = MsgDisconnect <$> readTMVar (connDisconnected connection)
        nextMessage = readTChan (connOutput connection)

-- Calling this operation will store a disconnect message
-- in the connection state. Afterwards, any attempts to read outgoing
-- messages from the connection shall yield this message and
-- the reader must close the connection after sending
-- the disconnect message.
disconnectWith :: Connection identity -> DisconnectReason -> IO ()
disconnectWith connection reason =
    atomically $ putTMVar (connDisconnected connection) (Disconnect reason mempty mempty) <|> pure ()

pushMessage :: Connection identity -> Message -> IO ()
pushMessage connection msg = do
  print msg
  case msg of
    MsgIgnore {}                  -> pure ()

    MsgServiceRequest x           -> Service.handleServiceRequest      connection x

    MsgUserAuthRequest x          -> UserAuth.handleUserAuthRequest    connection x

    MsgChannelOpen x              -> Channel.handleChannelOpen         connection x
    MsgChannelClose x             -> Channel.handleChannelClose        connection x
    MsgChannelEof x               -> Channel.handleChannelEof          connection x
    MsgChannelRequest x           -> Channel.handleChannelRequest      connection x
    MsgChannelWindowAdjust x      -> Channel.handleChannelWindowAdjust connection x
    MsgChannelData x              -> Channel.handleChannelData         connection x
    MsgChannelExtendedData x      -> Channel.handleChannelExtendedData connection x

    _                             -> connection `disconnectWith` DisconnectProtocolError
