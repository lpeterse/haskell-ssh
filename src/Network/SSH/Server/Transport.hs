module Network.SSH.Server.Transport where

import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Monad                (forever, unless, when)
import           Control.Monad.STM

import           Network.SSH.Message
import           Network.SSH.Server.Types

send :: Connection identity -> Message -> STM ()
send connection =
    writeTChan (connOutput connection)

disconnectWith :: Connection identity -> DisconnectReason -> STM ()
disconnectWith connection reason =
    putTMVar (connDisconnected connection) (Disconnect reason mempty mempty) `orElse` pure ()
