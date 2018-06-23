{-# LANGUAGE RankNTypes #-}
module Network.SSH.Server.Types where

import           Control.Concurrent           (ThreadId)
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Concurrent.STM.TVar
import           Control.Monad.Terminal
import qualified Data.ByteString              as BS
import qualified Data.Map.Strict              as M
import           Data.Word
import           System.Exit

import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Stream
import           Network.SSH.TAccountingQueue

data Connection identity
    = Connection
    { connConfig       :: Config identity
    , connSessionId    :: SessionId
    , connIdentity     :: TVar (Maybe identity)
    , connChannels     :: TVar (M.Map ChannelId (Channel identity))
    , connLogs         :: TChan String
    , connOutput       :: TChan Message
    , connDisconnected :: TMVar Disconnect
    }

data Channel identity
    = Channel
    { chanConnection          :: Connection identity
    , chanApplication         :: ChannelApplication
    , chanIdLocal             :: ChannelId
    , chanIdRemote            :: ChannelId
    , chanMaxPacketSizeRemote :: Word32
    , chanWindowSizeLocal     :: TVar Word32
    , chanWindowSizeRemote    :: TVar Word32
    , chanClosed              :: TVar Bool
    }

data ChannelApplication
    = ChannelApplicationSession Session

data Session
    = Session
    { sessEnvironment :: TVar (M.Map BS.ByteString BS.ByteString)
    , sessTerminal    :: TVar (Maybe Terminal)
    , sessThread      :: TVar (Maybe ThreadId)
    , sessStdin       :: TAccountingQueue
    , sessStdout      :: TAccountingQueue
    , sessStderr      :: TAccountingQueue
    }


