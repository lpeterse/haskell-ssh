{-# LANGUAGE RankNTypes #-}
module Network.SSH.Server.Service.Connection.Internal where

import           Control.Concurrent           (ThreadId)
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Monad.STM
import qualified Data.ByteString              as BS
import qualified Data.Map.Strict              as M
import           Data.Word

import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.TAccountingQueue

data Connection identity
    = Connection
    { connConfig       :: Config identity
    , connIdentity     :: TVar identity
    , connChannels     :: TVar (M.Map ChannelId (Channel identity))
    , connOutput       :: Message -> IO ()
    , connTerminated   :: TVar Bool
    }

terminate :: Connection identity -> IO ()
terminate connection = atomically $ writeTVar (connTerminated connection) True

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
    , sessTerminal    :: TVar (Maybe ())
    , sessThread      :: TVar (Maybe ThreadId)
    , sessStdin       :: TAccountingQueue
    , sessStdout      :: TAccountingQueue
    , sessStderr      :: TAccountingQueue
    }
