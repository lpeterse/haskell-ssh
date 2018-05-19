{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.Types where

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

import           Network.SSH.Message
import           Network.SSH.Server.Config

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
    , chanType                :: ChannelType
    , chanIdLocal             :: ChannelId
    , chanIdRemote            :: ChannelId
    , chanMaxPacketSizeLocal  :: ChannelPacketSize
    , chanMaxPacketSizeRemote :: ChannelPacketSize
    , chanWindowSizeLocal     :: TVar ChannelWindowSize
    , chanWindowSizeRemote    :: TVar ChannelWindowSize
    , chanClosed              :: TVar Bool
    }
