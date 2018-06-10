{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
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
import           Control.Monad.Terminal
import qualified Crypto.PubKey.Ed25519        as Ed25519
import qualified Data.ByteArray               as BA
import qualified Data.ByteString              as BS
import qualified Data.Count                   as Count
import           Data.Function                (fix)
import qualified Data.Map.Strict              as M
import           Data.Maybe
import           Data.Stream
import           Data.Typeable
import           Data.Word
import           System.Exit

import           Network.SSH.Key
import           Network.SSH.Message
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
    , chanMaxPacketSizeRemote :: Count.Count Word8
    , chanWindowSizeLocal     :: TVar (Count.Count Word8)
    , chanWindowSizeRemote    :: TVar (Count.Count Word8)
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

data Config identity = Config {
    hostKey                :: PrivateKey
    , onAuthRequest        :: UserName -> ServiceName -> PublicKey -> IO (Maybe identity)
    , onExecRequest        :: forall stdin stdout stderr command. (BA.ByteArrayAccess command, DuplexStream stdin, DuplexStream stdout, DuplexStream stderr)
                            => Maybe (identity -> stdin -> stdout -> stderr -> command -> IO ExitCode)
    , channelMaxCount      :: Count.Count (Channel identity)
    , channelMaxWindowSize :: Count.Count Word8
    , channelMaxPacketSize :: Count.Count Word8
    }

newDefaultConfig :: IO (Config identity)
newDefaultConfig = do
    sk <- Ed25519.generateSecretKey
    pure Config {
        hostKey              = Ed25519PrivateKey (Ed25519.toPublic sk) sk
        , onAuthRequest        = \_ _ _ -> pure Nothing
        , onExecRequest        = Nothing
        , channelMaxCount      = Count.Count 256
        , channelMaxWindowSize = Count.Count $ 256 * 1024
        , channelMaxPacketSize = Count.Count $ 32 * 1024
        }
