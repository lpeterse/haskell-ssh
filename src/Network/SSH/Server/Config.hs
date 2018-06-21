{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
module Network.SSH.Server.Config where

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
import           Data.Function                (fix)
import           Data.Stream
import           Data.Word
import           System.Exit

import           Network.SSH.Key
import           Network.SSH.Message

type Command = BS.ByteString

data Config identity = Config {
      hostKey              :: PrivateKey
    , onAuthRequest        :: UserName -> ServiceName -> PublicKey -> IO (Maybe identity)
    , onExecRequest        :: forall stdin stdout stderr. (DuplexStream stdin, DuplexStream stdout, DuplexStream stderr)
                           => Maybe (identity -> stdin -> stdout -> stderr -> Command -> IO ExitCode)
    , onDisconnect         :: Disconnect -> IO ()
    , transportBufferSize  :: Word16
    , channelMaxCount      :: Word16
    , channelMaxWindowSize :: Word32
    , channelMaxPacketSize :: Word32
    }

newDefaultConfig :: IO (Config identity)
newDefaultConfig = do
    sk <- Ed25519.generateSecretKey
    pure Config {
          hostKey              = Ed25519PrivateKey (Ed25519.toPublic sk) sk
        , onAuthRequest        = \_ _ _ -> pure Nothing
        , onExecRequest        = Nothing
        , onDisconnect         = \_ -> pure ()
        , transportBufferSize  = 4096
        , channelMaxCount      = 256
        , channelMaxWindowSize = 256 * 1024
        , channelMaxPacketSize = 32 * 1024
        }
