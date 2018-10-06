{-# LANGUAGE ExistentialQuantification #-}
module Network.SSH.Server.Config where

import qualified Data.ByteString        as BS
import           Data.List.NonEmpty     (NonEmpty)
import           Data.Word
import qualified Data.Map.Strict        as M
import           System.Exit

import           Network.SSH.Algorithms
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Stream
import           Network.SSH.Transport

type Command = BS.ByteString

data Config identity
    = Config
      { transportConfig               :: TransportConfig
      , userAuthConfig                :: UserAuthConfig identity
      , connectionConfig              :: ConnectionConfig identity
      }

data UserAuthConfig identity
    = UserAuthConfig
      { onAuthRequest                 :: UserName -> ServiceName -> PublicKey -> IO (Maybe identity)
      }

data ConnectionConfig identity
    = ConnectionConfig
      { onShellRequest                :: Maybe (Session identity -> IO ExitCode)
      , onExecRequest                 :: Maybe (Session identity -> Command -> IO ExitCode)
      , channelMaxCount               :: Word16
      , channelMaxQueueSize           :: Word32
      , channelMaxPacketSize          :: Word32
      }

data Session identity
    = forall stdin stdout stderr. (InputStream stdin, OutputStream stdout, OutputStream stderr) => Session
      { identity    :: identity
      , environment :: M.Map BS.ByteString BS.ByteString
      , ptySettings :: Maybe PtySettings
      , stdin       :: stdin
      , stdout      :: stdout
      , stderr      :: stderr
      }

defaultConfig :: Config identity
defaultConfig = Config
    { transportConfig               = defaultTransportConfig
    , userAuthConfig                = defaultUserAuthConfig
    , connectionConfig              = defaultConnectionConfig
    }

defaultUserAuthConfig :: UserAuthConfig identity
defaultUserAuthConfig = UserAuthConfig
    { onAuthRequest                 = \_ _ _ -> pure Nothing
    }

defaultConnectionConfig :: ConnectionConfig identity
defaultConnectionConfig = ConnectionConfig
    { onShellRequest                = Nothing
    , onExecRequest                 = Nothing
    , channelMaxCount               = 256
    , channelMaxQueueSize           = 256 * 1024
    , channelMaxPacketSize          = 32 * 1024
    }