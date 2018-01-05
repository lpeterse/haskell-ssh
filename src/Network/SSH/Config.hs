module Network.SSH.Config where

import           Control.Monad.STM
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ByteString       as BS
import           System.Exit

data ServerConfig
  = ServerConfig
  { scHostKey  :: Ed25519.SecretKey
  , scRunShell :: Maybe (STM BS.ByteString -> (BS.ByteString -> STM ()) -> (BS.ByteString -> STM ()) -> IO ExitCode)
  }
