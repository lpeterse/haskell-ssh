module Network.SSH.Server.Config where

import           Control.Monad.Terminal
import qualified Crypto.PubKey.Ed25519  as Ed25519
import           System.Exit

import           Network.SSH.Key
import           Network.SSH.Message

data Config = Config {
      hostKey        :: PrivateKey
    , onShellRequest :: Maybe (Terminal -> IO ExitCode)
    }

newDefaultConfig :: IO Config
newDefaultConfig = do
    sk <- Ed25519.generateSecretKey
    pure Config {
          hostKey        = Ed25519PrivateKey (Ed25519.toPublic sk) sk
        , onShellRequest = Nothing
        }
