module Network.SSH.Server.Config where

import           Control.Monad.Terminal
import qualified Crypto.PubKey.Ed25519  as Ed25519
import           System.Exit

import           Network.SSH.Key
import           Network.SSH.Message

data Config identity = Config {
      hostKey        :: PrivateKey
    , onAuthRequest  :: UserName -> ServiceName -> PublicKey -> IO (Maybe identity)
    , onShellRequest :: Maybe (identity -> Terminal -> IO ExitCode)
    }

newDefaultConfig :: IO (Config identity)
newDefaultConfig = do
    sk <- Ed25519.generateSecretKey
    pure Config {
          hostKey        = Ed25519PrivateKey (Ed25519.toPublic sk) sk
        , onAuthRequest  = \_ _ _ -> pure Nothing
        , onShellRequest = Nothing
        }
