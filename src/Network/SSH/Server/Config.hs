{-# LANGUAGE RankNTypes #-}
module Network.SSH.Server.Config where

import           Control.Monad.Terminal
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Data.ByteArray           as BA
import           System.Exit

import           Network.SSH.DuplexStream
import           Network.SSH.Key
import           Network.SSH.Message

data Config identity = Config {
      hostKey         :: PrivateKey
    , onAuthRequest   :: UserName -> ServiceName -> PublicKey -> IO (Maybe identity)
    , onExecRequest   :: forall stdin stdout stderr command. (BA.ByteArrayAccess command, DuplexStream stdin, DuplexStream stdout, DuplexStream stderr)
                      => Maybe (identity -> stdin -> stdout -> stderr -> command -> IO ExitCode)
    , channelMaxCount :: Int
    }

newDefaultConfig :: IO (Config identity)
newDefaultConfig = do
    sk <- Ed25519.generateSecretKey
    pure Config {
          hostKey         = Ed25519PrivateKey (Ed25519.toPublic sk) sk
        , onAuthRequest   = \_ _ _ -> pure Nothing
        , onExecRequest   = Nothing
        , channelMaxCount = 256
        }
