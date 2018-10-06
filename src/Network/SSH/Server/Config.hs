{-# LANGUAGE ExistentialQuantification #-}
module Network.SSH.Server.Config where

import qualified Crypto.PubKey.Ed25519  as Ed25519
import qualified Data.ByteString        as BS
import           Data.List.NonEmpty     (NonEmpty)
import           Data.Word
import qualified Data.Map.Strict        as M
import           System.Exit

import           Network.SSH.Algorithms
import           Network.SSH.AuthAgent
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Stream
import           Network.SSH.Transport

type Command = BS.ByteString

data Config identity
    = Config
      { keyExchangeAlgorithms         :: NonEmpty KeyExchangeAlgorithm
      , encryptionAlgorithms          :: NonEmpty EncryptionAlgorithm
      , onAuthRequest                 :: UserName -> ServiceName -> PublicKey -> IO (Maybe identity)
      , onShellRequest                :: Maybe (Session identity -> IO ExitCode)
      , onExecRequest                 :: Maybe (Session identity -> Command -> IO ExitCode)
      , transportConfig               :: TransportConfig
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

newDefaultConfig :: IO (Config identity)
newDefaultConfig = do
    sk <- Ed25519.generateSecretKey
    pure Config {
          keyExchangeAlgorithms         = pure Curve25519Sha256AtLibsshDotOrg
        , encryptionAlgorithms          = pure Chacha20Poly1305AtOpensshDotCom
        , onAuthRequest                 = \_ _ _ -> pure Nothing
        , onShellRequest                = Nothing
        , onExecRequest                 = Nothing
        , channelMaxCount               = 256
        , channelMaxQueueSize           = 256 * 1024
        , channelMaxPacketSize          = 32 * 1024
        , transportConfig               = defaultTransportConfig
        }
