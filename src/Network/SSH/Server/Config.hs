{-# LANGUAGE RankNTypes #-}
module Network.SSH.Server.Config where

import           Control.Exception
import qualified Crypto.PubKey.Ed25519  as Ed25519
import qualified Data.ByteString        as BS
import           Data.List.NonEmpty     (NonEmpty)
import           Data.Word
import           System.Exit

import           Network.SSH.Algorithms
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Stream

type Command = BS.ByteString

data Config identity = Config {
      hostKeys                      :: NonEmpty KeyPair
    , keyExchangeAlgorithms         :: NonEmpty KeyExchangeAlgorithm
    , encryptionAlgorithms          :: NonEmpty EncryptionAlgorithm
    , onAuthRequest                 :: UserName -> ServiceName -> PublicKey -> IO (Maybe identity)
    , onShellRequest                :: forall stdin stdout stderr. (DuplexStream stdin, DuplexStream stdout, DuplexStream stderr)
                                    => Maybe (identity -> stdin -> stdout -> stderr -> IO ExitCode)
    , onExecRequest                 :: forall stdin stdout stderr. (DuplexStream stdin, DuplexStream stdout, DuplexStream stderr)
                                    => Maybe (identity -> stdin -> stdout -> stderr -> Command -> IO ExitCode)
    , onSend                        :: Message -> IO ()
    , onReceive                     :: Message -> IO ()
    , onDisconnect                  :: Either SomeException Disconnect -> IO ()
    , channelMaxCount               :: Word16
    , channelMaxWindowSize          :: Word32
    , channelMaxPacketSize          :: Word32
    , maxTimeBeforeRekey            :: Word64
    , maxDataBeforeRekey            :: Word64
    }

newDefaultConfig :: IO (Config identity)
newDefaultConfig = do
    sk <- Ed25519.generateSecretKey
    pure Config {
          hostKeys                      = pure (KeyPairEd25519 (Ed25519.toPublic sk) sk)
        , keyExchangeAlgorithms         = pure Curve25519Sha256AtLibsshDotOrg
        , encryptionAlgorithms          = pure Chacha20Poly1305AtOpensshDotCom
        , onAuthRequest                 = \_ _ _ -> pure Nothing
        , onShellRequest                = Nothing
        , onExecRequest                 = Nothing
        , onSend                        = \_ -> pure ()
        , onReceive                     = \_ -> pure ()
        , onDisconnect                  = \_ -> pure ()
        , channelMaxCount               = 256
        , channelMaxWindowSize          = 256 * 1024
        , channelMaxPacketSize          = 32 * 1024
        , maxTimeBeforeRekey            = 3600
        , maxDataBeforeRekey            = 1024 * 1024 * 1024
        }
