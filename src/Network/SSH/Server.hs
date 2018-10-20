{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase        #-}
module Network.SSH.Server (
    -- * Server
      serve
    , Config (..)
    -- * Authentication Layer
    , UserAuthConfig (..)
    -- * Connection Layer
    , ConnectionConfig (..)
    -- ** session
    , Session (..)
    -- ** direct-tcpip
    , DirectTcpIpRequest (..)
    , Address (..)
    ) where

import           Data.Default

import           Network.SSH.AuthAgent
import           Network.SSH.Exception
import           Network.SSH.Name
import           Network.SSH.Server.Service.Connection
import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Stream
import           Network.SSH.Transport

-- | Serve a single connection represented by a `DuplexStream`.
--
--   (1) The actual server behaviour is only determined by its configuration.
--       The default configuration rejects all authentication and service requests,
--       so you will need to adapt it to your use-case.
--   (2) The `AuthAgent` will be used to authenticate to the client.
--       It is usually sufficient to use a `Network.SSH.KeyPair` as agent.
--   (3) This operation does not return unless the other side either gracefully
--       closes the connection or an error occurs (like connection loss).
--       All expected exceptional conditions get caught and are reflected in the return
--       value.
--   (4) If the connection needs to be terminated by the server, this can be achieved by
--       throwing an asynchronous exception to the executing thread. All depdendant
--       threads and resources will be properly freed and a disconnect message will
--       be delivered to the client (if possible). It is a good idea to run `serve`
--       within an `Control.Concurrent.Async.Async` which can be canceled on demand.
--
-- Example:
--
-- @
-- runServer :: Socket -> IO ()
-- runServer sock = do
--     keyPair <- `Network.SSH.newKeyPair`
--     `serve` conf keyPair sock
--     where
--         conf = `def` { userAuthConfig   = `def` { `onAuthRequest`  = handleAuthRequest }
--                    , connectionConfig = `def` { `onShellRequest` = handleShellRequest }
--                    }
--
-- handleAuthRequest :: `Network.SSH.UserName` -> `Network.SSH.ServiceName` -> `Network.SSH.PublicKey` -> IO (Maybe `Network.SSH.UserName`)
-- handleAuthRequest user service pubkey = case user of
--   "simon" -> pure (Just user)
--   _       -> pure Nothing
--
-- handleDirectTcpIpRequest :: `DuplexStream` stream => `Network.SSH.UserName` -> `DirectTcpIpRequest` -> IO (Maybe (stream -> IO ()))
-- handleDirectTcpIpRequest user req
--     | port (destination req) == 80 = pure $ Just $ \stream -> do
--           bs <- `receive` stream 4096
--           `send` stream "HTTP/1.1 200 OK\\n"
--           send stream "Content-Type: text/plain\\n\\n"
--           send stream "Hello, world!\\n"
--           send stream "\\n"
--           send stream bs
--           pure ()
--     | otherwise = pure Nothing
--
-- handleShellRequest :: `OutputStream` stdout => `Session` `Network.SSH.UserName` -> IO `System.Exit.ExitCode`
-- handleShellRequest (Session user pty env stdin stdout stderr) = do
--     send stdout "Hellow, world!\\n"
--     pure `System.Exit.ExitSuccess`
-- @
serve :: (DuplexStream stream, AuthAgent agent) => Config identity -> agent -> stream -> IO Disconnect
serve config agent stream = run >>= \case
    Left  d  -> pure d
    Right () -> pure $ Disconnect Local DisconnectByApplication mempty
    where
        run =
            withTransport (transportConfig config) (Just agent) stream $ \transport session ->
            withAuthentication (userAuthConfig config) transport session $ \case
                Name "ssh-connection" ->
                    Just $ serveConnection (connectionConfig config) transport
                _ -> Nothing

-- | The server configuration.
--
--   * The type variable `identity` represents the return type of
--     the user authentication process. It may be chosen freely.
--     The identity object will be supplied to all subsequent
--     service handler functions and can be used as connection state.
data Config identity
    = Config
        { transportConfig  :: TransportConfig
        , userAuthConfig   :: UserAuthConfig identity
        , connectionConfig :: ConnectionConfig identity
        }

instance Default (Config identity) where
    def = Config
        { transportConfig  = def
        , userAuthConfig   = def
        , connectionConfig = def
        }