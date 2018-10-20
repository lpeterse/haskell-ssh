{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase        #-}
module Network.SSH.Server (
    serve
    , Config (..)
    , TransportConfig (..)
    , UserAuthConfig (..)
    , ConnectionConfig (..)
    , Session (..)
    , DirectTcpIpRequest (..)
    , Address (..)
    ) where

import           Network.SSH.AuthAgent
import           Network.SSH.Exception
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Service.Connection
import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Stream (DuplexStream ())
import           Network.SSH.Transport

serve :: (DuplexStream stream, AuthAgent agent) => Config identity -> agent -> stream -> IO Disconnect
serve config agent stream = run >>= \case
    Left  d  -> pure d
    Right () -> pure $ Disconnect Local DisconnectByApplication mempty
    where
        run =
            withTransport (transportConfig config) (Just agent) stream $ \transport session ->
            withAuthentication (userAuthConfig config) transport session $ \case
                ServiceName "ssh-connection" ->
                    Just $ serveConnection (connectionConfig config) transport
                _ -> Nothing
