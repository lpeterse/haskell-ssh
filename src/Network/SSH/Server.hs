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

import           Data.Default

import           Network.SSH.AuthAgent
import           Network.SSH.Exception
import           Network.SSH.Name
import           Network.SSH.Server.Service.Connection
import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Stream (DuplexStream ())
import           Network.SSH.Transport

data Config identity
    = Config
      { transportConfig    :: TransportConfig
      , userAuthConfig     :: UserAuthConfig identity
      , connectionConfig   :: ConnectionConfig identity
      }

instance Default (Config identity) where
    def = Config
        { transportConfig  = def
        , userAuthConfig   = def
        , connectionConfig = def
        }

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
