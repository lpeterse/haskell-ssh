{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase        #-}
module Network.SSH.Server ( serve ) where

import           Network.SSH.AuthAgent
import           Network.SSH.Exception
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Service.Connection
import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Stream (DuplexStreamPeekable ())
import           Network.SSH.Transport

serve :: (DuplexStreamPeekable stream) => Config identity -> AuthAgent -> stream -> IO Disconnect
serve config agent stream = run >>= \case
    Left  d  -> pure d
    Right () -> pure $ Disconnect Local DisconnectByApplication mempty
    where
        run =
            withTransport (transportConfig config) (Just agent) stream $ \transport session ->
            withAuthentication config transport session $ \case
                ServiceName "ssh-connection" ->
                    Just $ runConnection config transport
                _ -> Nothing
