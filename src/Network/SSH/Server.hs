{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase        #-}
module Network.SSH.Server ( serve ) where

import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Transport
import           Network.SSH.Message
import           Network.SSH.Stream (DuplexStreamPeekable ())
import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Server.Service.Connection

serve :: (DuplexStreamPeekable stream) => Config identity -> stream -> IO Disconnected
serve config stream = run >>= \case
    Left  d  -> pure d
    Right () -> pure $ Disconnected $ Disconnect DisconnectByApplication mempty mempty
    where
        run = withTransport transportConfig stream $ \transport session -> do
                withAuthentication config transport session $ \case
                    ServiceName "ssh-connection" ->
                        Just $ runConnection config transport
                    _ -> Nothing
        transportConfig = TransportServerConfig
            { tHostKeys          = hostKeys config
            , tKexAlgorithms     = keyExchangeAlgorithms config
            , tEncAlgorithms     = encryptionAlgorithms config
            , tOnSend            = onSend config
            , tOnReceive         = onReceive config
            }
