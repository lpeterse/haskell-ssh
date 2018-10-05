{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase        #-}
module Network.SSH.Server ( serve ) where

import           Network.SSH.Algorithms
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Service.Connection
import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Stream (DuplexStreamPeekable ())
import           Network.SSH.Transport

serve :: (DuplexStreamPeekable stream) => Config identity -> stream -> IO Disconnected
serve config stream = newTransportConfig >>= run >>= \case
    Left  d  -> pure d
    Right () -> pure $ Disconnected $ Disconnect DisconnectByApplication mempty mempty
    where
        run c = withTransport c stream $ \transport session -> do
                withAuthentication config transport session $ \case
                    ServiceName "ssh-connection" ->
                        Just $ runConnection config transport
                    _ -> Nothing
        newTransportConfig = pure TransportConfig
            { tAuthAgent          = Just $ authAgent config
            , tHostKeyAlgorithms  = pure SshEd25519
            , tKexAlgorithms      = keyExchangeAlgorithms config
            , tEncAlgorithms      = encryptionAlgorithms config
            , tMaxTimeBeforeRekey = maxTimeBeforeRekey config
            , tMaxDataBeforeRekey = maxDataBeforeRekey config
            , tOnSend             = onSend config
            , tOnReceive          = onReceive config
            }
