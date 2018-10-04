{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase        #-}
module Network.SSH.Server ( serve ) where

import           Control.Exception (throwIO, catch)

import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Transport
import           Network.SSH.Stream (DuplexStreamPeekable ())
import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Server.Service.Connection

serve :: (DuplexStreamPeekable stream) => Config identity -> stream -> IO ()
serve config stream = withDisconnectHandler config $
    withTransport transportConfig stream $ \transport session -> do
        withAuthentication config transport session $ \case
            ServiceName "ssh-connection" ->
                Just $ runConnection config transport
            _ -> Nothing
        error "FIXME"
    where
        transportConfig = TransportServerConfig
            { tHostKeys          = hostKeys config
            , tKexAlgorithms     = keyExchangeAlgorithms config
            , tEncAlgorithms     = encryptionAlgorithms config
            , tOnSend            = onSend config
            , tOnReceive         = onReceive config
            }

withDisconnectHandler :: Config identity -> IO Disconnect -> IO ()
withDisconnectHandler config run = action `catch` handler
  where
    action = run >>= (onDisconnect config . Right)
    handler e = onDisconnect config (Left e) >> throwIO e
