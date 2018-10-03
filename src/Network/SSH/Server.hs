{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server ( serve ) where

import           Control.Exception (throwIO, catch)

import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Transport
import           Network.SSH.Stream (DuplexStream ())
import qualified Network.SSH.Server.Service.UserAuth as U
import qualified Network.SSH.Server.Service.Connection as C

serve :: (DuplexStream stream) => Config identity -> stream -> IO ()
serve config stream = withDisconnectHandler config $
    withTransport transportConfig stream $ \transport session ->
        U.withUserAuth config transport session $ \identity -> do
            C.runConnection config transport identity
            error "FIXME"
    where
        transportConfig = TransportServerConfig
            { tHostKeys          = hostKeys config
            , tKexAlgorithms     = keyExchangeAlgorithms config
            , tEncAlgorithms     = encryptionAlgorithms config
            }

withDisconnectHandler :: Config identity -> IO Disconnect -> IO ()
withDisconnectHandler config run = action `catch` handler
  where
    action = run >>= (onDisconnect config . Right)
    handler e = onDisconnect config (Left e) >> throwIO e
