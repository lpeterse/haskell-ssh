{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.Service where

import           Control.Monad.STM

import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport
import           Network.SSH.Server.Types

handleServiceRequest :: Connection identity -> ServiceRequest -> IO ()
handleServiceRequest connection (ServiceRequest (ServiceName srv)) = atomically $ case srv of
    "ssh-userauth"   -> accept
    "ssh-connection" -> accept
    _                -> reject
    where
        accept = send connection $ MsgServiceAccept (ServiceAccept (ServiceName srv))
        reject = connection `disconnectWith` DisconnectServiceNotAvailable
