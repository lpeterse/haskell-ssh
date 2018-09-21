{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.Service where

import Control.Exception (throwIO)

import           Network.SSH.Message
import           Network.SSH.Server.Types

handleServiceRequest :: Connection identity -> ServiceRequest -> IO ()
handleServiceRequest connection (ServiceRequest (ServiceName srv)) = case srv of
    "ssh-userauth"   -> accept
    "ssh-connection" -> accept
    _                -> reject
    where
        accept = connOutput connection $ MsgServiceAccept (ServiceAccept (ServiceName srv))
        reject = throwIO $ Disconnect DisconnectServiceNotAvailable mempty mempty