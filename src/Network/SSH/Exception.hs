{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Exception where

import Network.SSH.Message

exceptionProtocolVersionNotSupported :: Disconnect
exceptionProtocolVersionNotSupported =
    Disconnect DisconnectProtocolVersionNotSupported mempty mempty

exceptionConnectionLost :: Disconnect
exceptionConnectionLost =
    Disconnect DisconnectConnectionLost mempty mempty