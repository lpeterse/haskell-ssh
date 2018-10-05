{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Exception where

import qualified Data.ByteString               as BS
import           Control.Exception              (throwIO)

import Network.SSH.Message

exceptionProtocolVersionNotSupported :: Disconnect
exceptionProtocolVersionNotSupported =
    Disconnect DisconnectProtocolVersionNotSupported mempty mempty

exceptionConnectionLost :: Disconnect
exceptionConnectionLost =
    Disconnect DisconnectConnectionLost mempty mempty

exceptionKexInvalidTransition :: Disconnect
exceptionKexInvalidTransition =
    Disconnect DisconnectKeyExchangeFailed "invalid transition" mempty

exceptionKexInvalidSignature :: Disconnect
exceptionKexInvalidSignature =
    Disconnect DisconnectKeyExchangeFailed "invalid signature" mempty

exceptionKexNoSignature :: Disconnect
exceptionKexNoSignature =
    Disconnect DisconnectKeyExchangeFailed "no signature" mempty

exceptionMacError :: Disconnect
exceptionMacError =
    Disconnect DisconnectMacError mempty mempty

exceptionInvalidPacket :: Disconnect
exceptionInvalidPacket =
    Disconnect DisconnectProtocolError "invalid packet" mempty

throwProtocolError :: BS.ByteString -> IO a
throwProtocolError e = throwIO $ Disconnect DisconnectProtocolError e mempty
