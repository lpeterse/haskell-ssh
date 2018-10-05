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

errorInvalidTransition :: IO a
errorInvalidTransition = throwIO $
    Disconnect DisconnectKeyExchangeFailed "invalid transition" mempty

errorInvalidSignature :: IO a
errorInvalidSignature = throwIO $
    Disconnect DisconnectKeyExchangeFailed "invalid signature" mempty

exceptionKexNoSignature :: Disconnect
exceptionKexNoSignature =
    Disconnect DisconnectKeyExchangeFailed "no signature" mempty

throwProtocolError :: BS.ByteString -> IO a
throwProtocolError e = throwIO $ Disconnect DisconnectProtocolError e mempty
