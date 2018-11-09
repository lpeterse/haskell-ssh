{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.SSH.Exception where

import           Control.Exception              ( Exception )
import qualified Data.ByteString               as BS
import           Data.String
import           Data.Word

data Disconnect = Disconnect DisconnectParty DisconnectReason DisconnectMessage
    deriving (Eq, Ord, Show)

data DisconnectParty = Local | Remote
    deriving (Eq, Ord, Show)

data DisconnectReason
    = DisconnectHostNotAllowedToConnect
    | DisconnectProtocolError
    | DisconnectKeyExchangeFailed
    | DisconnectReserved
    | DisconnectMacError
    | DisconnectCompressionError
    | DisconnectServiceNotAvailable
    | DisconnectProtocolVersionNotSupported
    | DisconnectHostKeyNotVerifiable
    | DisconnectConnectionLost
    | DisconnectByApplication
    | DisconnectTooManyConnection
    | DisconnectAuthCancelledByUser
    | DisconnectNoMoreAuthMethodsAvailable
    | DisconnectIllegalUsername
    | DisconnectOtherReason Word32
    deriving (Eq, Ord, Show)

newtype DisconnectMessage = DisconnectMessage BS.ByteString
    deriving (Eq, Ord, Show, Semigroup, Monoid, IsString)

instance Exception Disconnect where

exceptionProtocolVersionNotSupported :: Disconnect
exceptionProtocolVersionNotSupported =
    Disconnect Local DisconnectProtocolVersionNotSupported mempty

exceptionConnectionLost :: Disconnect
exceptionConnectionLost =
    Disconnect Local DisconnectConnectionLost mempty

exceptionKexInvalidTransition :: Disconnect
exceptionKexInvalidTransition =
    Disconnect Local DisconnectKeyExchangeFailed "invalid transition"

exceptionKexInvalidSignature :: Disconnect
exceptionKexInvalidSignature =
    Disconnect Local DisconnectKeyExchangeFailed "invalid signature"

exceptionKexNoSignature :: Disconnect
exceptionKexNoSignature =
    Disconnect Local DisconnectKeyExchangeFailed "no signature"

exceptionKexNoCommonKexAlgorithm :: Disconnect
exceptionKexNoCommonKexAlgorithm = 
    Disconnect Local DisconnectKeyExchangeFailed "no common kex algorithm"

exceptionKexNoCommonEncryptionAlgorithm :: Disconnect
exceptionKexNoCommonEncryptionAlgorithm = 
    Disconnect Local DisconnectKeyExchangeFailed "no common encryption algorithm"

exceptionMacError :: Disconnect
exceptionMacError =
    Disconnect Local DisconnectMacError mempty

exceptionInvalidPacket :: Disconnect
exceptionInvalidPacket =
    Disconnect Local DisconnectProtocolError "invalid packet"

exceptionPacketLengthExceeded :: Disconnect
exceptionPacketLengthExceeded =
    Disconnect Local DisconnectProtocolError "packet length exceeded"

exceptionAuthenticationTimeout :: Disconnect
exceptionAuthenticationTimeout =
    Disconnect Local DisconnectByApplication "authentication timeout"

exceptionAuthenticationLimitExceeded :: Disconnect
exceptionAuthenticationLimitExceeded =
    Disconnect Local DisconnectByApplication "authentication limit exceeded"

exceptionServiceNotAvailable :: Disconnect
exceptionServiceNotAvailable =
    Disconnect Local DisconnectServiceNotAvailable mempty

exceptionNoMoreAuthMethodsAvailable :: Disconnect
exceptionNoMoreAuthMethodsAvailable =
    Disconnect Local DisconnectNoMoreAuthMethodsAvailable mempty

exceptionInvalidChannelId :: Disconnect
exceptionInvalidChannelId =
    Disconnect Local DisconnectProtocolError "invalid channel id"

exceptionInvalidChannelState :: Disconnect
exceptionInvalidChannelState =
    Disconnect Local DisconnectProtocolError "invalid channel state"

exceptionInvalidChannelRequest :: Disconnect
exceptionInvalidChannelRequest =
    Disconnect Local DisconnectProtocolError "invalid channel request"

exceptionWindowSizeOverflow :: Disconnect
exceptionWindowSizeOverflow =
    Disconnect Local DisconnectProtocolError "window size overflow"
        
exceptionWindowSizeUnderrun :: Disconnect
exceptionWindowSizeUnderrun =
    Disconnect Local DisconnectProtocolError "window size underrun"

exceptionPacketSizeExceeded :: Disconnect
exceptionPacketSizeExceeded =
    Disconnect Local DisconnectProtocolError "packet size exceeded"

exceptionDataAfterEof :: Disconnect
exceptionDataAfterEof =
    Disconnect Local DisconnectProtocolError "data after eof"

exceptionAlreadyExecuting :: Disconnect
exceptionAlreadyExecuting =
    Disconnect Local DisconnectProtocolError "already executing"

exceptionUnexpectedMessage :: BS.ByteString -> Disconnect
exceptionUnexpectedMessage raw
    | BS.null raw = Disconnect Local DisconnectProtocolError "empty message"
    | otherwise   = Disconnect Local DisconnectProtocolError msg
    where
        x   = BS.head raw
        x0  = (x `div` 100) + 48
        x1  = ((x `div` 10) `mod` 10) + 48
        x2  = (x `mod` 10) + 48
        msg = DisconnectMessage $ "unexpected message type " <> BS.pack [x0,x1,x2] 
