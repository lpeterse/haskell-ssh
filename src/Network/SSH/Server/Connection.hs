{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.Connection
    ( Connection ()
    , withConnection
    , pushMessage
    , pullMessage
    ) where

import           Control.Applicative
import           Control.Concurrent
import           Control.Concurrent.Async
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Concurrent.STM.TVar
import           Control.Exception
import           Control.Monad                (forever, unless, when)
import           Control.Monad.STM
import qualified Data.ByteString              as BS
import           Data.Function                (fix)
import qualified Data.Map.Strict              as M
import           Data.Maybe
import           Data.Text                    as T
import           Data.Text.Encoding           as T
import           Data.Typeable
import           System.Exit

import           Network.SSH.Constants
import           Network.SSH.Exception
import           Network.SSH.Message
import qualified Network.SSH.Server.Channel   as Channel
import           Network.SSH.Server.Config
import           Network.SSH.Server.Types

withConnection :: Config identity -> SessionId -> (Connection identity -> IO ()) -> IO ()
withConnection cfg sid = bracket before after
    where
        before = Connection
            <$> pure cfg
            <*> pure sid
            <*> newTVarIO Nothing
            <*> newTVarIO mempty
            <*> newTChanIO
            <*> newTChanIO
            <*> newEmptyTMVarIO
        after connection = do
            pure ()

pullMessage :: Connection identity -> IO Message
pullMessage connection = atomically $ disconnectMessage <|> nextMessage
    where
        disconnectMessage = MsgDisconnect <$> readTMVar (connDisconnected connection)
        nextMessage = readTChan (connOutput connection)

-- Calling this operation will store a disconnect message
-- in the connection state. Afterwards, any attempts to read outgoing
-- messages from the connection shall yield this message and
-- the reader must close the connection after sending
-- the disconnect message.
disconnectWith :: Connection identity -> DisconnectReason -> IO ()
disconnectWith connection reason =
    atomically $ putTMVar (connDisconnected connection) (Disconnect reason mempty mempty) <|> pure ()

pushMessage :: Connection identity -> Message -> IO ()
pushMessage connection msg = do
  print msg
  case msg of
    MsgIgnore {}                  -> pure ()

    MsgServiceRequest x           -> handleServiceRequest x

    MsgUserAuthRequest x          -> handleAuthRequest x

    MsgChannelOpenConfirmation {} -> send (MsgUnimplemented Unimplemented)
    MsgChannelOpenFailure {}      -> send (MsgUnimplemented Unimplemented)
    MsgChannelFailure {}          -> send (MsgUnimplemented Unimplemented)
    MsgChannelSuccess {}          -> send (MsgUnimplemented Unimplemented)
    MsgChannelOpen x              -> Channel.handleIncomingChannelMessage connection (Channel.IncomingChannelOpen x)
    MsgChannelClose x             -> Channel.handleIncomingChannelMessage connection (Channel.IncomingChannelClose x)
    MsgChannelEof x               -> Channel.handleIncomingChannelMessage connection (Channel.IncomingChannelEof x)
    MsgChannelRequest x           -> Channel.handleIncomingChannelMessage connection (Channel.IncomingChannelRequest x)
    MsgChannelData x              -> Channel.handleIncomingChannelMessage connection (Channel.IncomingChannelData x)
    MsgChannelExtendedData x      -> Channel.handleIncomingChannelMessage connection (Channel.IncomingChannelExtendedData x)

    _                             -> connection `disconnectWith` DisconnectProtocolError
    where
        send :: Message -> IO ()
        send = atomically . writeTChan (connOutput connection)

        handleServiceRequest :: ServiceRequest -> IO ()
        handleServiceRequest (ServiceRequest (ServiceName srv)) = case srv of
            "ssh-userauth"   -> accept
            "ssh-connection" -> accept
            _                -> reject
            where
                accept = send $ MsgServiceAccept (ServiceAccept (ServiceName srv))
                reject = connection `disconnectWith` DisconnectServiceNotAvailable

        handleAuthRequest :: UserAuthRequest -> IO ()
        handleAuthRequest (UserAuthRequest user service method) = do
            print (UserAuthRequest user service method)
            case method of
              AuthPublicKey algo pk msig -> case msig of
                Nothing ->
                    unconditionallyConfirmPublicKeyIsOk algo pk
                Just sig
                    | verifyAuthSignature (connSessionId connection) user service algo pk sig -> do
                        onAuthRequest (connConfig connection) user service pk >>= \case
                            Nothing -> sendSupportedAuthMethods
                            Just ident -> atomically $ do
                                writeTVar (connIdentity connection) (Just ident)
                                writeTChan (connOutput connection) (MsgUserAuthSuccess UserAuthSuccess)
                    | otherwise ->
                        sendSupportedAuthMethods
              _ -> sendSupportedAuthMethods
            where
                sendSupportedAuthMethods =
                    send $ MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False
                unconditionallyConfirmPublicKeyIsOk algo pk =
                    send $ MsgUserAuthPublicKeyOk $ UserAuthPublicKeyOk algo pk
