{-# LANGUAGE LambdaCase #-}
module Network.SSH.Server.Connection
    ( Connection ()
    , withConnection
    , pushMessage
    ) where

import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Concurrent.STM.TVar
import           Control.Exception            (bracket, throwIO)

import           Network.SSH.Message
import qualified Network.SSH.Server.Channel   as Channel
import           Network.SSH.Server.Config
import qualified Network.SSH.Server.Service   as Service
import           Network.SSH.Server.Types
import qualified Network.SSH.Server.UserAuth  as UserAuth

withConnection :: Config identity -> SessionId -> (Message -> IO ()) -> (Connection identity -> IO a) -> IO a
withConnection cfg sid enqueueMessage = bracket before after
    where
        -- FIXME: Why is there a bracket at all?
        before = Connection
            <$> pure cfg
            <*> pure sid
            <*> newTVarIO Nothing
            <*> newTVarIO mempty
            <*> newTChanIO
            <*> pure enqueueMessage
            <*> newEmptyTMVarIO
        after = const $ pure ()


pushMessage :: Connection identity -> Message -> IO ()
pushMessage connection = \case
    MsgIgnore {}                  -> pure ()

    MsgServiceRequest x           -> Service.handleServiceRequest      connection x

    MsgUserAuthRequest x          -> UserAuth.handleUserAuthRequest    connection x

    MsgChannelOpen x              -> Channel.handleChannelOpen         connection x
    MsgChannelClose x             -> Channel.handleChannelClose        connection x
    MsgChannelEof x               -> Channel.handleChannelEof          connection x
    MsgChannelRequest x           -> Channel.handleChannelRequest      connection x
    MsgChannelWindowAdjust x      -> Channel.handleChannelWindowAdjust connection x
    MsgChannelData x              -> Channel.handleChannelData         connection x
    MsgChannelExtendedData x      -> Channel.handleChannelExtendedData connection x

    _                             -> throwIO $ Disconnect DisconnectProtocolError mempty mempty
