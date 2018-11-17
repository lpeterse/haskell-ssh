{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client
    ( Config (..)
    , UserAuthConfig (..)
    , ConnectionConfig (..)
    , withConnection
    , exec
    , Command (..)
    , ExecHandler (..)
    )
where

import           Control.Applicative
import           Control.Concurrent.Async              ( Async (..), async, withAsync )
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Control.Exception                     ( Exception, throwIO )
import           Control.Monad
import           Control.Monad.STM
import           Data.Default
import           Data.Function                         ( fix )
import           Data.List                             ( intersect )
import           Data.Map.Strict                       as M
import           System.Exit
import           Data.Word
import qualified Data.ByteString                       as BS
import qualified Data.ByteString.Short                 as SBS

import           Network.SSH.AuthAgent
import           Network.SSH.Client.Connection
import           Network.SSH.Client.UserAuth
import           Network.SSH.Constants
import           Network.SSH.Exception
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Key
import           Network.SSH.Name
import           Network.SSH.Stream
import           Network.SSH.Transport
import qualified Network.SSH.TStreamingQueue           as Q

data Config
    = Config
    { transportConfig  :: TransportConfig
    , userAuthConfig   :: UserAuthConfig
    , connectionConfig :: ConnectionConfig 
    }

instance Default Config where
    def = Config def def def

withConnection :: forall stream. (DuplexStream stream)
     => Config -> stream -> (Connection -> IO DisconnectMessage)
     -> IO Disconnect
withConnection config stream handler = mergeDisconnects $
    withTransport (transportConfig config) (Nothing :: Maybe KeyPair) stream $ \transport sessionId -> do
        requestServiceWithAuthentication (userAuthConfig config) transport sessionId (Name "ssh-connection")
        c <- atomically $ Connection transport (connectionConfig config) <$> newTVar mempty
        withAsync (dispatchIncoming transport c) $ \thread ->
            Disconnect Local DisconnectByApplication <$> handler c
    where
        mergeDisconnects :: IO (Either Disconnect Disconnect) -> IO Disconnect
        mergeDisconnects = fmap $ \case
            Left  d -> d
            Right d -> d

        dispatchIncoming :: Transport -> Connection -> IO ()
        dispatchIncoming t c = forever $ do
            receiveMessage t >>= \case
                C1 x -> print x
                C2 x@(ChannelOpenConfirmation lid _ _ _) -> atomically $ do
                    getChannelStateSTM c lid >>= \case
                        ChannelOpening f -> f (Right x)
                        _                -> throwSTM exceptionInvalidChannelState
                C3 x@(ChannelOpenFailure lid _ _ _) -> atomically $ do
                    getChannelStateSTM c lid >>= \case
                        ChannelOpening f -> f (Left x)
                        _                -> throwSTM exceptionInvalidChannelState
                C4  x -> print x
                C5  x -> print x
                C6  x -> print x
                C7  x -> print x
                C8  x -> print x
                C9  x -> print x
                C96 (ChannelEof lid) -> do
                    print "FIXME"
                C97 (ChannelClose lid) -> do
                    atomically $ getChannelStateSTM c lid >>= \case
                        ChannelRunning {} -> freeChannelSTM c lid
                        ChannelClosing {} -> freeChannelSTM c lid
                        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
