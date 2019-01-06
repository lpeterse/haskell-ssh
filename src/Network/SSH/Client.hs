{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client
    (
    -- * Config
      Config (..)
    , UserAuthConfig (..)
    , ConnectionConfig (..)
    -- * Connection
    , Connection ()
    , getChannelCount
    -- ** withClientConnection
    , withClientConnection
    -- ** runShell & runExec
    , runShell
    , runExec
    , SessionHandler (..)
    -- ** Misc
    , Command (..)
    , ExitSignal (..)
    , ChannelException (..)
    , ChannelOpenFailureDescription (..)
    )
where

import           Data.Default

import           Network.SSH.Client.Connection
import           Network.SSH.Client.UserAuth
import           Network.SSH.Key
import           Network.SSH.Name
import           Network.SSH.Stream
import           Network.SSH.Transport

data Config
    = Config
    { transportConfig  :: TransportConfig
    , userAuthConfig   :: UserAuthConfig
    , connectionConfig :: ConnectionConfig
    }

instance Default Config where
    def = Config def def def

withClientConnection :: DuplexStream stream => Config -> stream -> (Connection -> IO a) -> IO a
withClientConnection config stream handler = do
    ea <- withClientTransport (transportConfig config) stream $ \transport sessionId hostKey -> do
        requestServiceWithAuthentication (userAuthConfig config) transport sessionId (Name "ssh-connection")
        withConnection (connectionConfig config) transport handler
    case ea of
        Left  e -> print e >> undefined
        Right a -> pure a
