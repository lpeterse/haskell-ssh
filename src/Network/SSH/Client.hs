{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client
    ( Config (..)
    , UserAuthConfig (..)
    , ConnectionConfig (..)
    , runClient
    -- * Connection
    -- ** exec
    , ExecHandler (..)
    , Command (..)
    , exec
    )
where

import           Control.Concurrent.STM.TVar
import           Control.Concurrent.Async
import           Control.Monad
import           Control.Monad.STM
import           Data.Default

import           Network.SSH.Client.Connection
import           Network.SSH.Client.UserAuth
import           Network.SSH.Exception
import           Network.SSH.Message
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

runClient :: DuplexStream stream => Config -> stream -> (Connection -> IO a) -> IO a
runClient config stream handler = do
    ea <- withTransport (transportConfig config) (Nothing :: Maybe KeyPair) stream $ \transport sessionId -> do
        requestServiceWithAuthentication (userAuthConfig config) transport sessionId (Name "ssh-connection")
        withConnection (connectionConfig config) transport handler
    case ea of
        Left  _ -> error "FIXME"
        Right a -> pure a
