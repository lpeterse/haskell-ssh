{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client
    ( runClient
    -- * Config
    , ClientConfig (..)
    , ConnectionConfig (..)
    , ClientIdentity (..)
    , userPassword
    -- * Connection
    , Connection ()
    -- ** runShell & runExec
    , runShell
    , runExec
    , SessionHandler (..)
    -- ** Exceptions
    , ClientException (..)
    , ChannelException (..)
    , ChannelOpenFailureDescription (..)
    )
where

import Network.SSH.Client.Client
import Network.SSH.Client.Connection
import Network.SSH.Client.UserAuth
