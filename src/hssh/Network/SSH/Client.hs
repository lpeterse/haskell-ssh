{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client
    ( withClientConnection
    -- * Config
    , ClientConfig (..)
    , ConnectionConfig (..)
    , ClientIdentity (..)
    , userPassword
    -- * Connection
    , Connection ()
    , getChannelCount
    -- ** runShell & runExec
    , runShell
    , runExec
    , SessionHandler (..)
    -- ** Misc
    , Command (..)
    , Duration (..)
    , ExitSignal (..)
    , ChannelException (..)
    , ChannelOpenFailureDescription (..)
    )
where

import Network.SSH.Client.Client
import Network.SSH.Client.Connection
import Network.SSH.Client.UserAuth
