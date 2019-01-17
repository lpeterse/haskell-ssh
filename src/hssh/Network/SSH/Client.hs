{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client (
    -- * Client
    -- ** runClient
      runClient
    -- ** ClientConfig
    , ClientConfig (..)
    , HostKeyVerifier
    , VerificationResult (..)
    -- ** ClientIdentity
    , ClientIdentity (..)
    , userPassword
    -- * Connection
    , Connection ()
    , ConnectionConfig (..)
    -- ** runShell & runExec
    , runShell
    , runExec
    , SessionHandler (..)
    -- ** Exceptions
    , ClientException (..)
    , ChannelException (..)
    , ChannelOpenFailureDescription (..)
    ) where

import Network.SSH.Client.Client
import Network.SSH.Client.HostKeyVerifier
import Network.SSH.Client.Connection
import Network.SSH.Client.UserAuth
