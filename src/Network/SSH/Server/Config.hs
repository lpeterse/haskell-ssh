module Network.SSH.Server.Config where

import           Data.Default

import           Network.SSH.Transport
import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Server.Service.Connection

data Config identity
    = Config
      { transportConfig    :: TransportConfig
      , userAuthConfig     :: UserAuthConfig identity
      , connectionConfig   :: ConnectionConfig identity
      }

instance Default (Config identity) where
    def = Config
        { transportConfig  = def
        , userAuthConfig   = def
        , connectionConfig = def
        }
