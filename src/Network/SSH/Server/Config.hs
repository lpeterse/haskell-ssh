{-# LANGUAGE ExistentialQuantification, AllowAmbiguousTypes, RankNTypes #-}
module Network.SSH.Server.Config where

import qualified Data.ByteString        as BS
import           Data.Word
import qualified Data.Map.Strict        as M
import           System.Exit
import           Data.Default

import           Network.SSH.Message
import           Network.SSH.Stream
import           Network.SSH.Transport
import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Server.Service.Connection

type Command = BS.ByteString

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
