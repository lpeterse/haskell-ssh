{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Constants where

import qualified Data.ByteString     as BS

import           Network.SSH.Message

version :: Version
version
  = Version "SSH-2.0-hssh_0.1"
