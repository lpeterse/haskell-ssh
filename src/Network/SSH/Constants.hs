{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Constants where

import qualified Data.ByteString     as BS

import           Network.SSH.Message

version :: Version
version
  = Version "SSH-2.0-hssh_0.1"

serverKexInit :: KeyExchangeInit
serverKexInit = KeyExchangeInit
  { cookie
  = Cookie "\155=\ACK\150\169p\164\v\t\245\223\224\EOT\233\200\SO"
  , keyAlgorithms
  = [ "curve25519-sha256@libssh.org" ]
  , serverHostKeyAlgorithms
  = [ "ssh-ed25519" ]
  , encryptionAlgorithmsClientToServer
  = [ "chacha20-poly1305@openssh.com" ]
  , encryptionAlgorithmsServerToClient
  = [ "chacha20-poly1305@openssh.com" ]
  , macAlgorithmsClientToServer
  = [ "umac-64-etm@openssh.com" ]
  , macAlgorithmsServerToClient
  = [ "umac-64-etm@openssh.com" ]
  , compressionAlgorithmsClientToServer
  = [ "none" ]
  , compressionAlgorithmsServerToClient
  = [ "none" ]
  , languagesClientToServer
  = []
  , languagesServerToClient
  = []
  , firstKexPacketFollows
  = False
  }
