{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Constants where

import qualified Data.ByteString     as BS

import           Network.SSH.Message

version :: Version
version
  = Version "SSH-2.0-hssh_0.1"

serverKexInit :: KexInit
serverKexInit = KexInit
  { kexCookie
  = Cookie "\155=\ACK\150\169p\164\v\t\245\223\224\EOT\233\200\SO"
  , kexAlgorithms
  = [ "curve25519-sha256@libssh.org" ]
  , kexServerHostKeyAlgorithms
  = [ "ssh-ed25519" ]
  , kexEncryptionAlgorithmsClientToServer
  = [ "chacha20-poly1305@openssh.com" ]
  , kexEncryptionAlgorithmsServerToClient
  = [ "chacha20-poly1305@openssh.com" ]
  , kexMacAlgorithmsClientToServer
  = [ "umac-64-etm@openssh.com" ]
  , kexMacAlgorithmsServerToClient
  = [ "umac-64-etm@openssh.com" ]
  , kexCompressionAlgorithmsClientToServer
  = [ "none" ]
  , kexCompressionAlgorithmsServerToClient
  = [ "none" ]
  , kexLanguagesClientToServer
  = []
  , kexLanguagesServerToClient
  = []
  , kexFirstPacketFollows
  = False
  }
