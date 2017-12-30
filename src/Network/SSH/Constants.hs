{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Constants where

import qualified Data.ByteString     as BS

import           Network.SSH.Message

version :: Version
version  = Version "SSH-2.0-hssh_0.1"

kexInit :: Cookie -> KexInit
kexInit cookie = KexInit
  { kexCookie                              = cookie
  , kexAlgorithms                          = ["curve25519-sha256@libssh.org"]
  , kexServerHostKeyAlgorithms             = ["ssh-ed25519"]
  , kexEncryptionAlgorithmsClientToServer  = ["chacha20-poly1305@openssh.com"]
  , kexEncryptionAlgorithmsServerToClient  = ["chacha20-poly1305@openssh.com"]
  , kexMacAlgorithmsClientToServer         = []
  , kexMacAlgorithmsServerToClient         = []
  , kexCompressionAlgorithmsClientToServer = ["none"]
  , kexCompressionAlgorithmsServerToClient = ["none"]
  , kexLanguagesClientToServer             = []
  , kexLanguagesServerToClient             = []
  , kexFirstPacketFollows                  = False
  }
