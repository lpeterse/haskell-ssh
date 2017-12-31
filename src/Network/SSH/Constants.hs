{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Constants where

import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ByteString       as BS

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

exampleHostKey :: Ed25519.SecretKey
exampleHostKey = case Ed25519.secretKey bs of
  CryptoPassed k -> k
  CryptoFailed _ -> undefined
  where
    bs = BS.pack
      [239,90,200,222,247,52,104,25,64,47,196,140,102,205,187,142,
      226,139,42,39,225,249,15,144,86,235,102,104,136,224,207,161]
