{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Constants where

import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ByteString       as BS
import           Data.Semigroup
import qualified Data.Version          as V
import           Data.Word

import           Network.SSH.Message

import qualified Paths_hssh            as Library

version :: Version
version  = Version ("SSH-2.0-hssh_" <> v)
    where
        v = BS.pack $ fmap (fromIntegral . fromEnum) (V.showVersion Library.version)

maxPacketLength :: Word32
maxPacketLength = 35000

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
