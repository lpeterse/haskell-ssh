{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Algorithms where

import qualified Data.ByteString               as BS

data HostKeyAlgorithm
    = SshEd25519
    deriving (Eq, Show)

data KeyExchangeAlgorithm
    = Curve25519Sha256AtLibsshDotOrg
    deriving (Eq, Show)

data EncryptionAlgorithm
    = Chacha20Poly1305AtOpensshDotCom
    deriving (Eq, Show)

data CompressionAlgorithm
    = None
    deriving (Eq, Show)

class Algorithm a where
    algorithmName :: a -> BS.ByteString

instance Algorithm HostKeyAlgorithm where
    algorithmName SshEd25519 = "ssh-ed25519"

instance Algorithm KeyExchangeAlgorithm where
    algorithmName Curve25519Sha256AtLibsshDotOrg = "curve25519-sha256@libssh.org"

instance Algorithm EncryptionAlgorithm where
    algorithmName Chacha20Poly1305AtOpensshDotCom = "chacha20-poly1305@openssh.com"

instance Algorithm CompressionAlgorithm where
    algorithmName None = "none"
