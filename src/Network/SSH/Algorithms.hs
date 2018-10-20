{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Algorithms where

import           Network.SSH.Name

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

instance HasName HostKeyAlgorithm where
    name SshEd25519 = Name "ssh-ed25519"

instance HasName KeyExchangeAlgorithm where
    name Curve25519Sha256AtLibsshDotOrg = Name "curve25519-sha256@libssh.org"

instance HasName EncryptionAlgorithm where
    name Chacha20Poly1305AtOpensshDotCom = Name "chacha20-poly1305@openssh.com"

instance HasName CompressionAlgorithm where
    name None = Name "none"
