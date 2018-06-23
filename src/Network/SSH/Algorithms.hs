module Network.SSH.Algorithms where

data KeyExchangeAlgorithm
    = Curve25519Sha256AtLibsshDotOrg
    deriving (Eq, Ord, Show)

data EncryptionAlgorithm
    = Chacha20Poly1305AtOpensshDotCom
    deriving (Eq, Ord, Show)
