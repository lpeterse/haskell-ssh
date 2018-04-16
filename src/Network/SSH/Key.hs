{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
module Network.SSH.Key where

import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA     as RSA
import           Data.ByteArray
import qualified Data.ByteString       as BS
import           Text.Megaparsec
import           Text.Megaparsec.Byte

data RSA
data Ed25519

data family PublicKey a
data family PrivateKey a

data instance PublicKey Ed25519 = Ed25519PublicKey Ed25519.PublicKey deriving (Eq, Show)
data instance PrivateKey Ed25519 = Ed25519PrivateKey Ed25519.SecretKey deriving (Eq, Show)

class SshKeyAlgorithm a where
  decodePrivateKey :: BS.ByteString -> Maybe (PrivateKey a)

instance SshKeyAlgorithm Ed25519 where
  decodePrivateKey bs = Ed25519PrivateKey <$> (parseMaybe parser bs >>= maybeCryptoError . Ed25519.secretKey)
    where
      parser :: Parsec () BS.ByteString BS.ByteString
      parser = do
        string "-----BEGIN OPENSSH PRIVATE KEY-----"
        eol
        bs <- base64Parser
        string "-----END OPENSSH PRIVATE KEY-----"
        space
        eof
        pure bs
      base64 = s0 []
        where
          s0 xs         = (base64Char >>= s1 xs)         <|> (space >> s0 xs) <|> (char
          s1 xs i       = (base64Char >>= s2 xs i)       <|>
          s2 xs i j     = (base64Char >>= s3 xs i j)     <|>
          s3 xs i j k   = (base64Char >>= s3 xs i j k l) <|> 
          s4 xs i j k l = s0 $ (i `shiftL` 2 + j `shiftR` 4) : (j `shiftL` 4 + k `shiftR` 4) : (k `shiftL` 4 + l) : xs

          base64Char = p1 <|> p2 <|> p3 <|> p4
          p1 = upperChar >>= \c-> pure (fromEnum c - fromEnum 'A')
          p2 = lowerChar >>= \c-> pure (fromEnum c - fromEnum 'a' + 26)
          p3 = digitChar >>= \c-> pure (fromEnum c - fromEnum '0' + 52)
          p4 = char '+'  >> pure 62
          p5 = char '/'  >> pure 63
