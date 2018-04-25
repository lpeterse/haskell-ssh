{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
module Network.SSH.Key where

import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA     as RSA
import           Data.Bits
import           Data.ByteArray
import qualified Data.ByteString       as BS
import           Data.Word
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
        bs <- base64
        string "-----END OPENSSH PRIVATE KEY-----"
        space
        eof
        pure bs
      base64 :: Parsec () BS.ByteString BS.ByteString
      base64 = s0 []
        where
          -- Initial state.
          s0 xs         =                 (base64Char >>= s1 xs)       <|> (space1 >> s0 xs)       <|> pure (BS.pack $ reverse xs)
          -- One character read (i). Three more characters or whitespace expected.
          s1 xs i       =                 (base64Char >>= s2 xs i)     <|> (space1 >> s1 xs i)
          -- Two characters read (i and j). Either '==' or space or two more character expected.
          s2 xs i j     = r2 xs i j   <|> (base64Char >>= s3 xs i j)   <|> (space1 >> s2 xs i j)
          -- Three characters read (i, j and k). Either a '=' or space or one more character expected.
          s3 xs i j k   = r3 xs i j k <|> (base64Char >>= s4 xs i j k) <|> (space1 >> s3 xs i j k)
          -- Four characters read (i, j, k and l). Computation of result and transition back to s0.
          s4 xs i j k l = s0 $ (k `shiftL` 4 + l) : (j `shiftL` 4 + k `shiftR` 4) : (i `shiftL` 2 + j `shiftR` 4) : xs
          -- Read two '=' chars as finalizer. Only valid from state s2.
          r2 xs i j     = padding >> padding >> pure (BS.pack $ reverse $ (i `shiftL` 2 + j `shiftR` 4) : xs)
          -- Read one '=' char as finalizer. Only valid from state s1.
          r3 xs i j k   =            padding >> pure (BS.pack $ reverse $ (j `shiftL` 4 + k `shiftR` 4) : (i `shiftL` 2 + j `shiftR` 4) : xs)
          base64Char, p1, p2, p3, p4, p5, padding :: Parsec () BS.ByteString Word8
          base64Char    = p1 <|> p2 <|> p3 <|> p4
          p1            = upperChar >>= \c-> pure $ fromIntegral (fromEnum c - fromEnum 'A')
          p2            = lowerChar >>= \c-> pure $ fromIntegral (fromEnum c - fromEnum 'a' + 26)
          p3            = digitChar >>= \c-> pure $ fromIntegral (fromEnum c - fromEnum '0' + 52)
          p4            = char 43   >> pure 62 -- 43 == '+'
          p5            = char 47   >> pure 63 -- 47 == '/'
          padding       = char 61              -- 61 == '='
