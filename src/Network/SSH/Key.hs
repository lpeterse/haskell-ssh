{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
module Network.SSH.Key where

import           Control.Monad         (replicateM, when)
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA     as RSA
import qualified Data.Binary.Get       as B
import           Data.Bits
import           Data.ByteArray
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Lazy  as LBS
import           Data.Word
import           Text.Megaparsec
import           Text.Megaparsec.Byte

data RSA
data Ed25519

type Parser a = Parsec (ErrorItem Word8) BS.ByteString a

data PrivateKeyFile
   = PrivateKeyFile
     { cipher     :: BS.ByteString
     , kdf        :: BS.ByteString
     , kdfOptions :: BS.ByteString
     , keys       :: [(PrivateKey, BS.ByteString)]
     }
   deriving (Eq, Show)

data PrivateKey
  = Ed25519PrivateKey Ed25519.SecretKey
  deriving (Eq, Show)

decodePrivateKeyFile :: BS.ByteString -> Either String PrivateKeyFile
decodePrivateKeyFile bs = case runParser fileParser mempty bs of
  Left  e -> Left (parseErrorPretty e)
  Right a -> Right a
  where
    fileParser :: Parser PrivateKeyFile
    fileParser = do
      string "-----BEGIN OPENSSH PRIVATE KEY-----"
      eol
      bs <- base64Parser
      space
      string "-----END OPENSSH PRIVATE KEY-----"
      space
      eof
      case B.runGetOrFail binaryDecoder (LBS.fromStrict bs) of
        Left (_,_,e)  -> fail e
        Right (_,_,a) -> pure a

    base64Parser :: Parser BS.ByteString
    base64Parser = s0 []
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
        s4 xs i j k l = s0 $ byte3 : byte2 : byte1: xs
          where
            byte1 = ( i         `shiftL` 2) + (j `shiftR` 4)
            byte2 = ((j .&. 15) `shiftL` 4) + (k `shiftR` 2)
            byte3 = ((k .&.  3) `shiftL` 6) + l
        -- Read two '=' chars as finalizer. Only valid from state s2.
        r2 xs i j     = padding >> padding >> pure (BS.pack $ reverse $ byte1 : xs)
          where
            byte1 = (i `shiftL` 2 + j `shiftR` 4)
        -- Read one '=' char as finalizer. Only valid from state s1.
        r3 xs i j k   =            padding >> pure (BS.pack $ reverse $ byte2 : byte1 : xs)
          where
            byte1 = (i          `shiftL` 2) + (j `shiftR` 4)
            byte2 = ((j .&. 15) `shiftL` 4) + (k `shiftR` 2)
        base64Char, p1, p2, p3, p4, p5, padding :: Parser Word8
        base64Char    = p1 <|> p2 <|> p3 <|> p4 <|> p5
        p1            = upperChar >>= \c-> pure $ fromIntegral (fromEnum c - fromEnum 'A')
        p2            = lowerChar >>= \c-> pure $ fromIntegral (fromEnum c - fromEnum 'a' + 26)
        p3            = digitChar >>= \c-> pure $ fromIntegral (fromEnum c - fromEnum '0' + 52)
        p4            = char 43   >> pure 62 -- 43 == '+'
        p5            = char 47   >> pure 63 -- 47 == '/'
        padding       = char 61              -- 61 == '='

    binaryDecoder :: B.Get PrivateKeyFile
    binaryDecoder = do
      bytestring "openssh-key-v1\NUL"
      cipher       <- bytestringLen
      kdf          <- bytestringLen
      kdfOptions   <- bytestringLen
      numberOfKeys <- B.getWord32be
      keys         <- replicateM (fromIntegral numberOfKeys) getKeyComment
      pure (PrivateKeyFile cipher kdf kdfOptions keys)
      where
        bytestring bs = do
          bs' <- B.getByteString (BS.length bs)
          when (bs /= bs') (fail $ "Expected " ++ show bs ++ ", got " ++ show bs')

        bytestringLen = do
          w32 <- B.getWord32be
          B.getByteString (fromIntegral w32)

        getKeyComment = do
          size <- B.getWord32be
          key  <- B.isolate (fromIntegral size) $ do
            algo <- bytestringLen
            case algo of
              "ssh-ed25519" -> do
                sec <- bytestringLen
                case Ed25519.secretKey sec of
                  CryptoPassed a -> pure (Ed25519PrivateKey a)
                  CryptoFailed e -> fail (show e)
              _ -> fail $ "unsupported algorithm " ++ show algo
          size2 <- B.getWord32be
          comment <- B.isolate (fromIntegral size2) $ do
            ci1 <- B.getWord32be
            ci2 <- B.getWord32be
            when (c1 /= c2) (fail "Checksum error. Wrong passphrase?")
          pure (key, comment)
