{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
module Network.SSH.Key where

import           Control.Applicative    (many, (<|>))
import           Control.Monad          (forM, replicateM, when)
import qualified Crypto.Cipher.AES      as Cipher
import qualified Crypto.Cipher.Blowfish as Cipher
import qualified Crypto.Cipher.Types    as Cipher
import           Crypto.Error
import qualified Crypto.Hash            as Hash
import qualified Crypto.Hash.Algorithms as Hash
import qualified Crypto.KDF.BCryptPBKDF as BCryptPBKDF
import qualified Crypto.PubKey.Ed25519  as Ed25519
import qualified Crypto.PubKey.RSA      as RSA
import           Data.Bits
import           Data.ByteArray
import qualified Data.ByteArray         as BA
import qualified Data.ByteArray.Parse   as BP
import           Data.String
import           Data.Word

data PublicKey
  = Ed25519PublicKey Ed25519.PublicKey
  | RsaPublicKey     RSA.PublicKey
  deriving (Eq, Show)

data PrivateKey
  = Ed25519PrivateKey Ed25519.PublicKey Ed25519.SecretKey
  | RsaPrivateKey     RSA.PrivateKey
  deriving (Eq, Show)

parsePrivateKeyFile :: (BA.ByteArray input, IsString input, Show input, BA.ByteArray passphrase, BA.ByteArray comment)
                    => passphrase -> BP.Parser input [(PrivateKey, comment)]
parsePrivateKeyFile passphrase = do
    BP.bytes "-----BEGIN OPENSSH PRIVATE KEY-----"
    many space
    bs <- parseBase64
    many space
    BP.bytes "-----END OPENSSH PRIVATE KEY-----"
    many space
    BP.hasMore >>= flip when syntaxError
    case BP.parse parseKeys bs of
        BP.ParseOK _ keys -> pure keys
        BP.ParseFail e    -> fail e
        BP.ParseMore _    -> syntaxError
  where
    syntaxError :: BP.Parser ba a
    syntaxError = fail "Syntax error"

    parseBase64 :: (BA.ByteArray ba) => BP.Parser ba ba
    parseBase64 = s0 []
      where
        -- Initial state and final state.
        s0 xs         =                 (char >>= s1 xs)       <|> (space1 >> s0 xs)
                                                               <|> pure (BA.pack $ reverse xs)
        -- One character read (i). Three more characters or whitespace expected.
        s1 xs i       =                 (char >>= s2 xs i)     <|> (space1 >> s1 xs i)
        -- Two characters read (i and j). Either '==' or space or two more character expected.
        s2 xs i j     = r2 xs i j   <|> (char >>= s3 xs i j)   <|> (space1 >> s2 xs i j)
        -- Three characters read (i, j and k). Either a '=' or space or one more character expected.
        s3 xs i j k   = r3 xs i j k <|> (char >>= s4 xs i j k) <|> (space1 >> s3 xs i j k)
        -- Four characters read (i, j, k and l). Computation of result and transition back to s0.
        s4 xs i j k l = s0 $ byte3 : byte2 : byte1: xs
          where
            byte1 = ( i         `shiftL` 2) + (j `shiftR` 4)
            byte2 = ((j .&. 15) `shiftL` 4) + (k `shiftR` 2)
            byte3 = ((k .&.  3) `shiftL` 6) + l
        -- Read two '=' chars as finalizer. Only valid from state s2.
        r2 xs i j     = padding >> padding >> pure (BA.pack $ reverse $ byte1 : xs)
          where
            byte1 = (i `shiftL` 2) + (j `shiftR` 4)
        -- Read one '=' char as finalizer. Only valid from state s1.
        r3 xs i j k   = padding >> pure (BA.pack $ reverse $ byte2 : byte1 : xs)
          where
            byte1 = (i          `shiftL` 2) + (j `shiftR` 4)
            byte2 = ((j .&. 15) `shiftL` 4) + (k `shiftR` 2)

        char :: (BA.ByteArray ba) => BP.Parser ba Word8
        char = BP.anyByte >>= \c-> if
            | c >= fe 'A' && c <= fe 'Z' -> pure (c - fe 'A')
            | c >= fe 'a' && c <= fe 'z' -> pure (c - fe 'a' + 26)
            | c >= fe '0' && c <= fe '9' -> pure (c - fe '0' + 52)
            | c == fe '+'                -> pure 62
            | c == fe '/'                -> pure 63
            | otherwise                  -> fail ""

        padding :: (BA.ByteArray ba) => BP.Parser ba ()
        padding = BP.byte 61 -- 61 == fromEnum '='

    fe :: Char -> Word8
    fe = fromIntegral . fromEnum

    space :: (BA.ByteArray ba) => BP.Parser ba ()
    space = BP.anyByte >>= \c-> if
      | c == fe ' '  -> pure ()
      | c == fe '\n' -> pure ()
      | c == fe '\r' -> pure ()
      | c == fe '\t' -> pure ()
      | otherwise    -> fail ""

    space1 :: (BA.ByteArray ba) => BP.Parser ba ()
    space1 = space >> many space >> pure ()

    getWord32be :: BA.ByteArray ba => BP.Parser ba Word32
    getWord32be = do
        x0 <- fromIntegral <$> BP.anyByte
        x1 <- fromIntegral <$> BP.anyByte
        x2 <- fromIntegral <$> BP.anyByte
        x3 <- fromIntegral <$> BP.anyByte
        pure $ shiftR x0 24 .|. shiftR x1 16 .|. shiftR x2 8 .|. x3

    getString :: BA.ByteArray ba => BP.Parser ba ba
    getString = BP.take =<< (fromIntegral <$> getWord32be)

    parseKeys :: (BA.ByteArray input, IsString input, Show input, BA.ByteArray comment)
                  => BP.Parser input [(PrivateKey, comment)]
    parseKeys = do
        BP.bytes "openssh-key-v1\NUL"
        cipherAlgo <- getString
        kdfAlgo <- getString
        BP.skip 4 -- size of the kdf section
        deriveKey <- case kdfAlgo of
            "none" ->
                pure $ \keyLen-> CryptoFailed CryptoError_KeySizeInvalid
            "bcrypt" -> do
                salt   <- getString
                rounds <- fromIntegral <$> getWord32be
                pure $ \case
                    Cipher.KeySizeFixed len ->
                      CryptoPassed $ BCryptPBKDF.generate (BCryptPBKDF.Parameters rounds len) passphrase salt
            _ -> fail $ "Unsupported key derivation function " ++ show (convert kdfAlgo :: BA.Bytes)

        numberOfKeys <- fromIntegral <$> getWord32be
        publicKeysRaw <- getString -- not used
        privateKeysRawEncrypted <- getString
        privateKeysRawDecrypted <- BA.convert <$> case cipherAlgo of
            "none"       -> pure privateKeysRawEncrypted
            "aes256-cbc" -> do
                let result = do
                      let Cipher.KeySizeFixed keySize = Cipher.cipherKeySize (undefined :: Cipher.AES256)
                      let ivSize = Cipher.blockSize (undefined :: Cipher.AES256)
                      keyIV <- deriveKey $ Cipher.KeySizeFixed (keySize + ivSize)
                      let key = BA.take keySize keyIV :: BA.ScrubbedBytes
                      case Cipher.makeIV (BA.drop keySize keyIV) of
                          Nothing -> CryptoFailed CryptoError_IvSizeInvalid
                          Just iv -> do
                              cipher <- Cipher.cipherInit key :: CryptoFailable Cipher.AES256
                              pure $ Cipher.cbcDecrypt cipher iv privateKeysRawEncrypted
                case result of
                  CryptoPassed a -> pure a
                  CryptoFailed e -> fail (show e)
            "aes256-ctr" -> do
                let result = do
                      let Cipher.KeySizeFixed keySize = Cipher.cipherKeySize (undefined :: Cipher.AES256)
                      let ivSize = Cipher.blockSize (undefined :: Cipher.AES256)
                      keyIV <- deriveKey $ Cipher.KeySizeFixed (keySize + ivSize)
                      let key = BA.take keySize keyIV :: BA.ScrubbedBytes
                      case Cipher.makeIV (BA.drop keySize keyIV) of
                          Nothing -> CryptoFailed CryptoError_IvSizeInvalid
                          Just iv -> do
                              cipher <- Cipher.cipherInit key :: CryptoFailable Cipher.AES256
                              pure $ Cipher.ctrCombine cipher iv privateKeysRawEncrypted
                case result of
                  CryptoPassed a -> pure a
                  CryptoFailed e -> fail (show e)
            _ -> fail $ "Unsupported cipher " ++ show cipherAlgo
        case BP.parse (parsePrivateKeys numberOfKeys) privateKeysRawDecrypted of
          BP.ParseOK _ keys -> pure keys
          BP.ParseFail e    -> fail e
          BP.ParseMore _    -> syntaxError

    parsePrivateKeys :: (BA.ByteArray comment) => Int -> BP.Parser BA.ScrubbedBytes [(PrivateKey, comment)]
    parsePrivateKeys count = do
        check1 <- getWord32be
        check2 <- getWord32be
        when (check1 /= check2) (fail "Unsuccessful decryption")
        replicateM count $ do
            key <- getString >>= \algo-> case algo of
                "ssh-ed25519" -> do
                    BP.skip 4 -- length field (is always 32 for ssh-ed25519)
                    BP.skip Ed25519.publicKeySize
                    BP.skip 4 -- length field (is always 64 for ssh-ed25519)
                    secretKeyRaw <- BP.take 32
                    publicKeyRaw <- BP.take 32
                    let key = Ed25519PrivateKey
                          <$> Ed25519.publicKey publicKeyRaw
                          <*> Ed25519.secretKey secretKeyRaw
                    case key of
                        CryptoPassed a -> pure a
                        CryptoFailed _ -> fail $ "Invalid " ++ show (convert algo :: BA.Bytes) ++ " private key"
                _ -> fail $ "Unsupported algorithm " ++ show (convert algo :: BA.Bytes)
            comment <- BA.convert <$> getString
            pure (key, comment)

instance IsString BA.Bytes where
    fromString = BA.pack . map (fromIntegral . fromEnum)
