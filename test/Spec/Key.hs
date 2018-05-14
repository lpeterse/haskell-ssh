{-# LANGUAGE OverloadedStrings #-}
module Spec.Key where

import           Control.Monad         (zipWithM_)
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ByteArray        as BA
import qualified Data.ByteArray.Parse  as BP
import qualified Data.ByteString       as BS

import           Network.SSH.Key

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck as QC

passphrase :: BA.ScrubbedBytes
passphrase = "foobar"

testKey :: TestTree
testKey = testGroup "Network.SSH.Key"
  [ testEd25519Keys
  ]

testEd25519Keys :: TestTree
testEd25519Keys = testGroup "Ed25519"
    [ testCase "decode private key file #1" $
        parseEither (parsePrivateKeyFile passphrase) ed25519PrivateKeyFile1' @=? Right ([] :: [(PrivateKey, BA.Bytes)])
    , testCase "decode private key file #2" $
        parseEither (parsePrivateKeyFile passphrase) ed25519PrivateKeyFile2' @=? Right ([] :: [(PrivateKey, BA.Bytes)])
    , testCase "decode private key file #3" $ testKeyFileParser ed25519PrivateKeyFile3
    ]

testKeyFileParser :: (BS.ByteString, [(PrivateKey, BS.ByteString)]) -> Assertion
testKeyFileParser (file, keys) = case parseEither (parsePrivateKeyFile passphrase) file of
    Left e -> assertFailure e
    Right keys'
        | length keys == length keys' -> zipWithM_ f keys keys'
        | otherwise -> assertFailure "wrong number of keys"
    where
        passphrase = "foobar" :: BS.ByteString
        f (Ed25519PrivateKey p0 s0, c0) (Ed25519PrivateKey p1 s1, c1) = do
            p0 @=? p1
            s0 @=? s1
            c0 @=? c1
        f _ _ = assertFailure "key type mismatch"

parseEither :: (BA.ByteArray ba) => BP.Parser ba a -> ba -> Either String a
parseEither parser = f . BP.parse parser
    where
        f (BP.ParseOK _ a) = Right a
        f (BP.ParseFail e) = Left e
        f (BP.ParseMore c) = f (c Nothing)

{-
ed25519PrivateKeyFile1 :: PrivateKeyFile
ed25519PrivateKeyFile1 = PrivateKeyFile"\176\189Ox\174EGx\195\DC4\159\219c\177\208\220\152J}\251\240\246\178\232\SOH\230^|p\249\194\240"
  { cipher     = "none"
  , kdf        = Nothing
  , publicKeys = [ Ed25519PublicKey $ case Ed25519.publicKey k of
                       CryptoPassed a -> a
                       CryptoFailed e -> error (show e)
                 ]
  , privateKeys = []
  }
  where
    k :: BS.ByteString
    k = "jri.\246\NAK\248\172\243\187\200-\247\246\225\218\206\250\145\SI\246\140\131(\234\255\135\177\b\161\128O"
-}

ed25519PrivateKeyFile1' :: BS.ByteString
ed25519PrivateKeyFile1'  = mconcat
  [ "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  , "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
  , "QyNTUxOQAAACBqcmku9hX4rPO7yC339uHazvqRD/aMgyjq/4exCKGATwAAAJjG8+5kxvPu\n"
  , "ZAAAAAtzc2gtZWQyNTUxOQAAACBqcmku9hX4rPO7yC339uHazvqRD/aMgyjq/4exCKGATw\n"
  , "AAAEBPNkrjYh+rbEcLJEX5w63fHuNLuiw9hJOrOaZRxGqDgWpyaS72Ffis87vILff24drO\n"
  , "+pEP9oyDKOr/h7EIoYBPAAAAE2xwZXRlcnNlbkBnYWxsaWZyZXkBAg==\n"
  , "-----END OPENSSH PRIVATE KEY-----\n"
  ]

ed25519PrivateKeyFile2' :: BS.ByteString
ed25519PrivateKeyFile2'  = mconcat
  [ "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  , "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDoZKFgIh\n"
  , "SZDqyG7Ql7NKPMAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBBKQsqWIjLy/hrm\n"
  , "CMuiPKlwpHtzHwHsdit/JFU9DCg4AAAAoCiYqeiXjicdeesCkF4mzwXSjX4vIuliAXKFFo\n"
  , "mf3McjjfrzM4nduswKftoQ6byGsBN8Spx+u5YJrrRAPbZA27npE42H4w1uj6hKpnDEdUMT\n"
  , "9tJA+1Md+PUP/9vs3hqtF8aTVVBeOPDalQJYqOCOVKhu7pHpKCXiK1AC3f1WAw5f+Oul18\n"
  , "CLBz4QYpty8pnO27U+dx8wr6kETJ9YX3L7p1A=\n"
  , "-----END OPENSSH PRIVATE KEY-----\n"
  ]

ed25519PrivateKeyFile3 :: (BS.ByteString, [(PrivateKey, BS.ByteString)])
ed25519PrivateKeyFile3 = (file, [(Ed25519PrivateKey public secret, "comment")])
    where
        file = mconcat
            [ "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            , "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD5G4pbe5\n"
            , "Cu7Ih7QIieGudEAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILC9T3iuRUd4wxSf\n"
            , "22Ox0NyYSn378Pay6AHmXnxw+cLwAAAAkKiDNwjUUzANV7bMOF4OP8/X9oP7F2qDqK+V9a\n"
            , "fSQKxcXviOmiKt4YLI4L/rPvfuaLMqwbwExrNS/pJMRclpgfR2TGwRYXWKyHOcDGJLHLyg\n"
            , "qUHIfaVjrlzYhlxrgLXI4hlTG5p0VTH/uMXEPi/vP+jfcL3+WrWjq40qfGPu3UnWD9Rx9r\n"
            , "mOKIl1w+TlqDKsSw==\n"
            , "-----END OPENSSH PRIVATE KEY-----\n"
            ]
        CryptoPassed public = Ed25519.publicKey
            ("\176\189Ox\174EGx\195\DC4\159\219c\177\208\220\152J}\251\240\246\178\232\SOH\230^|p\249\194\240" :: BS.ByteString)
        CryptoPassed secret = Ed25519.secretKey
            ("\191\149=\220c[\ETBp3\168\136\173~ \231\204}s\136T\230F\175Q\253p\162\145\a~\152=" :: BS.ByteString)

