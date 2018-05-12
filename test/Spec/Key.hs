{-# LANGUAGE OverloadedStrings #-}
module Spec.Key where

import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ByteString       as BS

import           Network.SSH.Key

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck as QC

testKey :: TestTree
testKey = testGroup "Network.SSH.Key"
  [ testEd25519Keys
  ]

testEd25519Keys :: TestTree
testEd25519Keys = testGroup "Ed25519"
  [ testCase "decode private key file #1" $
      decodePrivateKeyFile ed25519PrivateKeyFile1' @=? Right ed25519PrivateKeyFile1
  , testCase "decode private key file #2" $
      decodePrivateKeyFile ed25519PrivateKeyFile2' @=? Right ed25519PrivateKeyFile1
  ]

ed25519PrivateKeyFile1 :: PrivateKeyFile
ed25519PrivateKeyFile1 = PrivateKeyFile
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
