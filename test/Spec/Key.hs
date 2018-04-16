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
  [ testCase "decode private key format" $
      (decodePrivateKey ed25519PublicKeyByteString :: Maybe (PrivateKey Ed25519)) @=? Nothing
  ]

ed25519PublicKeyByteString :: BS.ByteString
ed25519PublicKeyByteString  = mconcat
  [ "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  , "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
  , "QyNTUxOQAAACBqcmku9hX4rPO7yC339uHazvqRD/aMgyjq/4exCKGATwAAAJjG8+5kxvPu\n"
  , "ZAAAAAtzc2gtZWQyNTUxOQAAACBqcmku9hX4rPO7yC339uHazvqRD/aMgyjq/4exCKGATw\n"
  , "AAAEBPNkrjYh+rbEcLJEX5w63fHuNLuiw9hJOrOaZRxGqDgWpyaS72Ffis87vILff24drO\n"
  , "+pEP9oyDKOr/h7EIoYBPAAAAE2xwZXRlcnNlbkBnYWxsaWZyZXkBAg==\n"
  , "-----END OPENSSH PRIVATE KEY-----\n"
  ]
