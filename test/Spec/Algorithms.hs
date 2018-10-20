{-# LANGUAGE OverloadedStrings          #-}
module Spec.Algorithms ( tests ) where

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Algorithms

tests :: TestTree
tests = testGroup "Network.SSH.Algorithms"
    [ testGroup "HostKeyAlgorithm"
        [ testHostKeyAlgorithm01
        , testHostKeyAlgorithm02
        , testHostKeyAlgorithm03
        ]
    , testGroup "KeyExchangeAlgorithm"
        [ testKeyExchangeAlgorithm01
        , testKeyExchangeAlgorithm02
        , testKeyExchangeAlgorithm03
        ]
    , testGroup "EncryptionAlgorithm"
        [ testEncryptionAlgorithm01
        , testEncryptionAlgorithm02
        , testEncryptionAlgorithm03
        ]
    , testGroup "CompressionAlgorithm"
        [ testCompressionAlgorithm01
        , testCompressionAlgorithm02
        , testCompressionAlgorithm03
        ]
    ]

testHostKeyAlgorithm01 :: TestTree
testHostKeyAlgorithm01 = testCase "Eq" $
    assertEqual "==" SshEd25519 SshEd25519

testHostKeyAlgorithm02 :: TestTree
testHostKeyAlgorithm02 = testCase "Show" $
    assertEqual "show" "SshEd25519" (show SshEd25519)

testHostKeyAlgorithm03 :: TestTree
testHostKeyAlgorithm03 = testCase "AlgorithmName" $
    assertEqual "algorithmName" "ssh-ed25519" (algorithmName SshEd25519)

testKeyExchangeAlgorithm01 :: TestTree
testKeyExchangeAlgorithm01 = testCase "Eq" $
    assertEqual "==" Curve25519Sha256AtLibsshDotOrg Curve25519Sha256AtLibsshDotOrg

testKeyExchangeAlgorithm02 :: TestTree
testKeyExchangeAlgorithm02 = testCase "Show" $
    assertEqual "show" "Curve25519Sha256AtLibsshDotOrg" (show Curve25519Sha256AtLibsshDotOrg)

testKeyExchangeAlgorithm03 :: TestTree
testKeyExchangeAlgorithm03 = testCase "AlgorithmName" $
    assertEqual "algorithmName" "curve25519-sha256@libssh.org" (algorithmName Curve25519Sha256AtLibsshDotOrg)

testEncryptionAlgorithm01 :: TestTree
testEncryptionAlgorithm01 = testCase "Eq" $
    assertEqual "==" Chacha20Poly1305AtOpensshDotCom Chacha20Poly1305AtOpensshDotCom

testEncryptionAlgorithm02 :: TestTree
testEncryptionAlgorithm02 = testCase "Show" $
    assertEqual "show" "Chacha20Poly1305AtOpensshDotCom" (show Chacha20Poly1305AtOpensshDotCom)

testEncryptionAlgorithm03 :: TestTree
testEncryptionAlgorithm03 = testCase "AlgorithmName" $
    assertEqual "algorithmName" "chacha20-poly1305@openssh.com" (algorithmName Chacha20Poly1305AtOpensshDotCom)

testCompressionAlgorithm01 :: TestTree
testCompressionAlgorithm01 = testCase "Eq" $
    assertEqual "==" None None

testCompressionAlgorithm02 :: TestTree
testCompressionAlgorithm02 = testCase "Show" $
    assertEqual "show" "None" (show None)

testCompressionAlgorithm03 :: TestTree
testCompressionAlgorithm03 = testCase "AlgorithmName" $
    assertEqual "algorithmName" "none" (algorithmName None)
