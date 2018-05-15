{-# LANGUAGE OverloadedStrings #-}
module Spec.Key ( tests ) where

import           Control.Monad         (when, zipWithM_)
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ByteArray        as BA
import qualified Data.ByteArray.Parse  as BP
import qualified Data.ByteString       as BS

import           Network.SSH.Key

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck as QC

tests :: TestTree
tests = testGroup "Network.SSH.Key"
  [ testDecodePrivateKeyFile
  ]

testDecodePrivateKeyFile :: TestTree
testDecodePrivateKeyFile = testGroup "decodePrivateKeyFile"
    [ testCase "none, none, ed25519" $
        testKeyFileParser unencryptedEd25519PrivateKeyFile
    , testCase "bcrypt, aes256-cbc, ed25519" $
        testKeyFileParser bcryptAes256CbcEd25519PrivateKeyFile
    , testCase "bcrypt, aes256-ctr, ed25519" $
        testKeyFileParser bcryptAes256CtrEd25519PrivateKeyFile
    ]

testKeyFileParser :: (BS.ByteString, BS.ByteString, [(Key, BS.ByteString)]) -> Assertion
testKeyFileParser (file, passphrase, keys) = do
    keys' <- decodePrivateKeyFile passphrase file
    when (length keys /= length keys') (assertFailure "wrong number of keys")
    zipWithM_ f keys keys'
    where
        f (Ed25519Key p0 s0, c0) (Ed25519Key p1 s1, c1) = do
            c0 @=? c1
            p0 @=? p1
            s0 @=? s1
        f _ _ = assertFailure "key type mismatch"

unencryptedEd25519PrivateKeyFile :: (BS.ByteString, BS.ByteString, [(Key, BS.ByteString)])
unencryptedEd25519PrivateKeyFile = (file, passphrase, [(Ed25519Key public secret, "lpetersen@gallifrey")])
    where
        file = mconcat
            [ "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            , "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
            , "QyNTUxOQAAACBqcmku9hX4rPO7yC339uHazvqRD/aMgyjq/4exCKGATwAAAJjG8+5kxvPu\n"
            , "ZAAAAAtzc2gtZWQyNTUxOQAAACBqcmku9hX4rPO7yC339uHazvqRD/aMgyjq/4exCKGATw\n"
            , "AAAEBPNkrjYh+rbEcLJEX5w63fHuNLuiw9hJOrOaZRxGqDgWpyaS72Ffis87vILff24drO\n"
            , "+pEP9oyDKOr/h7EIoYBPAAAAE2xwZXRlcnNlbkBnYWxsaWZyZXkBAg==\n"
            , "-----END OPENSSH PRIVATE KEY-----\n"
            ]
        passphrase = ""
        CryptoPassed public = Ed25519.publicKey
            ("jri.\246\NAK\248\172\243\187\200-\247\246\225\218\206\250\145\SI\246\140\131(\234\255\135\177\b\161\128O" :: BS.ByteString)
        CryptoPassed secret = Ed25519.secretKey
            ("O6J\227b\US\171lG\v$E\249\195\173\223\RS\227K\186,=\132\147\171\&9\166Q\196j\131\129" :: BS.ByteString)

bcryptAes256CbcEd25519PrivateKeyFile :: (BS.ByteString, BS.ByteString, [(Key, BS.ByteString)])
bcryptAes256CbcEd25519PrivateKeyFile = (file, passphrase, [(Ed25519Key public secret, "comment1234")])
    where
        file = mconcat
            [ "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            , "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDTDrNhkD\n"
            , "C7tfLO0v9m/nKAAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIN/nNM4GQNcrKZv8\n"
            , "MkQ+oGPejLoeKwLqNobcoa1qiUSMAAAAkOeGAujVwOa7cGA/oHLDdCsGfpv1Mwh89GlPLE\n"
            , "OKztJLfh9htiGRpX3q5xkTvn+8KDIuB8ZO9G2YzVV3AD2Z40foUrgo6glZeLSxXBRDpOKA\n"
            , "qcaKRNOJ0iARTiaeLL3Dcmi3nEk07ZpAvlFuEKBuNkmgscooThDMBSzOHFcvMsWOW09zUY\n"
            , "duwiqJ+kj5LYPRzA==\n"
            , "-----END OPENSSH PRIVATE KEY-----\n"
            ]
        passphrase = "passphrase"
        CryptoPassed public = Ed25519.publicKey
            ("\223\231\&4\206\ACK@\215+)\155\252\&2D>\160c\222\140\186\RS+\STX\234\&6\134\220\161\173j\137D\140" :: BS.ByteString)
        CryptoPassed secret = Ed25519.secretKey
            ("\221\209\ETB\224\"M\133\169z\215H\158\DEL\134\&2n\155,q\227\229\251\183A+}\DC4qU\156\209n" :: BS.ByteString)

bcryptAes256CtrEd25519PrivateKeyFile :: (BS.ByteString, BS.ByteString, [(Key, BS.ByteString)])
bcryptAes256CtrEd25519PrivateKeyFile = (file, passphrase, [(Ed25519Key public secret, "comment")])
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
        passphrase = "foobar"
        CryptoPassed public = Ed25519.publicKey
            ("\176\189Ox\174EGx\195\DC4\159\219c\177\208\220\152J}\251\240\246\178\232\SOH\230^|p\249\194\240" :: BS.ByteString)
        CryptoPassed secret = Ed25519.secretKey
            ("\191\149=\220c[\ETBp3\168\136\173~ \231\204}s\136T\230F\175Q\253p\162\145\a~\152=" :: BS.ByteString)

