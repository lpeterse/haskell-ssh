{-# LANGUAGE OverloadedStrings #-}
module Spec.Client.Connection ( tests ) where

import           Control.Concurrent          ( threadDelay )
import           Control.Concurrent.Async
import           Control.Exception           ( AssertionFailed (..), throw, throwIO )
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.ByteString          as BS
import           Data.Default
import           System.Exit

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Client
import           Network.SSH.Internal

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Client.Connection"
    [ testGroup "withConnection"
        [ testWithConnection01
        , testWithConnection02
        , testWithConnection03
        ]
    ]

testWithConnection01 :: TestTree
testWithConnection01 = testCase "shall return handler return value" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    n' <- withConnection def clientStream $ \c -> do
        pure n
    assertEqual "return value" n n'
    where
        n = 123

testWithConnection02 :: TestTree
testWithConnection02 = testCase "shall re-throw exception when receiver thread throws exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "exp" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream (ChannelClose $ throw exp)
        threadDelay 1000000 -- wait here for exception
    where
        exp = ExitFailure 1

testWithConnection03 :: TestTree
testWithConnection03 = testCase "shall re-throw exception when handler thread throws exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "exp" exp $ withConnection def clientStream $ \c -> do
        throwIO exp
    where
        exp = ExitFailure 1
