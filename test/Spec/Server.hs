{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE LambdaCase                 #-}
module Spec.Server ( tests ) where

import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Server
import           Network.SSH.Stream
import           Network.SSH.Constants
import           Network.SSH.Message
import           Network.SSH.Server.Config

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Server"
    [ testServe01
    , testServe02
    ]

testServe01 :: TestTree
testServe01 = testCase "server exit on invalid client version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    config <- newDefaultConfig
    withAsync (serve config serverSocket `finally` close serverSocket) $ \server -> do
        void $ sendAll clientSocket "GET / HTTP/1.1\n\n"
        assertEqual "server response" mempty =<< receive clientSocket 1024
        waitCatch server >>= \case
            Right () -> assertFailure "should have failed"
            Left e 
                | fromException e == Just exp0 -> pure ()
                | otherwise -> assertFailure "wrong exception"
    
    where
        exp0 = Disconnect DisconnectProtocolVersionNotSupported mempty mempty

testServe02 :: TestTree
testServe02 = testCase "server sends version string after client version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    config <- newDefaultConfig
    withAsync (serve config serverSocket `finally` close serverSocket) $ \server -> do
        void $ sendAll clientSocket "SSH-2.0-OpenSSH_4.3\r\n"
        assertEqual "server response" (v <> "\r\n") =<< receive clientSocket 1024
    where
        Version v = version
