{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE FlexibleContexts           #-}
module Spec.TStreamingQueue ( tests ) where

import           Control.Monad.STM
import           Control.Concurrent.STM.TVar

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Internal

tests :: TestTree
tests = testGroup "Network.SSH.TStreamingQueue"
    [ test01
    , test02
    , test03
    , test04
    , test05
    ]

test01 :: TestTree
test01 = testCase "send 3 bytes, send 3 bytes, receive up to 6 bytes" $ do
    window <- newTVarIO 1000000
    q <- atomically $ newTStreamingQueue 10 window
    assertEqual "sent" 3 =<< atomically (enqueue q "ABC")
    assertEqual "sent" 3 =<< atomically (enqueue q "DEF")
    assertEqual "received" "ABCDEF" =<< atomically (dequeue q 6)

test02 :: TestTree
test02 = testCase "send 3 bytes, send 3 bytes, receive up to 7 bytes" $ do
    window <- newTVarIO 1000000
    q <- atomically $ newTStreamingQueue 10 window
    assertEqual "sent" 3 =<< atomically (enqueue q "ABC")
    assertEqual "sent" 3 =<< atomically (enqueue q "DEF")
    assertEqual "received" "ABCDEF" =<< atomically (dequeue q 7)

test03 :: TestTree
test03 = testCase "send 3 bytes, send eof, receive up to 7 bytes" $ do
    window <- newTVarIO 1000000
    q <- atomically $ newTStreamingQueue 10 window
    assertEqual "sent" 3 =<< atomically (enqueue q "ABC")
    atomically $ terminate q
    assertEqual "received" "ABC" =<< atomically (dequeue q 7)

test04 :: TestTree
test04 = testCase "send 0 bytes" $ do
    window <- newTVarIO 1000000
    q <- atomically $ newTStreamingQueue 10 window
    assertEqual "sent" 0 =<< atomically (enqueue q "")

test05 :: TestTree
test05 = testCase "send 4, receive 3, send 4, receive 3, sent eof, receive 3" $ do
    window <- newTVarIO 1000000
    q <- atomically $ newTStreamingQueue 10 window
    assertEqual "sent" 4 =<< atomically (enqueue q "1234")
    assertEqual "rcvd" "123" =<< atomically (dequeue q 3)
    assertEqual "sent" 4 =<< atomically (enqueue q "5678")
    assertEqual "rcvd" "456" =<< atomically (dequeue q 3)
    atomically $ terminate q
    assertEqual "rcvd" "78" =<< atomically (dequeue q 3)
