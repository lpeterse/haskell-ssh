{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE FlexibleContexts           #-}
module Spec.TWindowBuffer ( tests ) where

import           Control.Applicative
import           Control.Monad
import           Control.Monad.STM
import           Control.Concurrent.STM.TVar
import qualified Data.ByteString as BS

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.TWindowBuffer
import           Network.SSH.Stream

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.TWindowBuffer"
    [ testGroup "getSizeSTM"
        [ testGetSizeSTM01
        , testGetSizeSTM02
        ]
    , testGroup "getAvailableSTM"
        [ testGetAvailableSTM01
        , testGetAvailableSTM02
        , testGetAvailableSTM03
        , testGetAvailableSTM04
        ]
    , testGroup "getRecommendedWindowAdjustSTM" 
        [ testGetRecommendedWindowAdjustSTM01
        , testGetRecommendedWindowAdjustSTM02
        , testGetRecommendedWindowAdjustSTM03
        , testGetRecommendedWindowAdjustSTM04
        ]
    , testGroup "enqueueSTM"
        [ testEnqueueSTM01
        , testEnqueueSTM02
        , testEnqueueSTM03
        , testEnqueueSTM04
        , testEnqueueSTM05
        , testEnqueueSTM06
        , testEnqueueSTM07
        , testEnqueueSTM08
        , testEnqueueSTM09
        ]
    , testGroup "dequeueSTM"
        [ testDequeueSTM01
        , testDequeueSTM02
        , testDequeueSTM03
        , testDequeueSTM04
        , testDequeueSTM05
        , testDequeueSTM06
        , testDequeueSTM07
        ]
    ]

testGetSizeSTM01 :: TestTree
testGetSizeSTM01 = testCase "shall return 0 for empty buffer" do
    window <- newTVarIO 1000000
    q <- atomically $ newTWindowBufferSTM 10 window
    assertEqual "size" 0 =<< atomically (getSizeSTM q)

testGetSizeSTM02 :: TestTree
testGetSizeSTM02 = testCase "shall return n for non-empty buffer" do
    window <- newTVarIO 1000000
    q <- atomically $ newTWindowBufferSTM 10 window
    atomically $ enqueueSTM q "abc"
    assertEqual "size" 3 =<< atomically (getSizeSTM q)

testGetAvailableSTM01 :: TestTree
testGetAvailableSTM01 = testCase "shall return window for empty buffer when window < capacity" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    assertEqual "available" window =<< atomically (getAvailableSTM q)
    where
        window   = 123
        capacity = 456

testGetAvailableSTM02 :: TestTree
testGetAvailableSTM02 = testCase "shall return capacity for empty buffer when window > capacity" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    assertEqual "available" capacity =<< atomically (getAvailableSTM q)
    where
        window   = 456
        capacity = 123

testGetAvailableSTM03 :: TestTree
testGetAvailableSTM03 = testCase "shall return available capacity for non-empty buffer when window > capacity" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    atomically $ enqueueSTM q abc
    assertEqual "available" (capacity - fromIntegral (BS.length abc)) =<< atomically (getAvailableSTM q)
    where
        abc      = "ABC"
        window   = 456
        capacity = 123

testGetAvailableSTM04 :: TestTree
testGetAvailableSTM04 = testCase "shall return available window for non-empty buffer when window < capacity" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    atomically $ enqueueSTM q abc
    assertEqual "available" (window - 3) =<< atomically (getAvailableSTM q)
    where
        abc      = "ABC"
        window   = 123
        capacity = 456

testGetRecommendedWindowAdjustSTM01 :: TestTree
testGetRecommendedWindowAdjustSTM01 = testCase "shall block when window > 50% capacity" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    recommended <- atomically $ (getRecommendedWindowAdjustSTM q >> pure True) <|> pure False
    assertEqual "adjust recommended" False recommended
    where
        window   = 6
        capacity = 10

testGetRecommendedWindowAdjustSTM02 :: TestTree
testGetRecommendedWindowAdjustSTM02 = testCase "shall block when size > 50% capacity" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    atomically $ enqueueSTM q six
    recommended <- atomically $ (getRecommendedWindowAdjustSTM q >> pure True) <|> pure False
    assertEqual "adjust recommended" False recommended
    where
        six      = "123456"
        window   = 6
        capacity = 10

testGetRecommendedWindowAdjustSTM03 :: TestTree
testGetRecommendedWindowAdjustSTM03 = testCase "shall block when size and window <= 50% capacity but adjust would be too small" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    atomically $ enqueueSTM q six
    assertEqual "three" three =<< atomically (dequeueSTM q 3)
    assertEqual "available window" 4 =<< atomically (getAvailableWindowSTM q)
    assertEqual "available capacity" 7 =<< atomically (getAvailableCapacitySTM q)
    recommended <- atomically $ (getRecommendedWindowAdjustSTM q >> pure True) <|> pure False
    assertEqual "adjust recommended" False recommended
    where
        three    = "123"
        six      = "123456"
        window   = 10
        capacity = 10

testGetRecommendedWindowAdjustSTM04 :: TestTree
testGetRecommendedWindowAdjustSTM04 = testCase "shall recommend adjust when size + available window <= 50% capacity" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    atomically $ enqueueSTM q seven
    assertEqual "six" six =<< atomically (dequeueSTM q 6)
    assertEqual "size" 1 =<< atomically (getSizeSTM q)
    assertEqual "available window" 3 =<< atomically (getAvailableWindowSTM q)
    assertEqual "available capacity" 9 =<< atomically (getAvailableCapacitySTM q)
    assertEqual "adjust = capacity - size - window" 6 =<< atomically (getRecommendedWindowAdjustSTM q <|> pure 0)
    where
        six      = "123456"
        seven    = "1234567"
        window   = 10
        capacity = 10

testEnqueueSTM01 :: TestTree
testEnqueueSTM01 = testCase "shall increase size by data enqueued" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    atomically $ enqueueSTM q abc
    assertEqual "size" 3 =<< atomically (getSizeSTM q)
    where
        abc      = "ABC"
        window   = 10
        capacity = 10

testEnqueueSTM02 :: TestTree
testEnqueueSTM02 = testCase "shall decrease available capacity by data enqueued" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    atomically $ enqueueSTM q abc
    assertEqual "available capacity" 7 =<< atomically (getAvailableCapacitySTM q)
    where
        abc      = "ABC"
        window   = 9
        capacity = 10

testEnqueueSTM03 :: TestTree
testEnqueueSTM03 = testCase "shall decrease available window by data enqueued" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    atomically $ enqueueSTM q abc
    assertEqual "available window" 6 =<< atomically (getAvailableWindowSTM q)
    where
        abc      = "ABC"
        window   = 9
        capacity = 10

testEnqueueSTM04 :: TestTree
testEnqueueSTM04 = testCase "shall enqueue data in correct order" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    assertEqual "length ABC" 3 =<< atomically (enqueueSTM q abc)
    assertEqual "length DEF" 3 =<< atomically (enqueueSTM q def)
    assertEqual "dequeued" abcdef =<< atomically (dequeueSTM q 6)
    where
        abc      = "ABC"
        def      = "DEF"
        abcdef   = "ABCDEF"
        window   = 10
        capacity = 10

testEnqueueSTM05 :: TestTree
testEnqueueSTM05 = testCase "shall block when no window available" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    enqueued <- atomically $ (enqueueSTM q abc >> pure True) <|> pure False
    assertEqual "enqueued" False enqueued
    where
        abc      = "ABC"
        window   = 0
        capacity = 10

testEnqueueSTM06 :: TestTree
testEnqueueSTM06 = testCase "shall block when no capacity available" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    enq1 <- atomically $ (enqueueSTM q abc >> pure True) <|> pure False
    assertEqual "first enqueue" True enq1
    enq2 <- atomically $ (enqueueSTM q abc >> pure True) <|> pure False
    assertEqual "second enqueue" False enq2
    where
        abc      = "ABC"
        window   = 10
        capacity = 3

testEnqueueSTM07 :: TestTree
testEnqueueSTM07 = testCase "shall enqueue as many bytes as possible (window limit)" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    enq1 <- atomically $ enqueueSTM q abc <|> pure 0
    assertEqual "first enqueue" 3 enq1
    enq2 <- atomically $ enqueueSTM q abc <|> pure 0
    assertEqual "second enqueue" 1 enq2
    where
        abc      = "ABC"
        window   = 4
        capacity = 10

testEnqueueSTM08 :: TestTree
testEnqueueSTM08 = testCase "shall enqueue as many bytes as possible (capacity limit)" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    enq1 <- atomically $ enqueueSTM q abc <|> pure 0
    assertEqual "first enqueue" 3 enq1
    enq2 <- atomically $ enqueueSTM q abc <|> pure 0
    assertEqual "second enqueue" 1 enq2
    where
        abc      = "ABC"
        window   = 10
        capacity = 4

testEnqueueSTM09 :: TestTree
testEnqueueSTM09 = testCase "shall throw exception after eof" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    atomically $ sendEofSTM q
    assertThrows "exception" TWindowBufferWriteAfterEof
        $ atomically $ void $ enqueueSTM q abc <|> pure 0
    where
        abc      = "ABC"
        window   = 10
        capacity = 10

testDequeueSTM01 :: TestTree
testDequeueSTM01 = testCase "shall dequeue previously enqueued bytes" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    void $ atomically $ enqueueSTM q abc <|> pure 0
    assertEqual "dequeued" ab =<< atomically (dequeueSTM q 2)
    where
        ab       = "AB"
        abc      = "ABC"
        window   = 10
        capacity = 10

testDequeueSTM02 :: TestTree
testDequeueSTM02 = testCase "shall decrease size by bytes dequeued" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    void $ atomically $ enqueueSTM q abc <|> pure 0
    assertEqual "dequeued" ab =<< atomically (dequeueSTM q 2)
    assertEqual "size" 1 =<< atomically (getSizeSTM q)
    where
        ab       = "AB"
        abc      = "ABC"
        window   = 10
        capacity = 10

testDequeueSTM03 :: TestTree
testDequeueSTM03 = testCase "shall dequeue as many bytes as available" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    void $ atomically $ enqueueSTM q abc <|> pure 0
    assertEqual "dequeued" abc =<< atomically (dequeueSTM q 4)
    where
        abc      = "ABC"
        window   = 10
        capacity = 10

testDequeueSTM04 :: TestTree
testDequeueSTM04 = testCase "shall concatenate several chunks previously enqueued" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    void $ atomically $ enqueueSTM q abc <|> pure 0
    void $ atomically $ enqueueSTM q def <|> pure 0
    assertEqual "dequeued" (abc <> def) =<< atomically (dequeueSTM q 7)
    where
        abc      = "ABC"
        def      = "DEF"
        window   = 10
        capacity = 10

testDequeueSTM05 :: TestTree
testDequeueSTM05 = testCase "shall not respect chunk boundaries" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    void $ atomically $ enqueueSTM q "ABC" <|> pure 0
    void $ atomically $ enqueueSTM q "DEF" <|> pure 0
    assertEqual "dequeued (1)" "AB" =<< atomically (dequeueSTM q 2)
    assertEqual "dequeued (2)" "CD" =<< atomically (dequeueSTM q 2)
    void $ atomically $ enqueueSTM q "H" <|> pure 0
    void $ atomically $ enqueueSTM q "I" <|> pure 0
    void $ atomically $ enqueueSTM q "J" <|> pure 0
    assertEqual "dequeued (3)" "EFH" =<< atomically (dequeueSTM q 3)
    assertEqual "dequeued (4)" "IJ" =<< atomically (dequeueSTM q 5)
    where
        window   = 10
        capacity = 10

testDequeueSTM06 :: TestTree
testDequeueSTM06 = testCase "shall block when no bytes available" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    assertEqual "blocked (1)" True =<< atomically ((dequeueSTM q 5 >> pure False) <|> pure True)
    void $ atomically $ enqueueSTM q "ABC" <|> pure 0
    assertEqual "blocked (2)" False =<< atomically ((dequeueSTM q 5 >> pure False) <|> pure True)
    where
        window   = 10
        capacity = 10

testDequeueSTM07 :: TestTree
testDequeueSTM07 = testCase "shall return empty string after eof" do
    tWindow <- newTVarIO window
    q <- atomically $ newTWindowBufferSTM capacity tWindow
    void $ atomically $ enqueueSTM q "ABC" <|> pure 0
    void $ atomically $ sendEofSTM q
    assertEqual "dequeued (1)" "AB" =<< atomically (dequeueSTM q 2)
    assertEqual "dequeued (2)" "C" =<< atomically (dequeueSTM q 2)
    assertEqual "dequeued (3)" "" =<< atomically (dequeueSTM q 2)
    where
        window   = 10
        capacity = 10
