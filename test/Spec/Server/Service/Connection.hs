{-# LANGUAGE OverloadedStrings, FlexibleInstances, LambdaCase #-}
module Spec.Server.Service.Connection ( tests ) where
    
import           Control.Concurrent.MVar
import qualified Data.ByteString as BS
import           Control.Exception
import           Control.Monad

import           Network.SSH.Server.Service.Connection
import           Network.SSH.Message
import           Network.SSH.Server.Config

import           Test.Tasty
import           Test.Tasty.HUnit

tests :: TestTree
tests = testGroup "Network.SSH.Server.Service.Connection"
    [ testCase "connectionOpen yields open connection" $ do
        c <- connectionOpen undefined undefined undefined
        assertBool "connection closed state" . not =<< connectionClosed c

    , testCase "connectionClose closes connection" $ do
        c <- connectionOpen undefined undefined undefined
        connectionClose c
        assertBool "connection closed state" =<< connectionClosed c
    
    , testGroup "connectionChannelOpen"
        [ connectionChannelOpen01
        , connectionChannelOpen02
        , connectionChannelOpen03
        , connectionChannelOpen04
        ]
    ]

connectionChannelOpen01 :: TestTree
connectionChannelOpen01 = testCase "open one channel" $ do
    c <- newDefaultConfig
    let config = c { channelMaxWindowSize = lws, channelMaxPacketSize = lps }
    conn <- connectionOpen config identity send
    Right (ChannelOpenConfirmation rid' lid' lws' lps') <- connectionChannelOpen conn (ChannelOpen ct rid rws rps)
    assertEqual "remote channel id" rid rid'
    assertEqual "local channel id" lid lid'
    assertEqual "local max window size" lws lws'
    assertEqual "local max packet size" lps lps'
    where
        ct  = ChannelType "session"
        lid = ChannelId 0
        rid = ChannelId 1
        lws = 256 * 1024
        lps = 32 * 1024
        rws = 123
        rps = 456
        send = error "shall not send"
        identity = error "shall not use identity"

connectionChannelOpen02 :: TestTree
connectionChannelOpen02 = testCase "exceed channel limit" $ do
    c <- newDefaultConfig
    let config = c { channelMaxCount = 1 }
    conn <- connectionOpen config identity send
    Right (ChannelOpenConfirmation rid0' _ _ _) <- connectionChannelOpen conn (ChannelOpen ct rid0 rws rps)
    Left (ChannelOpenFailure rid1' reason _ _) <- connectionChannelOpen conn (ChannelOpen ct rid1 rws rps)
    assertEqual "remote channel id (first)" rid0 rid0'
    assertEqual "remote channel id (second)" rid1 rid1'
    assertEqual "failure reason" ChannelOpenResourceShortage reason
    where
        ct  = ChannelType "session"
        rid0 = ChannelId 0
        rid1 = ChannelId 1
        rws = 123
        rps = 456
        send = error "shall not send"
        identity = error "shall not use identity"

connectionChannelOpen03 :: TestTree
connectionChannelOpen03 = testCase "open two channels" $ do
    c <- newDefaultConfig
    let config = c { channelMaxCount = 2 }
    conn <- connectionOpen config identity send
    Right (ChannelOpenConfirmation rid0' lid0' _ _) <- connectionChannelOpen conn (ChannelOpen ct rid0 rws rps)
    Right (ChannelOpenConfirmation rid1' lid1' _ _) <- connectionChannelOpen conn (ChannelOpen ct rid1 rws rps)
    assertEqual "remote channel id (first)" rid0 rid0'
    assertEqual "remote channel id (second)" rid1 rid1'
    assertEqual "local channel id (first)" lid0 lid0'
    assertEqual "local channel id (second)" lid1 lid1'
    where
        ct  = ChannelType "session"
        lid0 = ChannelId 0
        lid1 = ChannelId 1
        rid0 = ChannelId 0
        rid1 = ChannelId 1
        rws = 123
        rps = 456
        send = error "shall not send"
        identity = error "shall not use identity"

connectionChannelOpen04 :: TestTree
connectionChannelOpen04 = testCase "open two channels, close first, reuse first" $ do
    c <- newDefaultConfig
    let config = c { channelMaxCount = 2 }
    conn <- connectionOpen config identity send
    Right (ChannelOpenConfirmation _ lid0' _ _) <- connectionChannelOpen conn (ChannelOpen ct rid0 rws rps)
    Right (ChannelOpenConfirmation _ lid1' _ _) <- connectionChannelOpen conn (ChannelOpen ct rid1 rws rps)
    assertEqual "local channel id (first)" lid0 lid0'
    assertEqual "local channel id (second)" lid1 lid1'
    connectionChannelClose conn (ChannelClose lid0')
    Right (ChannelOpenConfirmation _ lid2' _ _) <- connectionChannelOpen conn (ChannelOpen ct rid2 rws rps)
    assertEqual "local channel id (third)" lid2 lid2'
    where
        ct  = ChannelType "session"
        lid0 = ChannelId 0
        lid1 = ChannelId 1
        lid2 = ChannelId 0
        rid0 = ChannelId 0
        rid1 = ChannelId 1
        rid2 = ChannelId 2
        rws = 123
        rps = 456
        send = error "shall not send"
        identity = error "shall not use identity"

assertThrowsExact :: (Exception e, Eq e) => e -> IO a -> Assertion
assertThrowsExact e action = (action >> assertFailure "should have thrown") `catch` \e'-> when (e /= e') (throwIO e')
