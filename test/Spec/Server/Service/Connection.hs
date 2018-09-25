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
        , connectionChannelOpen05
        ]
    
    , testGroup "connectionChannelRequest"
        [ connectionChannelRequest01
        , connectionChannelRequest02
        , connectionChannelRequest03
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
        lid2 = lid0
        rid0 = ChannelId 0
        rid1 = ChannelId 1
        rid2 = ChannelId 2
        rws = 123
        rps = 456
        send = error "shall not send"
        identity = error "shall not use identity"

connectionChannelOpen05 :: TestTree
connectionChannelOpen05 = testCase "open unknown channel type" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf identity send
    Left (ChannelOpenFailure rid' reason _ _) <- connectionChannelOpen conn (ChannelOpen ct rid rws rps)
    assertEqual "remote channel id" rid rid'
    assertEqual "failure reason" ChannelOpenUnknownChannelType reason
    where
        ct  = ChannelType "unknown"
        rid = ChannelId 45
        rws = 123
        rps = 456
        send = error "shall not send"
        identity = error "shall not use identity"

connectionChannelRequest01 :: TestTree
connectionChannelRequest01 = testCase "request for non-existing channel" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf identity send
    connectionChannelRequest conn (ChannelRequest rid undefined)
        `assertException` \(Disconnect reason _ _) ->
            DisconnectProtocolError @=? reason
    where
        rid = ChannelId 23
        send = error "shall not send"
        identity = error "shall not use identity"

connectionChannelRequest02 :: TestTree
connectionChannelRequest02 = testCase "syntactically invalid request" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf identity send
    Right (ChannelOpenConfirmation _ lid _ _) <- connectionChannelOpen conn (ChannelOpen ct rid rws rps)
    connectionChannelRequest conn (ChannelRequest lid "")
        `assertException` \(Disconnect reason description _) -> do
            DisconnectProtocolError @=? reason
            "invalid session channel request" @=? description
    where
        ct  = ChannelType "session"
        rid = ChannelId 23
        rws = 123
        rps = 456
        send = error "shall not send"
        identity = error "shall not use identity"

connectionChannelRequest03 :: TestTree
connectionChannelRequest03 = testCase "session environment request" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf identity send
    Right (ChannelOpenConfirmation _ lid _ _) <- connectionChannelOpen conn (ChannelOpen ct rid rws rps)
    Nothing <- connectionChannelRequest conn (ChannelRequest lid "\NUL\NUL\NUL\ETXenv\NUL\NUL\NUL\NUL\ACKLC_ALL\NUL\NUL\NUL\ven_US.UTF-8")
    pure ()
    where
        ct  = ChannelType "session"
        rid = ChannelId 23
        rws = 123
        rps = 456
        send = error "shall not send"
        identity = error "shall not use identity"

assertException :: Exception e => IO a -> (e -> Assertion) -> Assertion
assertException action checkException = (action >> assertFailure "should have thrown") `catch` checkException
