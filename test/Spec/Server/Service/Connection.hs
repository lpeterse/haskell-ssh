{-# LANGUAGE OverloadedStrings #-}
module Spec.Server.Service.Connection ( tests ) where
    
import           Control.Applicative
import           Control.Concurrent (threadDelay)
import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad
import           System.Exit
import           Control.Monad.STM
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar

import           Network.SSH.Server.Service.Connection
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Internal
import           Network.SSH.Stream (send, sendAll, receive)

import           Test.Tasty
import           Test.Tasty.HUnit

tests :: TestTree
tests = testGroup "Network.SSH.Server.Service.Connection"
    [ testGroup "dispatcher"
        [ dispatcher01
        , dispatcher02
        , dispatcher03
        , dispatcher04
        , dispatcher05
        , dispatcher06
        , dispatcher07
        ]
    , testGroup "connectionChannelOpen"
        [ connectionChannelOpen01
        , connectionChannelOpen02
        , connectionChannelOpen03
        , connectionChannelOpen04
        , connectionChannelOpen05
        ]
    , testGroup "connectionChannelClose"
        [ connectionChannelClose01
        , connectionChannelClose02
        , connectionChannelClose03
        ]
    , testGroup "connectionChannelRequest"
        [ connectionChannelRequest01
        , connectionChannelRequest02
        , connectionChannelRequest03
        , testGroup "env requests"
            [ connectionChannelRequestEnv01
            ]
        , testGroup "pty requests"
            [ connectionChannelRequestPty01
            , connectionChannelRequestPty02
            ]
        , testGroup "shell requests"
            [ connectionChannelRequestShell01
            , connectionChannelRequestShell02
            , connectionChannelRequestShell03
            , connectionChannelRequestShell04
            , connectionChannelRequestShell05
            , connectionChannelRequestShell06
            , connectionChannelRequestShell07
            , connectionChannelRequestShell08
            , connectionChannelRequestShell09
            ]
        , testGroup "exec requests"
            [ connectionChannelRequestExec01
            , connectionChannelRequestExec02
            ]
        ]
    , testGroup "connectionChannelData"
        [ connectionChannelData01
        , connectionChannelData02
        , connectionChannelData03
        , connectionChannelData04
        , connectionChannelData05
        ]

    , testGroup "connectionChannelWindowAdjust"
        [ connectionChannelWindowAdjust01
        , connectionChannelWindowAdjust02
        ]
    ]

dispatcher01 :: TestTree
dispatcher01 = testCase "MsgChannelOpen" $ do
    chan <- newTChanIO
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ readTChan chan
    conf <- newDefaultConfig
    dispatcher conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } sender () msg0 $
        Continuation $ \continue-> do
            assertEqual "msg1" msg1 =<< receiver
            continue msg2 $ Continuation $ \_ ->
                assertEqual "msg3" msg3 =<< receiver
    where
        lid = ChannelId 0
        rid = ChannelId 1
        lws = 1
        lps = 2
        rws = 3
        rps = 4
        msg0 = MsgChannelOpen (ChannelOpen (ChannelType "foobar") rid rws rps)
        msg1 = MsgChannelOpenFailure (ChannelOpenFailure rid ChannelOpenUnknownChannelType mempty mempty)
        msg2 = MsgChannelOpen (ChannelOpen (ChannelType "session") rid rws rps)
        msg3 = MsgChannelOpenConfirmation (ChannelOpenConfirmation rid lid lws lps)

dispatcher02 :: TestTree
dispatcher02 = testCase "MsgChannelClose" $ do
    chan <- newTChanIO
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ readTChan chan
    conf <- newDefaultConfig
    dispatcher conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } sender () msg0 $
        Continuation $ \continue-> do
            assertEqual "msg1" msg1 =<< receiver
            continue msg2 $ Continuation $ \_ ->
                assertEqual "msg3" msg3 =<< receiver
    where
        lid = ChannelId 0
        rid = ChannelId 1
        lws = 1
        lps = 2
        rws = 3
        rps = 4
        msg0 = MsgChannelOpen (ChannelOpen (ChannelType "session") rid rws rps)
        msg1 = MsgChannelOpenConfirmation (ChannelOpenConfirmation rid lid lws lps)
        msg2 = MsgChannelClose (ChannelClose lid)
        msg3 = MsgChannelClose (ChannelClose rid)

dispatcher03 :: TestTree
dispatcher03 = testCase "MsgChannelEof" $ do
    chan <- newTChanIO
    allDone <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ readTChan chan
    conf <- newDefaultConfig
    dispatcher conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } sender () msg0 $
        Continuation $ \continue-> do
            assertEqual "msg1" msg1 =<< receiver
            continue msg2 $ Continuation $ \_ ->
                atomically $ writeTVar allDone True
    assertEqual "allDone" True =<< readTVarIO allDone
    where
        lid = ChannelId 0
        rid = ChannelId 1
        lws = 1
        lps = 2
        rws = 3
        rps = 4
        msg0 = MsgChannelOpen (ChannelOpen (ChannelType "session") rid rws rps)
        msg1 = MsgChannelOpenConfirmation (ChannelOpenConfirmation rid lid lws lps)
        msg2 = MsgChannelEof (ChannelEof lid)

dispatcher04 :: TestTree
dispatcher04 = testCase "MsgChannelRequest" $ do
    chan <- newTChanIO
    tmvar <- newEmptyTMVarIO
    allDone <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let handler (Session idnt _ _ _ stdout _) = do
            send stdout "A"
            atomically (putTMVar tmvar idnt)
            pure ExitSuccess 
    conf <- newDefaultConfig
    dispatcher conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onShellRequest = Just handler } sender idnt req0 $
        Continuation $ \continue0-> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ \continue1 -> do
                assertEqual "res1" res1 =<< receiver
                continue1 req2 $ Continuation $ \continue2 -> do
                    assertEqual "res2" res2 =<< receiver
                    continue1 req3 $ Continuation $ \continue3 -> do
                        assertEqual "res3" res3 =<< receiver
                        continue1 req4 $ Continuation $ \continue4 -> do
                            assertEqual "res4" res4 =<< receiver
                            assertEqual "idnt" idnt =<< atomically (readTMVar tmvar)
                            atomically $ writeTVar allDone True
    assertEqual "allDone" True =<< readTVarIO allDone
    where
        lid = ChannelId 0
        rid = ChannelId 1
        lws = 1
        lps = 2
        rws = 3
        rps = 4
        idnt = "identity" :: String
        req0 = MsgChannelOpen (ChannelOpen (ChannelType "session") rid rws rps)
        res0 = Just $ MsgChannelOpenConfirmation (ChannelOpenConfirmation rid lid lws lps)
        req1 = MsgChannelRequest (ChannelRequest lid "env" True "\NUL\NUL\NUL\ACKLC_ALL\NUL\NUL\NUL\ven_US.UTF-8")
        res1 = Just $ MsgChannelSuccess (ChannelSuccess rid)
        req2 = MsgChannelRequest (ChannelRequest lid "env" False "\NUL\NUL\NUL\ACKLC_ALL\NUL\NUL\NUL\ven_US.UTF-8")
        res2 = Nothing
        req3 = MsgChannelRequest (ChannelRequest lid "---" True mempty)
        res3 = Just $ MsgChannelFailure (ChannelFailure rid)
        req4 = MsgChannelRequest (ChannelRequest lid "shell" True mempty)
        res4 = Just $ MsgChannelSuccess (ChannelSuccess rid)

dispatcher05 :: TestTree
dispatcher05 = testCase "MsgChannelData" $ do
    chan <- newTChanIO
    allDone <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    conf <- newDefaultConfig
    dispatcher conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } sender () req0 $
        Continuation $ \continue0-> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ \continue1 -> do
                assertEqual "res1" res1 =<< receiver
                atomically $ writeTVar allDone True
    assertEqual "allDone" True =<< readTVarIO allDone
    where
        lid = ChannelId 0
        rid = ChannelId 1
        lws = 1
        lps = 2
        rws = 3
        rps = 4
        req0 = MsgChannelOpen (ChannelOpen (ChannelType "session") rid rws rps)
        res0 = Just $ MsgChannelOpenConfirmation (ChannelOpenConfirmation rid lid lws lps)
        req1 = MsgChannelData (ChannelData lid "A")
        res1 = Nothing

dispatcher06 :: TestTree
dispatcher06 = testCase "MsgChannelWindowAdjust" $ do
    chan <- newTChanIO
    allDone <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    conf <- newDefaultConfig
    dispatcher conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } sender () req0 $
        Continuation $ \continue0-> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ \continue1 -> do
                assertEqual "res1" res1 =<< receiver
                atomically $ writeTVar allDone True
    assertEqual "allDone" True =<< readTVarIO allDone
    where
        lid = ChannelId 0
        rid = ChannelId 1
        lws = 1
        lps = 2
        rws = 3
        rps = 4
        req0 = MsgChannelOpen (ChannelOpen (ChannelType "session") rid rws rps)
        res0 = Just $ MsgChannelOpenConfirmation (ChannelOpenConfirmation rid lid lws lps)
        req1 = MsgChannelWindowAdjust (ChannelWindowAdjust lid 123)
        res1 = Nothing

dispatcher07 :: TestTree
dispatcher07 = testCase "other messages" $ do
    chan <- newTChanIO
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    conf <- newDefaultConfig
    assertThrows "exp0" exp0 $ dispatcher conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } sender () req0 $
        Continuation $ const $ pure ()
    where
        lid = ChannelId 0
        rid = ChannelId 1
        lws = 1
        lps = 2
        rws = 3
        rps = 4
        req0 = MsgUnknown 0
        exp0 = Disconnect DisconnectProtocolError "unexpected message type (connection module)" mempty

connectionChannelOpen01 :: TestTree
connectionChannelOpen01 = testCase "open one channel" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    where
        lid = ChannelId 0
        rid = ChannelId 1
        lws = 256 * 1024
        lps = 32 * 1024
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)

connectionChannelOpen02 :: TestTree
connectionChannelOpen02 = testCase "exceed channel limit" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxCount = 1, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn0
    assertEqual "msg1" msg1 =<< connectionChannelOpen conn opn1
    where
        rid0 = ChannelId 0
        lid0 = ChannelId 0
        rid1 = ChannelId 1
        rws  = 124
        rps  = 456
        lws  = 128
        lps  = 32
        opn0 = ChannelOpen (ChannelType "session") rid0 rws rps
        opn1 = ChannelOpen (ChannelType "session") rid1 rws rps
        msg0 = Right (ChannelOpenConfirmation rid0 lid0 lws lps)
        msg1 = Left (ChannelOpenFailure rid1 ChannelOpenResourceShortage "" "")

connectionChannelOpen03 :: TestTree
connectionChannelOpen03 = testCase "open two channels" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxCount = 2, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn0
    assertEqual "msg1" msg1 =<< connectionChannelOpen conn opn1
    where
        lid0 = ChannelId 0
        lid1 = ChannelId 1
        rid0 = ChannelId 2
        rid1 = ChannelId 3
        rws  = 123
        rps  = 456
        lws  = 128
        lps  = 32
        opn0 = ChannelOpen (ChannelType "session") rid0 rws rps
        opn1 = ChannelOpen (ChannelType "session") rid1 rws rps
        msg0 = Right (ChannelOpenConfirmation rid0 lid0 lws lps)
        msg1 = Right (ChannelOpenConfirmation rid1 lid1 lws lps)

connectionChannelOpen04 :: TestTree
connectionChannelOpen04 = testCase "open two channels, close first, reuse first" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxCount = 2, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn0
    assertEqual "msg1" msg1 =<< connectionChannelOpen conn opn1
    assertEqual "msg2" msg2 =<< connectionChannelClose conn cls0
    assertEqual "msg3" msg3 =<< connectionChannelOpen conn opn2
    where
        ctp  = ChannelType "session"
        lid0 = ChannelId 0
        lid1 = ChannelId 1
        lid2 = lid0
        rid0 = ChannelId 0
        rid1 = ChannelId 1
        rid2 = ChannelId 2
        rws  = 123
        rps  = 456
        lws  = 243
        lps  = 545
        opn0 = ChannelOpen ctp rid0 rws rps
        opn1 = ChannelOpen ctp rid1 rws rps
        opn2 = ChannelOpen ctp rid2 rws rps
        cls0 = ChannelClose lid0
        msg0 = Right (ChannelOpenConfirmation rid0 lid0 lws lps)
        msg1 = Right (ChannelOpenConfirmation rid1 lid1 lws lps)
        msg2 = Just (ChannelClose (ChannelId 0))
        msg3 = Right (ChannelOpenConfirmation rid2 lid2 lws lps)

connectionChannelOpen05 :: TestTree
connectionChannelOpen05 = testCase "open unknown channel type" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "unknown") rid rws rps
        msg0 = Left (ChannelOpenFailure rid ChannelOpenUnknownChannelType "" "")

connectionChannelClose01 :: TestTree
connectionChannelClose01 = testCase "fail on invalid channel id" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf () undefined
    assertThrows "exp" exp $ connectionChannelClose conn cls
    where
        cls = ChannelClose (ChannelId 0)
        exp = Disconnect DisconnectProtocolError "invalid channel id" mempty

connectionChannelClose02 :: TestTree
connectionChannelClose02 = testCase "reuse local channel id when close acknowledged" $ do
    msgs <- newTChanIO
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onShellRequest = Just handler } () sender
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
    assertEqual "msg2" msg2 =<< receiver
    assertEqual "msg3" msg3 =<< receiver
    assertEqual "msg4" msg4 =<< receiver
    assertEqual "msg5" msg5 =<< connectionChannelClose conn cls
    assertEqual "msg6" msg6 =<< connectionChannelOpen conn opn
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        cls = ChannelClose lid
        req = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = MsgChannelEof (ChannelEof rid)
        msg3 = MsgChannelRequest (ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL")
        msg4 = MsgChannelClose (ChannelClose rid)
        msg5 = Nothing
        msg6 = msg0
        handler = const $ pure ExitSuccess

connectionChannelClose03 :: TestTree
connectionChannelClose03 = testCase "don't reuse local channel id unless close acknowledged" $ do
    msgs <- newTChanIO
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onShellRequest = Just handler } () sender
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
    assertEqual "msg2" msg2 =<< receiver
    assertEqual "msg3" msg3 =<< receiver
    assertEqual "msg4" msg4 =<< receiver
    assertEqual "msg5" msg5 =<< connectionChannelOpen conn opn
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        cls = ChannelClose lid
        req = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = MsgChannelEof (ChannelEof rid)
        msg3 = MsgChannelRequest (ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL")
        msg4 = MsgChannelClose (ChannelClose rid)
        msg5 = Right (ChannelOpenConfirmation rid (ChannelId 1) lws lps)
        handler = const $ pure ExitSuccess

connectionChannelRequest01 :: TestTree
connectionChannelRequest01 = testCase "fail on invalid channel id" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    assertThrows "exp0" exp0 $ connectionChannelRequest conn req
    where
        lid0 = ChannelId 0
        lid1 = ChannelId 1
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid1 "env" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid0 lws lps)
        exp0 = Disconnect DisconnectProtocolError "invalid channel id" mempty

connectionChannelRequest02 :: TestTree
connectionChannelRequest02 = testCase "reject unknown / unimplemented requests" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid "unknown" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Left (ChannelFailure rid))

connectionChannelRequest03 :: TestTree
connectionChannelRequest03 = testCase "accept session environment request" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid "env" False "\NUL\NUL\NUL\ACKLC_ALL\NUL\NUL\NUL\ven_US.UTF-8"
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Nothing

connectionChannelRequestEnv01 :: TestTree
connectionChannelRequestEnv01 = testCase "fail on invalid request" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    assertThrows "exp0" exp0 $ connectionChannelRequest conn req
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid "env" True mempty -- mempty is invalid
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        exp0 = Disconnect DisconnectProtocolError "invalid channel request" mempty

connectionChannelRequestPty01 :: TestTree
connectionChannelRequestPty01 = testCase "accept pty request" $ do
    conf <- newDefaultConfig
    bracket (connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps} () undefined) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
    where
        lid =  ChannelId 0
        rid  = ChannelId 23
        lws  = 100
        lps  = 200
        rws  = 123
        rps  = 456
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        opn  = ChannelOpen (ChannelType "session") rid rws rps
        req  = ChannelRequest lid "pty-req" True $ mconcat
            [ "\NUL\NUL\NUL\ENQxterm\NUL\NUL\SOH\DLE"
            , "\NUL\NUL\NULI\NUL\NUL\ap\NUL\NUL\ETX\254\NUL\NUL\SOH\ENQ\129\NUL"
            , "\NUL\150\NUL\128\NUL\NUL\150\NUL\SOH\NUL\NUL\NUL\ETX\STX\NUL\NUL"
            , "\NUL\FS\ETX\NUL\NUL\NUL\DEL\EOT\NUL\NUL\NUL\NAK\ENQ\NUL\NUL\NUL"
            , "\EOT\ACK\NUL\NUL\NUL\NUL\a\NUL\NUL\NUL\NUL\b\NUL\NUL\NUL\DC1\t"
            , "\NUL\NUL\NUL\DC3\n\NUL\NUL\NUL\SUB\f\NUL\NUL\NUL\DC2\r\NUL\NUL"
            , "\NUL\ETB\SO\NUL\NUL\NUL\SYN\DC2\NUL\NUL\NUL\SI\RS\NUL\NUL\NUL"
            , "\SOH\US\NUL\NUL\NUL\NUL \NUL\NUL\NUL\NUL!\NUL\NUL\NUL\NUL\"\NUL"
            , "\NUL\NUL\NUL#\NUL\NUL\NUL\NUL$\NUL\NUL\NUL\SOH%\NUL\NUL\NUL\NUL&"
            , "\NUL\NUL\NUL\SOH'\NUL\NUL\NUL\NUL(\NUL\NUL\NUL\NUL)\NUL\NUL\NUL"
            , "\SOH*\NUL\NUL\NUL\SOH2\NUL\NUL\NUL\SOH3\NUL\NUL\NUL\SOH4\NUL\NUL"
            , "\NUL\NUL5\NUL\NUL\NUL\SOH6\NUL\NUL\NUL\SOH7\NUL\NUL\NUL\SOH8\NUL"
            , "\NUL\NUL\NUL9\NUL\NUL\NUL\NUL:\NUL\NUL\NUL\NUL;\NUL\NUL\NUL\SOH"
            , "<\NUL\NUL\NUL\SOH=\NUL\NUL\NUL\SOH>\NUL\NUL\NUL\NULF\NUL\NUL\NUL"
            , "\SOHG\NUL\NUL\NUL\NULH\NUL\NUL\NUL\SOHI\NUL\NUL\NUL\NULJ\NUL\NUL"
            , "\NUL\NULK\NUL\NUL\NUL\NULZ\NUL\NUL\NUL\SOH[\NUL\NUL\NUL\SOH\\"
            , "\NUL\NUL\NUL\NUL]\NUL\NUL\NUL\NUL\NUL" ]

connectionChannelRequestPty02 :: TestTree
connectionChannelRequestPty02 = testCase "shell handler gets pty settings injected" $ withTimeout $ do
    tmvar <- newEmptyTMVarIO
    msgs <- newTChanIO
    let handler (Session _ _ pty _ _ _) = atomically (putTMVar tmvar pty) >> pure ExitSuccess
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onShellRequest = Just handler } () sender) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req0
        assertEqual "msg2" msg2 =<< connectionChannelRequest conn req1
        assertEqual "msg3" msg3 =<< receiver
        assertEqual "msg4" msg4 =<< receiver
        assertEqual "msg5" msg5 =<< receiver
        settings <- atomically (takeTMVar tmvar)
        assertEqual "ptyEnv"          (Just "xterm") (ptyEnv          <$> settings)
        assertEqual "ptyWidthCols"    (Just     272) (ptyWidthCols    <$> settings)
        assertEqual "ptyHeightRows"   (Just      73) (ptyHeightRows   <$> settings)
        assertEqual "ptyWidthPixels"  (Just    1904) (ptyWidthPixels  <$> settings)
        assertEqual "ptyHeightPixels" (Just    1022) (ptyHeightPixels <$> settings)
    where
        lid =  ChannelId 0
        rid  = ChannelId 23
        lws  = 100
        lps  = 200
        rws  = 123
        rps  = 456
        opn  = ChannelOpen (ChannelType "session") rid rws rps
        req0 = ChannelRequest lid "pty-req" True pty0
        req1 = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = Just (Right (ChannelSuccess rid))
        msg3 = MsgChannelEof (ChannelEof rid)
        msg4 = MsgChannelRequest (ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL")
        msg5 = MsgChannelClose (ChannelClose rid)
        pty0 = mconcat
            [ "\NUL\NUL\NUL\ENQxterm\NUL\NUL\SOH\DLE"
            , "\NUL\NUL\NULI\NUL\NUL\ap\NUL\NUL\ETX\254\NUL\NUL\SOH\ENQ\129\NUL"
            , "\NUL\150\NUL\128\NUL\NUL\150\NUL\SOH\NUL\NUL\NUL\ETX\STX\NUL\NUL"
            , "\NUL\FS\ETX\NUL\NUL\NUL\DEL\EOT\NUL\NUL\NUL\NAK\ENQ\NUL\NUL\NUL"
            , "\EOT\ACK\NUL\NUL\NUL\NUL\a\NUL\NUL\NUL\NUL\b\NUL\NUL\NUL\DC1\t"
            , "\NUL\NUL\NUL\DC3\n\NUL\NUL\NUL\SUB\f\NUL\NUL\NUL\DC2\r\NUL\NUL"
            , "\NUL\ETB\SO\NUL\NUL\NUL\SYN\DC2\NUL\NUL\NUL\SI\RS\NUL\NUL\NUL"
            , "\SOH\US\NUL\NUL\NUL\NUL \NUL\NUL\NUL\NUL!\NUL\NUL\NUL\NUL\"\NUL"
            , "\NUL\NUL\NUL#\NUL\NUL\NUL\NUL$\NUL\NUL\NUL\SOH%\NUL\NUL\NUL\NUL&"
            , "\NUL\NUL\NUL\SOH'\NUL\NUL\NUL\NUL(\NUL\NUL\NUL\NUL)\NUL\NUL\NUL"
            , "\SOH*\NUL\NUL\NUL\SOH2\NUL\NUL\NUL\SOH3\NUL\NUL\NUL\SOH4\NUL\NUL"
            , "\NUL\NUL5\NUL\NUL\NUL\SOH6\NUL\NUL\NUL\SOH7\NUL\NUL\NUL\SOH8\NUL"
            , "\NUL\NUL\NUL9\NUL\NUL\NUL\NUL:\NUL\NUL\NUL\NUL;\NUL\NUL\NUL\SOH"
            , "<\NUL\NUL\NUL\SOH=\NUL\NUL\NUL\SOH>\NUL\NUL\NUL\NULF\NUL\NUL\NUL"
            , "\SOHG\NUL\NUL\NUL\NULH\NUL\NUL\NUL\SOHI\NUL\NUL\NUL\NULJ\NUL\NUL"
            , "\NUL\NULK\NUL\NUL\NUL\NULZ\NUL\NUL\NUL\SOH[\NUL\NUL\NUL\SOH\\"
            , "\NUL\NUL\NUL\NUL]\NUL\NUL\NUL\NUL\NUL" ]

connectionChannelRequestShell01 :: TestTree
connectionChannelRequestShell01 = testCase "without handler" $ withTimeout $ do
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onShellRequest = Nothing, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
    where
        lid  = ChannelId 0
        rid  = ChannelId 23
        lws  = 100
        lps  = 200
        rws  = 123
        rps  = 456
        opn  = ChannelOpen (ChannelType "session") rid rws rps
        req  = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Left (ChannelFailure rid))

connectionChannelRequestShell02 :: TestTree
connectionChannelRequestShell02 = testCase "with handler exit(0)" $ withTimeout $ do
    msgs <- newTChanIO
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onShellRequest = Just handler, channelMaxQueueSize = lws, channelMaxPacketSize = lps } idnt sender) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
        assertEqual "msg2" msg2 =<< receiver
        assertEqual "msg3" msg3 =<< receiver
        assertEqual "msg4" msg4 =<< receiver
    where
        lid  = ChannelId 0
        rid  = ChannelId 23
        lws  = 100
        lps  = 200
        rws  = 123
        rps  = 456
        opn  = ChannelOpen (ChannelType "session") rid rws rps
        req  = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = MsgChannelEof (ChannelEof rid)
        msg3 = MsgChannelRequest (ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL")
        msg4 = MsgChannelClose (ChannelClose rid)
        idnt = "identity"
        handler (Session i _ pty _ _ _) 
            | i == idnt && pty == Nothing = pure ExitSuccess
            | otherwise                   = pure (ExitFailure 1)

connectionChannelRequestShell03 :: TestTree
connectionChannelRequestShell03 = testCase "with handler exit(0) after writing to stdout" $ withTimeout $ do
    msgs <- newTChanIO
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onShellRequest = Just handler, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () sender) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
        assertEqual "msg2" msg2 =<< receiver
        assertEqual "msg3" msg3 =<< receiver
        assertEqual "msg4" msg4 =<< receiver
        assertEqual "msg5" msg5 =<< receiver
    where
        echo = "PING PING PING PING"
        lid = ChannelId 0
        rid = ChannelId 23
        rws = 123
        rps = 456
        lws = 300
        lps = 400
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = MsgChannelData (ChannelData rid "ABCDEF")
        msg3 = MsgChannelEof (ChannelEof rid)
        msg4 = MsgChannelRequest (ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL")
        msg5 = MsgChannelClose (ChannelClose rid)
        handler (Session _ _ _ _ stdout _) = do
            sendAll stdout "ABCDEF"
            pure ExitSuccess

connectionChannelRequestShell04 :: TestTree
connectionChannelRequestShell04 = testCase "with handler exit(1) after echoing stdin to stdout" $ withTimeout $ do
    msgs <- newTChanIO
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onShellRequest = Just handler, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () sender) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
        connectionChannelData conn (ChannelData lid echo)
        assertEqual "msg2" msg2 =<< receiver
        assertEqual "msg3" msg3 =<< receiver
        assertEqual "msg4" msg4 =<< receiver
        assertEqual "msg5" msg5 =<< receiver
    where
        echo = "PING PING PING PING"
        lid = ChannelId 0
        rid = ChannelId 23
        rws = 123
        rps = 456
        lws = 300
        lps = 400
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = MsgChannelData (ChannelData rid echo)
        msg3 = MsgChannelEof (ChannelEof rid)
        msg4 = MsgChannelRequest (ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\SOH")
        msg5 = MsgChannelClose (ChannelClose rid)
        handler (Session _ _ _ stdin stdout _) = do
            receive stdin 1024 >>= sendAll stdout
            pure (ExitFailure 1)

connectionChannelRequestShell05 :: TestTree
connectionChannelRequestShell05 = testCase "with handler exit(1) after echoing stdin to stderr" $ withTimeout $ do
    msgs <- newTChanIO
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onShellRequest = Just handler, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () sender) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
        connectionChannelData conn (ChannelData lid echo)
        assertEqual "msg2" msg2 =<< receiver
        assertEqual "msg3" msg3 =<< receiver
        assertEqual "msg4" msg4 =<< receiver
        assertEqual "msg5" msg5 =<< receiver
    where
        echo = "PING PING PING PING"
        lid = ChannelId 0
        rid = ChannelId 23
        rws = 123
        rps = 456
        lws = 300
        lps = 400
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = MsgChannelExtendedData (ChannelExtendedData rid 1 echo)
        msg3 = MsgChannelEof (ChannelEof rid)
        msg4 = MsgChannelRequest (ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\SOH")
        msg5 = MsgChannelClose (ChannelClose rid)
        handler (Session _ _ _ stdin _ stderr) = do
            receive stdin 1024 >>= sendAll stderr >> pure ()
            pure (ExitFailure 1)

connectionChannelRequestShell06 :: TestTree
connectionChannelRequestShell06 = testCase "with handler throwing exception" $ withTimeout $ do
    msgs <- newTChanIO
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onShellRequest = Just handler, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () sender) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<<  connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<<  connectionChannelRequest conn req
        assertEqual "msg2" msg2 =<< receiver
        assertEqual "msg3" msg3 =<< receiver
        assertEqual "msg4" msg4 =<< receiver
    where
        lid = ChannelId 0
        rid = ChannelId 23
        rws = 123
        rps = 456
        lws = 300
        lps = 400
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = MsgChannelEof (ChannelEof rid)
        msg3 = MsgChannelRequest (ChannelRequest rid "exit-signal" False "\NUL\NUL\NUL\ETXILL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL")
        msg4 = MsgChannelClose (ChannelClose rid)
        handler _ = error "nasty handler"

connectionChannelRequestShell07 :: TestTree
connectionChannelRequestShell07 = testCase "with handler running while close by client" $ withTimeout $ do
    msgs <- newTChanIO
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onShellRequest = Just handler, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () sender) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
        assertEqual "msg2" msg2 =<< connectionChannelClose conn cls
    where
        lid = ChannelId 0
        rid = ChannelId 23
        rws = 123
        rps = 456
        lws = 300
        lps = 400
        opn = ChannelOpen (ChannelType "session") rid rws rps
        cls = ChannelClose lid
        req = ChannelRequest lid "shell" True mempty
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = Just (ChannelClose rid)
        handler _ = threadDelay 10000000 >> pure ExitSuccess

connectionChannelRequestShell08 :: TestTree
connectionChannelRequestShell08 = testCase "with handler and inbound flow control" $ withTimeout $ do
    msgs <- newTChanIO
    tmvar0 <- newEmptyTMVarIO
    tmvar1 <- newEmptyTMVarIO
    tmvar2 <- newEmptyTMVarIO
    let handler (Session _ _ _ stdin _ _) = do
            atomically $ takeTMVar tmvar0
            atomically . putTMVar tmvar1 =<< receive stdin 1
            atomically $ takeTMVar tmvar0
            atomically . putTMVar tmvar1 =<< receive stdin 1
            void $ atomically $ takeTMVar tmvar2
            pure ExitSuccess
    let send msg = atomically $ writeTChan msgs msg
    let receiver = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onShellRequest = Just handler, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () send) connectionClose $ \conn -> do
        assertEqual "msg00" msg00 =<< connectionChannelOpen conn opn
        assertEqual "msg01" msg01 =<< connectionChannelRequest conn req
        connectionChannelData conn (ChannelData lid "ABC")
        atomically $ putTMVar tmvar0 ()
        assertEqual "byte0" "A" =<< atomically (takeTMVar tmvar1)
        atomically $ putTMVar tmvar0 ()
        assertEqual "byte1" "B" =<< atomically (takeTMVar tmvar1)
        assertEqual "msg02" msg02 =<< receiver
        connectionChannelData conn (ChannelData lid "DE")
        assertThrows "exp00" exp00 $ connectionChannelData conn (ChannelData lid "F")
    where
        lid = ChannelId 0
        rid = ChannelId 23
        rws = 4
        rps = 1
        lws = 3
        lps = 1
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid "shell" True mempty
        msg00 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg01 = Just (Right (ChannelSuccess rid))
        msg02 = MsgChannelWindowAdjust (ChannelWindowAdjust rid 2)
        exp00 = Disconnect DisconnectProtocolError "window size underrun" mempty

connectionChannelRequestShell09 :: TestTree
connectionChannelRequestShell09 = testCase "with handler and outbound flow control" $ withTimeout $ do
    msgs <- newTChanIO
    tmvar0 <- newEmptyTMVarIO
    tmvar1 <- newEmptyTMVarIO
    tmvar2 <- newEmptyTMVarIO
    let handler (Session _ _ _ _ stdout _) = do
            i <- send stdout "1234567890"
            atomically $ putTMVar tmvar0 i
            j <- send stdout "ABCD"
            atomically $ putTMVar tmvar1 j
            pure ExitSuccess
    let send msg = atomically $ writeTChan msgs msg
    let receiver = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onShellRequest = Just handler, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () send) connectionClose $ \conn -> do
        assertEqual "msg00" msg00 =<< connectionChannelOpen conn opn
        assertEqual "msg01" msg01 =<< connectionChannelRequest conn req
        assertEqual "bytes1" (fromIntegral rws) =<< atomically (readTMVar tmvar0)
        assertEqual "msg02" msg02 =<< receiver
        assertEqual "msg03" msg03 =<< receiver
        assertEqual "msg04" msg04 =<< receiver
        assertEqual "msg05" msg05 =<< receiver
        connectionChannelWindowAdjust conn (ChannelWindowAdjust lid 3)
        assertEqual "bytes2" 3 =<< atomically (readTMVar tmvar1)
        assertEqual "msg06" msg06 =<< receiver
        assertEqual "msg07" msg07 =<< receiver
        assertEqual "msg08" msg08 =<< receiver
        assertEqual "msg09" msg09 =<< receiver
        assertEqual "msg10" msg10 =<< receiver
        assertEqual "msg11" msg11 =<< receiver
    where
        ct  = ChannelType "session"
        lid = ChannelId 0
        rid = ChannelId 23
        rws = 4
        rps = 1
        lws = 5
        lps = 1
        opn = ChannelOpen (ChannelType "session") rid rws rps
        req = ChannelRequest lid "shell" True mempty
        msg00 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg01 = Just (Right (ChannelSuccess rid))
        msg02 = MsgChannelData (ChannelData rid "1")
        msg03 = MsgChannelData (ChannelData rid "2")
        msg04 = MsgChannelData (ChannelData rid "3")
        msg05 = MsgChannelData (ChannelData rid "4")
        msg06 = MsgChannelData (ChannelData rid "A")
        msg07 = MsgChannelData (ChannelData rid "B")
        msg08 = MsgChannelData (ChannelData rid "C")
        msg09 = MsgChannelEof (ChannelEof rid)
        msg10 = MsgChannelRequest (ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL")
        msg11 = MsgChannelClose (ChannelClose rid)

connectionChannelRequestExec01 :: TestTree
connectionChannelRequestExec01 = testCase "without handler" $ withTimeout $ do
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onExecRequest = Nothing, channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
    where
        lid  = ChannelId 0
        rid  = ChannelId 23
        lws  = 100
        lps  = 200
        rws  = 123
        rps  = 456
        opn  = ChannelOpen (ChannelType "session") rid rws rps
        req  = ChannelRequest lid "exec" True "\NUL\NUL\NUL\NUL"
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Left (ChannelFailure rid))

connectionChannelRequestExec02 :: TestTree
connectionChannelRequestExec02 = testCase "with handler exit(0)" $ withTimeout $ do
    msgs <- newTChanIO
    let sender msg = atomically $ writeTChan msgs msg
    let receiver   = atomically $ readTChan msgs
    conf <- newDefaultConfig
    bracket (connectionOpen conf { onExecRequest = Just handler, channelMaxQueueSize = lws, channelMaxPacketSize = lps } idnt sender) connectionClose $ \conn -> do
        assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
        assertEqual "msg1" msg1 =<< connectionChannelRequest conn req
        assertEqual "msg2" msg2 =<< receiver
        assertEqual "msg3" msg3 =<< receiver
        assertEqual "msg4" msg4 =<< receiver
    where
        lid  = ChannelId 0
        rid  = ChannelId 23
        lws  = 100
        lps  = 200
        rws  = 123
        rps  = 456
        opn  = ChannelOpen (ChannelType "session") rid rws rps
        req  = ChannelRequest lid "exec" True "\NUL\NUL\NUL\NUL"
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        msg1 = Just (Right (ChannelSuccess rid))
        msg2 = MsgChannelEof (ChannelEof rid)
        msg3 = MsgChannelRequest (ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL")
        msg4 = MsgChannelClose (ChannelClose rid)
        idnt = "identity" :: String
        handler (Session i _ _ _ _ _) command
            | i == idnt && command == mempty = pure ExitSuccess
            | otherwise = pure (ExitFailure 1)

connectionChannelData01 :: TestTree
connectionChannelData01 = testCase "channel data" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    connectionChannelData conn (ChannelData lid "ABCDEF")
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)

connectionChannelData02 :: TestTree
connectionChannelData02 = testCase "channel data after eof" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    connectionChannelEof conn (ChannelEof lid)
    assertThrows "exp0" exp0 $ connectionChannelData conn (ChannelData lid "ABCDEF")
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        exp0 = Disconnect DisconnectProtocolError "data after eof" mempty

connectionChannelData03 :: TestTree
connectionChannelData03 = testCase "window size" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    connectionChannelData conn (ChannelData lid "ABC")
    connectionChannelData conn (ChannelData lid "DEF")
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 6
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)

connectionChannelData04 :: TestTree
connectionChannelData04 = testCase "window exhaustion #1" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    assertThrows "exp0" exp0 $ connectionChannelData conn (ChannelData lid "ABCDEF")
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 5
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        exp0 = Disconnect DisconnectProtocolError "window size underrun" mempty

connectionChannelData05 :: TestTree
connectionChannelData05 = testCase "window exhaustion #2" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    connectionChannelData conn (ChannelData lid "ABC")
    assertThrows "exp0" exp0 $ connectionChannelData conn (ChannelData lid "DEF")
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 5
        lps = 200
        rws = 123
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        exp0 = Disconnect DisconnectProtocolError "window size underrun" mempty

connectionChannelWindowAdjust01 :: TestTree
connectionChannelWindowAdjust01 = testCase "window adjustion up to maximum" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    connectionChannelWindowAdjust conn (ChannelWindowAdjust lid 128)
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = maxBound - 128
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)

connectionChannelWindowAdjust02 :: TestTree
connectionChannelWindowAdjust02 = testCase "window adjustion beyond maximum shoud throw" $ do
    conf <- newDefaultConfig
    conn <- connectionOpen conf { channelMaxQueueSize = lws, channelMaxPacketSize = lps } () undefined
    assertEqual "msg0" msg0 =<< connectionChannelOpen conn opn
    assertThrows "exp0" exp0 $ connectionChannelWindowAdjust conn (ChannelWindowAdjust lid 129)
    where
        lid = ChannelId 0
        rid = ChannelId 23
        lws = 100
        lps = 200
        rws = maxBound - 128
        rps = 456
        opn = ChannelOpen (ChannelType "session") rid rws rps
        msg0 = Right (ChannelOpenConfirmation rid lid lws lps)
        exp0 = Disconnect DisconnectProtocolError "window size overflow" mempty

assertThrows :: (Eq e, Exception e) => String -> e -> IO a -> Assertion
assertThrows label e action = (action >> failure0) `catch` \e'-> when (e /= e') (failure1 e')
    where
        failure0 = assertFailure (label ++ ": should have thrown " ++ show e)
        failure1 e' = assertFailure (label ++ ": should have thrown " ++ show e ++ " (saw " ++ show e' ++ " instead)")

withTimeout :: IO a -> IO a
withTimeout action = withAsync action $ \thread -> do
    t <- registerDelay 1000000
    let timeout = readTVar t >>= check >> pure (assertFailure "timeout")
    let result  = waitSTM thread >>= pure . pure
    join $ atomically $ result <|> timeout
