{-# LANGUAGE OverloadedStrings #-}
module Spec.Server.Service.Connection ( tests ) where
    
import           Control.Concurrent.Async
import           System.Exit
import           Data.Default
import qualified Data.Map.Strict as M

import           Network.SSH.Internal

import           Test.Tasty
import           Test.Tasty.HUnit

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Server.Service.Connection"
    [ test01
    , test02
    , test03
    , test04
    , test05
    , test06
    , test07
    , test08
    , testGroup "channel requests"
        [ testRequest01
        , testGroup "session channel requests"
            [ testRequestSession01
            , testRequestSession02
            ]
        ]
    ]

test01 :: TestTree
test01  = testCase "open one session channel" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
    where
        lid  = ChannelId 0
        rid  = ChannelId 1
        lws  = 256 * 1024
        lps  = 32 * 1024
        rws  = 123
        rps  = 456
        req0 = ChannelOpen rid rws rps ChannelOpenSession
        res0 = ChannelOpenConfirmation rid lid lws lps

test02 :: TestTree
test02  = testCase "open two session channels" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
    where
        lid0 = ChannelId 0
        rid0 = ChannelId 3
        lid1 = ChannelId 1
        rid1 = ChannelId 4
        lws  = 257 * 1024
        lps  = 32 * 1024
        rws  = 123
        rps  = 456
        req0 = ChannelOpen rid0 rws rps ChannelOpenSession
        res0 = ChannelOpenConfirmation rid0 lid0 lws lps
        req1 = ChannelOpen rid1 rws rps ChannelOpenSession
        res1 = ChannelOpenConfirmation rid1 lid1 lws lps

test03 :: TestTree
test03  = testCase "open two session channels (exceed limit)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxCount = 1, channelMaxQueueSize = lws, channelMaxPacketSize = lps }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
    where
        lid  = ChannelId 0
        rid0 = ChannelId 1
        rid1 = ChannelId 2
        lws  = 258 * 1024
        lps  = 32 * 1024
        rws  = 123
        rps  = 456
        req0 = ChannelOpen rid0 rws rps ChannelOpenSession
        res0 = ChannelOpenConfirmation rid0 lid lws lps
        req1 = ChannelOpen rid1 rws rps ChannelOpenSession
        res1 = ChannelOpenFailure rid1 ChannelOpenResourceShortage mempty mempty

test04 :: TestTree
test04  = testCase "open two session channels (close first, reuse first)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        sendMessage clientStream req2
        receiveMessage clientStream >>= assertEqual "res2" res2
    where
        lid0 = ChannelId 0
        rid0 = ChannelId 1
        rid1 = ChannelId 2
        lws  = 259 * 1024
        lps  = 32 * 1024
        rws  = 123
        rps  = 456
        req0 = ChannelOpen rid0 rws rps ChannelOpenSession
        res0 = ChannelOpenConfirmation rid0 lid0 lws lps
        req1 = ChannelClose lid0
        res1 = ChannelClose rid0
        req2 = ChannelOpen rid1 rws rps ChannelOpenSession
        res2 = ChannelOpenConfirmation rid1 lid0 lws lps

test05 :: TestTree
test05  = testCase "open unknown channel type" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
    where
        rid0 = ChannelId 1
        lws  = 259 * 1024
        lps  = 32 * 1024
        rws  = 123
        rps  = 456
        req0 = ChannelOpen rid0 rws rps (ChannelOpenOther (ChannelType "unknown"))
        res0 = ChannelOpenFailure rid0 ChannelOpenUnknownChannelType mempty mempty

test06 :: TestTree
test06  = testCase "close non-existing channel id" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def
    withAsync (serveConnection config serverStream ()) $ \thread -> do
        sendMessage clientStream req0
        assertThrows "exp0" exp0 $ wait thread
    where
        lid0 = ChannelId 0
        req0 = ChannelClose lid0
        exp0 = exceptionInvalidChannelId

test07 :: TestTree
test07  = testCase "close channel (don't reuse unless acknowledged)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onShellRequest = Just handler }
    withAsync (serveConnection config serverStream ()) $ const $ do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res10" res10
        receiveMessage clientStream >>= assertEqual "res11" res11
        receiveMessage clientStream >>= assertEqual "res12" res12
        receiveMessage clientStream >>= assertEqual "res13" res13
        sendMessage clientStream req2
        receiveMessage clientStream >>= assertEqual "res2" res2
    where
        lid0  = ChannelId 0
        rid0  = ChannelId 23
        lid1  = ChannelId 1
        rid1  = ChannelId 24
        lws   = 100
        lps   = 200
        rws   = 123
        rps   = 456
        req0  = ChannelOpen rid0 rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid0 lid0 lws lps
        req1  = ChannelRequest lid0 "shell" True mempty
        res10 = ChannelSuccess rid0
        res11 = ChannelEof rid0
        res12 = ChannelRequest rid0 "exit-status" False "\NUL\NUL\NUL\NUL"
        res13 = ChannelClose rid0
        req2  = ChannelOpen rid1 rws rps ChannelOpenSession
        res2  = ChannelOpenConfirmation rid1 lid1 lws lps
        handler = const $ pure ExitSuccess

test08 :: TestTree
test08  = testCase "close channel (reuse when acknowledged)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onShellRequest = Just handler }
    withAsync (serveConnection config serverStream ()) $ const $ do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res10" res10
        receiveMessage clientStream >>= assertEqual "res11" res11
        receiveMessage clientStream >>= assertEqual "res12" res12
        receiveMessage clientStream >>= assertEqual "res13" res13
        sendMessage clientStream req2
        sendMessage clientStream req3
        receiveMessage clientStream >>= assertEqual "res3" res3
    where
        lid0  = ChannelId 0
        rid0  = ChannelId 23
        rid1  = ChannelId 24
        lws   = 100
        lps   = 200
        rws   = 123
        rps   = 456
        req0  = ChannelOpen rid0 rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid0 lid0 lws lps
        req1  = ChannelRequest lid0 "shell" True mempty
        res10 = ChannelSuccess rid0
        res11 = ChannelEof rid0
        res12 = ChannelRequest rid0 "exit-status" False "\NUL\NUL\NUL\NUL"
        res13 = ChannelClose rid0
        req2  = ChannelClose lid0
        req3  = ChannelOpen rid1 rws rps ChannelOpenSession
        res3  = ChannelOpenConfirmation rid1 lid0 lws lps
        handler = const $ pure ExitSuccess

testRequest01 :: TestTree
testRequest01 = testCase "reject unknown / unimplemented requests" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps }
    withAsync (serveConnection config serverStream ()) $ const $ do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
    where
        lid  = ChannelId 0
        rid  = ChannelId 23
        lws  = 100
        lps  = 200
        rws  = 123
        rps  = 456
        req0 = ChannelOpen rid rws rps ChannelOpenSession
        res0 = ChannelOpenConfirmation rid lid lws lps
        req1 = ChannelRequest lid "unknown" True mempty
        res1 = ChannelFailure rid

testRequestSession01 :: TestTree
testRequestSession01 = testCase "env request" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onShellRequest = Just h }
    withAsync (serveConnection config serverStream ()) $ const $ do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        sendMessage clientStream req2
        receiveMessage clientStream >>= assertEqual "res20" res20
        receiveMessage clientStream >>= assertEqual "res21" res21
        receiveMessage clientStream >>= assertEqual "res22" res22
    where
        lid   = ChannelId 0
        rid   = ChannelId 23
        lws   = 100
        lps   = 200
        rws   = 123
        rps   = 456
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "env" False "\NUL\NUL\NUL\ACKLC_ALL\NUL\NUL\NUL\ven_US.UTF-8"
        req2  = ChannelRequest lid "shell" True ""
        res20 = ChannelSuccess rid
        res21 = ChannelEof rid
        res22 = ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL"
        h s
            | environment s == M.singleton "LC_ALL" "en_US.UTF-8" = pure ExitSuccess
            | otherwise                                           = pure (ExitFailure 1)

testRequestSession02 :: TestTree
testRequestSession02 = testCase "pty request" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onShellRequest = Just h }
    withAsync (serveConnection config serverStream ()) $ const $ do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        sendMessage clientStream req2
        receiveMessage clientStream >>= assertEqual "res20" res20
        receiveMessage clientStream >>= assertEqual "res21" res21
        receiveMessage clientStream >>= assertEqual "res22" res22
    where
        lid   = ChannelId 0
        rid   = ChannelId 23
        lws   = 100
        lps   = 200
        rws   = 123
        rps   = 456
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "pty-req" True $ runPut (put pty)
        res1  = ChannelSuccess rid
        req2  = ChannelRequest lid "shell" True ""
        res20 = ChannelSuccess rid
        res21 = ChannelEof rid
        res22 = ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL"
        h s
            | ptySettings s == Just pty = pure ExitSuccess
            | otherwise                 = pure (ExitFailure 1)
        pty = PtySettings
            { ptyEnv          = "xterm"
            , ptyWidthCols    = 80
            , ptyHeightRows   = 23
            , ptyWidthPixels  = 1024
            , ptyHeightPixels = 768
            , ptyModes        = "fsldkjfsdjflskjdf"
            }

{-

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

-}