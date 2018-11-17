{-# LANGUAGE OverloadedStrings #-}
module Spec.Server.Connection ( tests ) where

import           Control.Concurrent      ( threadDelay )
import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Exception       ( onException )
import           Control.Monad           ( void )
import           System.Exit
import           Data.Default
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Short as SBS

import           Network.SSH.Internal

import           Test.Tasty
import           Test.Tasty.HUnit

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Server.Connection"
    [ test00
    , test01
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
            , testGroup "shell requests"
                [ testRequestSessionShell01
                , testRequestSessionShell02
                , testRequestSessionShell03
                , testRequestSessionShell04
                , testRequestSessionShell05
                , testRequestSessionShell06
                , testRequestSessionShell07
                ]
            , testGroup "channel data"
                [ testSessionData01
                , testSessionData02
                , testSessionData03
                ]
            , testGroup "flow control"
                [ testSessionFlowControl01
                , testSessionFlowControl02
                , testSessionFlowControl03
                , testSessionFlowControl04
                , testSessionFlowControl05
                ]
            ]
        ]
    ]

test00 :: TestTree
test00  = testCase "open one session channel (no handler, expect rejection)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
    where
        rid  = ChannelId 1
        lws  = 256 * 1024
        lps  = 32 * 1024
        rws  = 123
        rps  = 456
        req0 = ChannelOpen rid rws rps ChannelOpenSession
        res0 = ChannelOpenFailure rid ChannelOpenAdministrativelyProhibited mempty mempty

test01 :: TestTree
test01  = testCase "open one session channel (with handler)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = \_ _ -> pure $ Just undefined
        }
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
test02  = testCase "open two session channels (with handler)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = \_ _ -> pure $ Just undefined
        }
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
    let config = def {
            channelMaxCount = 1,
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = \_ _ -> pure $ Just undefined
        }
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
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = \_ _ -> pure $ Just undefined
        }
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
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onSessionRequest = handler }
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
        handler _ _ = pure $ Just $ SessionHandler $ \env pty cmd stdin stdout stderr ->
            pure ExitSuccess

test08 :: TestTree
test08  = testCase "close channel (reuse when acknowledged)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onSessionRequest = handler }
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
        handler _ _ = pure $ Just $ SessionHandler $ \env pty cmd stdin stdout stderr ->
            pure ExitSuccess

testRequest01 :: TestTree
testRequest01 = testCase "reject unknown / unimplemented requests" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = \_ _ -> pure $ Just undefined
        }
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
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onSessionRequest = h }
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
        h _ _ = pure $ Just $ SessionHandler $ \env pty cmd stdin stdout stderr -> pure $
            if env == Environment [("LC_ALL","en_US.UTF-8")] 
                then ExitSuccess
                else ExitFailure 1

testRequestSession02 :: TestTree
testRequestSession02 = testCase "pty request" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def { channelMaxQueueSize = lws, channelMaxPacketSize = lps, onSessionRequest = h }
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
        pty   = PtySettings
                { ptyEnv          = "xterm"
                , ptyWidthCols    = 80
                , ptyHeightRows   = 23
                , ptyWidthPixels  = 1024
                , ptyHeightPixels = 768
                , ptyModes        = "fsldkjfsdjflskjdf"
                }
        h _ _ = pure $ Just $ SessionHandler $ \_ mpty _ _ _ _ -> pure $ case mpty of
            Just (TermInfo pty') | pty == pty' -> ExitSuccess
            _                                  -> ExitFailure 1

testRequestSessionShell01 :: TestTree
testRequestSessionShell01 = testCase "handler exits with 0" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res10" res10
        receiveMessage clientStream >>= assertEqual "res11" res11
        receiveMessage clientStream >>= assertEqual "res12" res12
        receiveMessage clientStream >>= assertEqual "res13" res13
    where
        lid  = ChannelId 0
        rid  = ChannelId 1
        lws  = 256 * 1024
        lps  = 32 * 1024
        rws  = 123
        rps  = 456
        req0 = ChannelOpen rid rws rps ChannelOpenSession
        res0 = ChannelOpenConfirmation rid lid lws lps
        req1 = ChannelRequest lid "shell" True mempty
        res10 = ChannelSuccess rid
        res11 = ChannelEof rid
        res12 = ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL"
        res13 = ChannelClose rid
        handler _ _ = pure $ Just $ SessionHandler $ \_ _ Nothing _ _ _ ->
            pure ExitSuccess

testRequestSessionShell02 :: TestTree
testRequestSessionShell02 = testCase "handler exits with 1" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res10" res10
        receiveMessage clientStream >>= assertEqual "res11" res11
        receiveMessage clientStream >>= assertEqual "res12" res12
        receiveMessage clientStream >>= assertEqual "res13" res13
    where
        lid  = ChannelId 0
        rid  = ChannelId 1
        lws  = 256 * 1024
        lps  = 32 * 1024
        rws  = 123
        rps  = 456
        req0 = ChannelOpen rid rws rps ChannelOpenSession
        res0 = ChannelOpenConfirmation rid lid lws lps
        req1 = ChannelRequest lid "shell" True mempty
        res10 = ChannelSuccess rid
        res11 = ChannelEof rid
        res12 = ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\SOH"
        res13 = ChannelClose rid
        handler _ _ = pure $ Just $ SessionHandler $ \_ _ Nothing _ _ _ ->
            pure (ExitFailure 1)

testRequestSessionShell03 :: TestTree
testRequestSessionShell03 = testCase "handler exits with 0 after writing to stdout" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res10" res10
        receiveMessage clientStream >>= assertEqual "res11" res11
        receiveMessage clientStream >>= assertEqual "res12" res12
        receiveMessage clientStream >>= assertEqual "res13" res13
        receiveMessage clientStream >>= assertEqual "res14" res14
    where
        ping  = "PING PING PING PING"
        lid   = ChannelId 0
        rid   = ChannelId 1
        lws   = 256 * 1024
        lps   = 32 * 1024
        rws   = 123
        rps   = 456
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res10 = ChannelSuccess rid
        res11 = ChannelData rid (SBS.toShort ping)
        res12 = ChannelEof rid
        res13 = ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL"
        res14 = ChannelClose rid
        handler _ _ = pure $ Just $ SessionHandler $ \_ _ Nothing _ stdout _ -> do
            void $ send stdout ping
            pure ExitSuccess

testRequestSessionShell04 :: TestTree
testRequestSessionShell04 = testCase "handler exits with 0 after writing to stderr" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res10" res10
        receiveMessage clientStream >>= assertEqual "res11" res11
        receiveMessage clientStream >>= assertEqual "res12" res12
        receiveMessage clientStream >>= assertEqual "res13" res13
        receiveMessage clientStream >>= assertEqual "res14" res14
    where
        ping  = "PING PING PING PING"
        lid   = ChannelId 0
        rid   = ChannelId 1
        lws   = 256 * 1024
        lps   = 32 * 1024
        rws   = 123
        rps   = 456
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res10 = ChannelSuccess rid
        res11 = ChannelExtendedData rid 1 (SBS.toShort ping)
        res12 = ChannelEof rid
        res13 = ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL"
        res14 = ChannelClose rid
        handler _ _ = pure $ Just $ SessionHandler $ \_ _ Nothing _ _ stderr -> do
            void $ send stderr ping
            pure ExitSuccess

testRequestSessionShell05 :: TestTree
testRequestSessionShell05 = testCase "handler exits with 0 after echoing stdin to stdout" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        sendMessage clientStream req2
        receiveMessage clientStream >>= assertEqual "res21" res21
        receiveMessage clientStream >>= assertEqual "res22" res22
        receiveMessage clientStream >>= assertEqual "res23" res23
        receiveMessage clientStream >>= assertEqual "res24" res24
    where
        ping  = "PING PING PING PING"
        lid   = ChannelId 0
        rid   = ChannelId 1
        lws   = 256 * 1024
        lps   = 32 * 1024
        rws   = 123
        rps   = 456
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res1  = ChannelSuccess rid
        req2  = ChannelData lid (SBS.toShort ping)
        res21 = ChannelData rid (SBS.toShort ping)
        res22 = ChannelEof rid
        res23 = ChannelRequest rid "exit-status" False "\NUL\NUL\NUL\NUL"
        res24 = ChannelClose rid
        handler _ _ = pure $ Just $ SessionHandler $ \_ _ Nothing stdin stdout _ -> do
            void (send stdout =<< receive stdin 128)
            pure ExitSuccess

testRequestSessionShell06 :: TestTree
testRequestSessionShell06 = testCase "handler throws exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res11" res11
        receiveMessage clientStream >>= assertEqual "res12" res12
        receiveMessage clientStream >>= assertEqual "res13" res13
        receiveMessage clientStream >>= assertEqual "res14" res14
    where
        lid   = ChannelId 0
        rid   = ChannelId 1
        lws   = 256 * 1024
        lps   = 32 * 1024
        rws   = 123
        rps   = 456
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res11 = ChannelSuccess rid
        res12 = ChannelEof rid
        res13 = ChannelRequest rid "exit-signal" False "\NUL\NUL\NUL\ETXILL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL"
        res14 = ChannelClose rid
        handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ _ _ _ -> do
            error "nasty handler"
            pure ExitSuccess

testRequestSessionShell07 :: TestTree
testRequestSessionShell07 = testCase "handler running while closed by client" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    mvar0 <- newEmptyMVar
    mvar1 <- newEmptyMVar
    let handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ _ _ _ -> do
            putMVar mvar0 ()
            threadDelay (1000*1000) `onException` putMVar mvar1 () 
            pure ExitSuccess
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        readMVar mvar0 -- wait for handler thread start
        sendMessage clientStream req2
        readMVar mvar1 -- wait for handler thread termination by exception
        receiveMessage clientStream >>= assertEqual "res2" res2
    where
        lid   = ChannelId 0
        rid   = ChannelId 1
        lws   = 256 * 1024
        lps   = 32 * 1024
        rws   = 123
        rps   = 456
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res1  = ChannelSuccess rid
        req2  = ChannelClose lid
        res2  = ChannelClose rid

testSessionData01 :: TestTree
testSessionData01 = testCase "honor remote max packet size" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ _ stdout _ -> do
            sendAll stdout msg
            pure ExitSuccess
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res11" res11
        receiveMessage clientStream >>= assertEqual "res12" res12
        receiveMessage clientStream >>= assertEqual "res13" res13
        receiveMessage clientStream >>= assertEqual "res14" res14
        receiveMessage clientStream >>= assertEqual "res15" res15
    where
        msg   = "ABC"
        lid   = ChannelId 0
        rid   = ChannelId 23
        rws   = fromIntegral (BS.length msg)
        rps   = 1
        lws   = fromIntegral (BS.length msg)
        lps   = fromIntegral (BS.length msg)
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res11 = ChannelSuccess rid
        res12 = ChannelData rid "A"
        res13 = ChannelData rid "B"
        res14 = ChannelData rid "C"
        res15 = ChannelEof rid

testSessionData02 :: TestTree
testSessionData02 = testCase "throw exception if local maxPacketSize is exeeded" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    mvar0 <- newEmptyMVar
    mvar1 <- newEmptyMVar
    let handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ stdin _ _ -> do
            void $ takeMVar mvar0
            putMVar mvar1 =<< receive stdin 1
            void $ takeMVar mvar0
            pure ExitSuccess
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \thread -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        -- Payload exceeds local maxPacketSize (lps).
        sendMessage clientStream req2
        assertThrows "exp2" exp2 $ wait thread
        -- Unblock handler.
        putMVar mvar0 ()
    where
        msg   = "ABC"
        lid   = ChannelId 0
        rid   = ChannelId 23
        rws   = 0
        rps   = 0
        lws   = fromIntegral (SBS.length msg)
        lps   = fromIntegral (SBS.length msg) - 1
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res1  = ChannelSuccess rid
        req2  = ChannelData lid msg
        exp2  = exceptionPacketSizeExceeded

testSessionData03 :: TestTree
testSessionData03 = testCase "throw exception if remote sends data after eof" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    mvar0 <- newEmptyMVar
    let handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ _ _ _ -> do
            void $ takeMVar mvar0
            pure ExitSuccess
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \thread -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        sendMessage clientStream req2
        sendMessage clientStream req3
        assertThrows "exp3" exp3 $ wait thread
        -- Unblock handler.
        putMVar mvar0 ()
    where
        msg   = "ABC"
        lid   = ChannelId 0
        rid   = ChannelId 23
        rws   = 0
        rps   = 0
        lws   = fromIntegral (SBS.length msg)
        lps   = fromIntegral (SBS.length msg)
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res1  = ChannelSuccess rid
        req2  = ChannelEof lid
        req3  = ChannelData lid msg
        exp3  = exceptionDataAfterEof

testSessionFlowControl01 :: TestTree
testSessionFlowControl01 = testCase "adjust inbound window when < 50% and capacity available" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    mvar0 <- newEmptyMVar
    mvar1 <- newEmptyMVar
    let handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ stdin _ _ -> do
            void $ takeMVar mvar0
            putMVar mvar1 =<< receive stdin 1
            void $ takeMVar mvar0
            pure ExitSuccess
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        -- Initial window (lws) is 5.
        -- Send 3 bytes ("ABC"). Remaining window is then < 50%.
        sendMessage clientStream req2
        -- Window adjust not yet possible due to lack of free capacity.
        -- Handler shall consume 1 byte to increase capacity to > 50%.
        putMVar mvar0 ()
        assertEqual "first byte" "A" =<< takeMVar mvar1
        -- Now expecting window adjust..
        receiveMessage clientStream >>= assertEqual "res2" res2
        -- Let handler finish.
        putMVar mvar0 ()
    where
        lid   = ChannelId 0
        rid   = ChannelId 23
        rws   = 0
        rps   = 0
        lws   = 5
        lps   = 5
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res1  = ChannelSuccess rid
        req2  = ChannelData lid "ABC"
        res2  = ChannelWindowAdjust rid 3

testSessionFlowControl02 :: TestTree
testSessionFlowControl02 = testCase "throw exception on inbound window size underrun" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    mvar0 <- newEmptyMVar
    let handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ _ _ _ -> do
            void $ takeMVar mvar0
            pure ExitSuccess
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \thread -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        sendMessage clientStream req2
        sendMessage clientStream req3
        assertThrows "exp3" exp3 $ wait thread
        -- Unblock handler.
        putMVar mvar0 ()
    where
        lid = ChannelId 0
        rid = ChannelId 23
        rws = 0
        rps = 0
        lws = 1
        lps = 1
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res1  = ChannelSuccess rid
        req2  = ChannelData lid "A"
        req3  = ChannelData lid "B"
        exp3  = exceptionWindowSizeUnderrun

testSessionFlowControl03 :: TestTree
testSessionFlowControl03 = testCase "honor outbound window size and adjustment" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ _ stdout _ -> do
            sendAll stdout msg
            pure ExitSuccess
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res11" res11
        receiveMessage clientStream >>= assertEqual "res12" res12
        sendMessage clientStream req2
        receiveMessage clientStream >>= assertEqual "res2" res2
        sendMessage clientStream req3
        receiveMessage clientStream >>= assertEqual "res31" res31
        receiveMessage clientStream >>= assertEqual "res32" res32
    where
        msg   = "ABCDEF"
        lid   = ChannelId 0
        rid   = ChannelId 23
        rws   = 3
        rps   = fromIntegral (BS.length msg)
        lws   = fromIntegral (BS.length msg)
        lps   = fromIntegral (BS.length msg)
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res11 = ChannelSuccess rid
        res12 = ChannelData rid "ABC"
        req2  = ChannelWindowAdjust lid 2
        res2  = ChannelData rid "DE"
        req3  = ChannelWindowAdjust lid 1
        res31 = ChannelData rid "F"
        res32 = ChannelEof rid

testSessionFlowControl04 :: TestTree
testSessionFlowControl04 = testCase "remote adjusts window size to maximum" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ stdin stdout _ -> do
            sendAll stdout =<< receiveAll stdin (SBS.length msg)
            pure ExitSuccess
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \_ -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        sendMessage clientStream req2
        sendMessage clientStream req3
        receiveMessage clientStream >>= assertEqual "res31" res31
        receiveMessage clientStream >>= assertEqual "res32" res32
    where
        msg   = "ABC"
        lid   = ChannelId 0
        rid   = ChannelId 23
        rws   = 0
        rps   = fromIntegral (SBS.length msg)
        lws   = fromIntegral (SBS.length msg)
        lps   = fromIntegral (SBS.length msg)
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res1  = ChannelSuccess rid
        req2  = ChannelData lid msg
        req3  = ChannelWindowAdjust lid maxBound
        res31 = ChannelData rid msg
        res32 = ChannelEof rid

testSessionFlowControl05 :: TestTree
testSessionFlowControl05 = testCase "throw exception if remote adjusts window size to (maximum + 1)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    mvar0 <- newEmptyMVar
    let handler _ _ = pure $ Just $ SessionHandler $ \_ _ _ _ _ _ -> do
            readMVar mvar0
            pure ExitSuccess
    let config = def {
            channelMaxQueueSize = lws,
            channelMaxPacketSize = lps,
            onSessionRequest = handler
        }
    withAsync (serveConnection config serverStream ()) $ \thread -> do
        sendMessage clientStream req0
        receiveMessage clientStream >>= assertEqual "res0" res0
        sendMessage clientStream req1
        receiveMessage clientStream >>= assertEqual "res1" res1
        sendMessage clientStream req2
        sendMessage clientStream req3
        putMVar mvar0 ()
        assertThrows "exp3" exp3 $ wait thread
    where
        lid   = ChannelId 0
        rid   = ChannelId 23
        rws   = 1
        rps   = 1
        lws   = 1
        lps   = 1
        req0  = ChannelOpen rid rws rps ChannelOpenSession
        res0  = ChannelOpenConfirmation rid lid lws lps
        req1  = ChannelRequest lid "shell" True mempty
        res1  = ChannelSuccess rid
        req2  = ChannelWindowAdjust lid maxBound
        req3  = ChannelData lid "ABC"
        exp3  = exceptionWindowSizeOverflow
