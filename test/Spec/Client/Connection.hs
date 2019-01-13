{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase        #-}
module Spec.Client.Connection ( tests ) where

import           Control.Concurrent          ( threadDelay )
import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Exception           ( AssertionFailed (..), fromException, throw, throwIO )
import           Control.Monad               ( void )
import           Control.Monad.STM
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.ByteString          as BS
import           Data.Default
import           System.Exit
import           System.IO.Error

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Client.Connection
import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Message
import           Network.SSH.Stream

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Client.Connection"
    [ testGroup "withConnection"
        [ testWithConnection01
        , testWithConnection02
        , testWithConnection03
        , testWithConnection04
        ]
    , testGroup "message dispatch in initial state"
        [ testDispatch01
        , testDispatch02
        , testDispatch03
        , testDispatch04
        , testDispatch05
        , testDispatch06
        , testDispatch07
        , testDispatch08
        , testDispatch09
        , testDispatch10
        , testDispatch11
        , testDispatch12
        ]
    , testGroup "session"
        [ testGroup "shell (open / close / exception handling)"
            [ testSessionShellOpen01
            , testSessionShellOpen02
            , testSessionShellOpen03
            , testSessionShellOpen04
            , testSessionShellOpen05
            , testSessionShellOpen06
            , testSessionShellOpen07
            , testSessionShellOpen08
            , testSessionShellOpen09
            , testSessionShellOpen10
            , testSessionShellOpen11
            ]
        , testGroup "shell (channel requests)" 
            [ testSessionShellRequest01
            , testSessionShellRequest02
            , testSessionShellRequest03
            , testSessionShellRequest04
            ]
        , testGroup "shell (data and window adjust)"
            [ testSessionShellData01
            , testSessionShellData02
            , testSessionShellData03
            , testSessionShellData04
            , testSessionShellData05
            , testSessionShellData06
            ]
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

testWithConnection04 :: TestTree
testWithConnection04 = testCase "shall throw exception when receiving unexpected message" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "exp" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream Ignore
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "unexpected message type 002")


testDispatch01 :: TestTree
testDispatch01 = testCase "GlobalRequest shall be ignored if wantReply == False" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ GlobalRequest False $ GlobalRequestOther "GLOBAL REQUEST"
        -- This is a bit tricky. We need to process one additional message
        -- in order to assure that the previous one has been ignored.
        -- This one should cause a specific exception which is used to test the behaviour.
        sendMessage serverStream $ ChannelClose (ChannelId 0)
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch02 :: TestTree
testDispatch02 = testCase "GlobalRequest shall be replied with RequestFailure otherwise" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    withConnection def clientStream $ \c -> do
        sendMessage serverStream $ GlobalRequest True $ GlobalRequestOther "GLOBAL REQUEST"
        threadDelay 100000 -- wait for client to process
    assertEqual "resp" RequestFailure =<< receiveMessage serverStream

testDispatch03 :: TestTree
testDispatch03 = testCase "ChannelOpenConfirmation shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ ChannelOpenConfirmation (ChannelId 0) (ChannelId 0) 0 0
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch04 :: TestTree
testDispatch04 = testCase "ChannelOpenFailure shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream
            $ ChannelOpenFailure (ChannelId 0) ChannelOpenAdministrativelyProhibited "" ""
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch05 :: TestTree
testDispatch05 = testCase "ChannelWindowAdjust shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ ChannelWindowAdjust (ChannelId 0) 123
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch06 :: TestTree
testDispatch06 = testCase "ChannelData shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ ChannelData (ChannelId 0) "ABC"
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch07 :: TestTree
testDispatch07 = testCase "ChannelExtendedData shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ ChannelExtendedData (ChannelId 0) 0 "ABC"
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch08 :: TestTree
testDispatch08 = testCase "ChannelEof shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ ChannelEof (ChannelId 0)
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch09 :: TestTree
testDispatch09 = testCase "ChannelClose shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ ChannelClose (ChannelId 0)
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch10 :: TestTree
testDispatch10 = testCase "ChannelRequest shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ ChannelRequest (ChannelId 0) "session" True "1234"
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch11 :: TestTree
testDispatch11 = testCase "ChannelSuccess shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ ChannelSuccess (ChannelId 0)
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testDispatch12 :: TestTree
testDispatch12 = testCase "ChannelFailure shall cause exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    assertThrows "asd" exp $ withConnection def clientStream $ \c -> do
        sendMessage serverStream $ ChannelFailure (ChannelId 0)
        threadDelay 1000000 -- wait here for exception
    where
        exp = Disconnect Local DisconnectProtocolError (DisconnectMessage "invalid channel id")

testSessionShellOpen01 :: TestTree
testSessionShellOpen01 = testCase "shall send channel open request" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c ->
            runShell c $ SessionHandler $ \_ _ _ _ -> pure ()
    withAsync action $ \thread ->
        assertEqual "req1" req1 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession

testSessionShellOpen02 :: TestTree
testSessionShellOpen02 = testCase "shall increase channel ids when requesting several channels" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let x = runShell c $ SessionHandler $ \_ _ _ _ -> pure ()
            withAsync x $ \_ -> threadDelay 10000 >> x
    withAsync action $ \_ -> do
        assertEqual "req1" req1 =<< receiveMessage serverStream
        assertEqual "req2" req2 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelOpen (ChannelId 1) ws ps ChannelOpenSession

testSessionShellOpen03 :: TestTree
testSessionShellOpen03 = testCase "shall throw exception when channel open failed" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    invoked <- newEmptyMVar
    let s c    = runShell c $ SessionHandler $ \_ _ _ _ -> pure ()
    let action = withConnection conf clientStream $ \c -> withAsync (s c) $ \sThread -> do
            failure <- waitCatch sThread
            putMVar invoked failure
    withAsync action $ \_ -> do
        assertEqual "req1" req1 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelOpenFailure lid ChannelOpenAdministrativelyProhibited "" ""
        (Left e) <- readMVar invoked
        case fromException e of
            Nothing -> assertFailure (show e)
            Just e' -> assertEqual "exp2" exp2 e'
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        exp2 = ChannelOpenFailed ChannelOpenAdministrativelyProhibited (ChannelOpenFailureDescription "")

testSessionShellOpen04 :: TestTree
testSessionShellOpen04 = testCase "shall request runShell when channel open confirmed" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let s c    = runShell c $ SessionHandler $ \_ _ _ _ -> pure ()
    let action = withConnection conf clientStream s
    withAsync action $ \_ -> do
        assertEqual "req1" req1 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelOpenConfirmation lid rid ws ps
        assertEqual "req2" req2 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)

testSessionShellOpen05 :: TestTree
testSessionShellOpen05 = testCase "shall throw exception when runShell request failed" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    me <- newEmptyMVar
    let s c = runShell c $ SessionHandler $ \_ _ _ _ -> pure ()
    let a = withConnection conf clientStream $ \c ->
                withAsync (s c) $ \sThread ->
                    putMVar me =<< waitCatch sThread
    withAsync a $ \_ -> do
        assertEqual "req1" req1 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelOpenConfirmation lid rid ws ps
        assertEqual "req2" req2 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelFailure lid
        (Left e) <- readMVar me
        case fromException e of
            Nothing -> assertFailure (show e)
            Just e' -> assertEqual "exp3" exp3 e'
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        exp3 = ChannelRequestFailed

testSessionShellOpen06 :: TestTree
testSessionShellOpen06 = testCase "shall invoke session handler when runShell request successful" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    me <- newEmptyMVar
    let s c = runShell c $ SessionHandler $ \_ _ _ _ -> pure 123
    let a = withConnection conf clientStream $ \c ->
                withAsync (s c) $ \sThread ->
                    putMVar me =<< waitCatch sThread
    withAsync a $ \_ -> do
        assertEqual "req1" req1 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelOpenConfirmation lid rid ws ps
        assertEqual "req2" req2 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelSuccess lid
        readMVar me >>= \case
            Left e -> assertFailure (show e)
            Right a -> assertEqual "handler result" 123 a 
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)

testSessionShellOpen07 :: TestTree
testSessionShellOpen07 = testCase "shall send eof and close after session handler returned" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let s c = runShell c $ SessionHandler $ \_ _ _ _ -> pure 123
    let a = withConnection conf clientStream s
    withAsync a $ \_ -> do
        assertEqual "req1" req1 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelOpenConfirmation lid rid ws ps
        assertEqual "req2" req2 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelSuccess lid
        assertEqual "req3" req3 =<< receiveMessage serverStream
        assertEqual "req4" req4 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        req3 = ChannelEof rid
        req4 = ChannelClose rid

testSessionShellOpen08 :: TestTree
testSessionShellOpen08 = testCase "shall send eof and close after session handler threw exception" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let s c = runShell c $ SessionHandler $ \_ _ _ _ -> throwIO (userError "ERROR")
    let a = withConnection conf clientStream s
    withAsync a $ \_ -> do
        assertEqual "req1" req1 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelOpenConfirmation lid rid ws ps
        assertEqual "req2" req2 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelSuccess lid
        assertEqual "req3" req3 =<< receiveMessage serverStream
        assertEqual "req4" req4 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        req3 = ChannelEof rid
        req4 = ChannelClose rid

testSessionShellOpen09 :: TestTree
testSessionShellOpen09 = testCase "shall close properly even if canceled before channel open confirmed" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    mc    <- newEmptyMVar
    step1 <- newEmptyMVar
    step2 <- newEmptyMVar
    step3 <- newEmptyMVar
    let action = withConnection conf clientStream $ \c -> do
            putMVar mc c
            readMVar step1
            let s = runShell c $ SessionHandler $ \_ _ _ _ -> pure ()
            withAsync s $ \shellThread -> do
                readMVar step2
                cancel shellThread
                putMVar step3 ()
                threadDelay 1000000 -- wait till end of test
    withAsync action $ \_ -> do
        c <- readMVar mc
        assertEqual "channel count before" 0 =<< getChannelCount c
        putMVar step1 ()
        assertEqual "req1" req1 =<< receiveMessage serverStream
        assertEqual "channel count (1)" 1 =<< getChannelCount c
        putMVar step2 () -- cancel runShell thread now
        readMVar step3   -- wait for runShell thread to be canceled
        sendMessage serverStream $ ChannelOpenConfirmation lid rid ws ps
        assertEqual "req2" req2 =<< receiveMessage serverStream
        assertEqual "channel count (1)" 1 =<< getChannelCount c
        sendMessage serverStream $ ChannelClose lid
        threadDelay 10000 -- wait for client cleanup
        assertEqual "channel count after" 0 =<< getChannelCount c
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelClose rid

testSessionShellOpen10 :: TestTree
testSessionShellOpen10 = testCase "shall close properly even if canceled before channel open failed" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    mc    <- newEmptyMVar
    step1 <- newEmptyMVar
    step2 <- newEmptyMVar
    step3 <- newEmptyMVar
    let action = withConnection conf clientStream $ \c -> do
            putMVar mc c
            readMVar step1
            let s = runShell c $ SessionHandler $ \_ _ _ _ -> pure ()
            withAsync s $ \shellThread -> do
                readMVar step2
                cancel shellThread
                putMVar step3 ()
                threadDelay 1000000 -- wait till end of test
    withAsync action $ \_ -> do
        c <- readMVar mc
        assertEqual "channel count before" 0 =<< getChannelCount c
        putMVar step1 ()
        assertEqual "req1" req1 =<< receiveMessage serverStream
        assertEqual "channel count (1)" 1 =<< getChannelCount c
        putMVar step2 () -- cancel runShell thread now
        readMVar step3   -- wait for runShell thread to be canceled
        sendMessage serverStream res1
        threadDelay 10000 -- wait for client cleanup
        assertEqual "channel count after" 0 =<< getChannelCount c
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        res1 = ChannelOpenFailure lid ChannelOpenAdministrativelyProhibited "" ""

testSessionShellOpen11 :: TestTree
testSessionShellOpen11 = testCase "shall close properly when close initiated by server" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    mc    <- newEmptyMVar
    step1 <- newEmptyMVar
    step2 <- newEmptyMVar
    let action = withConnection conf clientStream $ \c -> do
            putMVar mc c
            readMVar step1
            let s = runShell c $ SessionHandler $ \_ _ _ exitSTM -> do
                    threadDelay 10000
                    readMVar step2
                    atomically exitSTM
            withAsync s wait
    withAsync action $ \thread -> do
        c <- readMVar mc
        assertEqual "channel count before" 0 =<< getChannelCount c
        putMVar step1 ()
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- runShell request / success
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- close / close
        sendMessage serverStream sc3
        assertEqual "cs3" cs3 =<< receiveMessage serverStream
        -- wait for and check exit code
        putMVar step2 ()
        wait thread >>= \case
            Left  es -> assertFailure (show es)
            Right ec -> assertEqual "exit code" (ExitFailure (-1)) ec

        threadDelay 10000 -- wait for client cleanup
        assertEqual "channel count after" 0 =<< getChannelCount c
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelClose lid
        cs3  = ChannelClose rid

testSessionShellRequest01 :: TestTree
testSessionShellRequest01 = testCase "unknown requests shall be rejected (when wantReply=True)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \_ _ _ _ ->
                    threadDelay 1000000 -- wait for end of test
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- unknown request / response
        sendMessage serverStream sc3
        assertEqual "cs3" cs3 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelRequest lid "req-unknown" True ""
        cs3  = ChannelFailure rid

testSessionShellRequest02 :: TestTree
testSessionShellRequest02 = testCase "unknown requests shall be ignored (when wantReply=False)" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \_ _ _ _ ->
                    threadDelay 10000
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- unknown request
        sendMessage serverStream sc3
        -- eof and close
        assertEqual "cs3" cs3 =<< receiveMessage serverStream
        assertEqual "cs4" cs4 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelRequest lid "req-unknown" False ""
        cs3  = ChannelEof rid
        cs4  = ChannelClose rid

testSessionShellRequest03 :: TestTree
testSessionShellRequest03 = testCase "'exit-status' shall be passed to the session handler" $ do
    mes <- newEmptyMVar
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \_ _ _ exitSTM ->
                    putMVar mes =<< atomically exitSTM
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- exit-status request
        sendMessage serverStream sc3
        -- eof and close
        assertEqual "exit-status" es =<< readMVar mes
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelRequest lid "exit-status" False "\NUL\NUL\NUL\NUL"
        es   = Right ExitSuccess

testSessionShellRequest04 :: TestTree
testSessionShellRequest04 = testCase "'exit-signal' shall be passed to the session handler" $ do
    mes <- newEmptyMVar
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \_ _ _ exitSTM ->
                    putMVar mes =<< atomically exitSTM
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- exit-status request
        sendMessage serverStream sc3
        -- eof and close
        assertEqual "exit-status" es =<< readMVar mes
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelRequest lid "exit-signal" False $ runPut $ put sig
        sig  = ChannelRequestExitSignal "INTR" False "" ""
        es   = Left (ExitSignal "INTR" False "")

testSessionShellData01 :: TestTree
testSessionShellData01 = testCase "shall receive data on stdout" $ do
    rcvd <- newEmptyMVar
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \_ stdout _ _ -> do
                        x <- receiveAll stdout 4
                        putMVar rcvd x
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- send data
        sendMessage serverStream sc3
        assertEqual "rcvd" "ABCD"  =<< readMVar rcvd
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelData lid "ABCD"

testSessionShellData02 :: TestTree
testSessionShellData02 = testCase "shall receive data on stderr" $ do
    rcvd <- newEmptyMVar
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \_ _ stderr _ -> do
                        x <- receiveAll stderr 4
                        putMVar rcvd x
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- send data
        sendMessage serverStream sc3
        assertEqual "rcvd" "ABCD"  =<< readMVar rcvd
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelExtendedData lid 1 "ABCD"

testSessionShellData03 :: TestTree
testSessionShellData03 = testCase "shall send data when writing stdin" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \stdin _ _ _ -> do
                        void $ sendAll stdin "ABCD" 
                        threadDelay 1000000
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- receive data
        assertEqual "cs3" cs3 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        cs3  = ChannelData rid "ABCD"

testSessionShellData04 :: TestTree
testSessionShellData04 = testCase "shall throw exception when window size exceeded" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \stdin _ _ _ ->
                        threadDelay 1000000
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- message exceeds window size
        sendMessage serverStream sc3
        waitCatch thread >>= \case
            Right () -> assertFailure "should have thrown"
            Left e -> case fromException e of
                Nothing -> assertFailure "wrong exception"
                Just e' -> assertEqual "exception" exceptionWindowSizeUnderrun e'
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 3
        ps   = 128
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelData lid "ABCD"

testSessionShellData05 :: TestTree
testSessionShellData05 = testCase "shall throw exception when packet size exceeded" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \stdin _ _ _ ->
                        threadDelay 1000000
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- message exceeds window size
        sendMessage serverStream sc3
        waitCatch thread >>= \case
            Right () -> assertFailure "should have thrown"
            Left e -> case fromException e of
                Nothing -> assertFailure "wrong exception"
                Just e' -> assertEqual "exception" exceptionPacketSizeExceeded e'
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 128
        ps   = 3
        cs1  = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelData lid "ABCD"

testSessionShellData06 :: TestTree
testSessionShellData06 = testCase "shall adjust window size when necessary" $ do
    step1 <- newEmptyMVar
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let s = runShell c $ SessionHandler $ \stdin stdout _ _ -> do
                        void $ receiveAll stdout 2
                        void $ sendAll stdin "CD"
                        void $ receiveAll stdout 2
                        -- stdout size should now be 0
                        -- stdout window should now be 1
                        readMVar step1
            withAsync s wait
    withAsync action $ \thread -> do
        -- open / open confirmation
        assertEqual "cs1" cs1 =<< receiveMessage serverStream
        sendMessage serverStream sc1
        -- shell request / response
        assertEqual "cs2" cs2 =<< receiveMessage serverStream
        sendMessage serverStream sc2
        -- send 2 bytes / receive 2 bytes (no window adjust yet)
        sendMessage serverStream sc3
        assertEqual "cs3" cs3 =<< receiveMessage serverStream
        -- send 2 more bytes (window adjust now)
        sendMessage serverStream sc4
        assertEqual "cs4" cs4 =<< receiveMessage serverStream
        -- unblock handler
        putMVar step1 ()
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            , getEnvironment       = pure (Environment [])
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 5
        ps   = 128
        cs1  = O090 $ ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        sc1  = ChannelOpenConfirmation lid rid ws ps
        cs2  = O098 $ ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        sc2  = ChannelSuccess lid
        sc3  = ChannelData lid "AB"
        cs3  = O094 $ ChannelData rid "CD"
        sc4  = ChannelData lid "EF"
        cs4  = O093 $ ChannelWindowAdjust rid 4
