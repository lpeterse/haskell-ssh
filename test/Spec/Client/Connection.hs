{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase        #-}
module Spec.Client.Connection ( tests ) where

import           Control.Concurrent          ( threadDelay )
import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Exception           ( AssertionFailed (..), fromException, throw, throwIO )
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.ByteString          as BS
import           Data.Default
import           System.Exit

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Client
import           Network.SSH.Internal hiding ( ConnectionConfig (..) )

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
        [ testGroup "shell"
            [ testSessionShell01
            , testSessionShell02
            , testSessionShell03
            , testSessionShell04
            , testSessionShell05
            , testSessionShell06
            , testSessionShell07
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

testSessionShell01 :: TestTree
testSessionShell01 = testCase "shall send channel open request" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c ->
            shell c $ SessionHandler $ \_ _ _ _ -> pure ()
    withAsync action $ \thread ->
        assertEqual "req1" req1 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            }
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession

testSessionShell02 :: TestTree
testSessionShell02 = testCase "shall increase channel ids when requesting several channels" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let action = withConnection conf clientStream $ \c -> do
            let x = shell c $ SessionHandler $ \_ _ _ _ -> pure ()
            withAsync x $ \_ -> threadDelay 10000 >> x
    withAsync action $ \_ -> do
        assertEqual "req1" req1 =<< receiveMessage serverStream
        assertEqual "req2" req2 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            }
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelOpen (ChannelId 1) ws ps ChannelOpenSession

testSessionShell03 :: TestTree
testSessionShell03 = testCase "shall throw exception when channel open failed" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    invoked <- newEmptyMVar
    let s c    = shell c $ SessionHandler $ \_ _ _ _ -> pure ()
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
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        exp2 = ChannelOpenFailed ChannelOpenAdministrativelyProhibited (ChannelOpenFailureDescription "")

testSessionShell04 :: TestTree
testSessionShell04 = testCase "shall request shell when channel open confirmed" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let s c    = shell c $ SessionHandler $ \_ _ _ _ -> pure ()
    let action = withConnection conf clientStream s
    withAsync action $ \_ -> do
        assertEqual "req1" req1 =<< receiveMessage serverStream
        sendMessage serverStream $ ChannelOpenConfirmation lid rid ws ps
        assertEqual "req2" req2 =<< receiveMessage serverStream
    where
        conf = def
            { channelMaxQueueSize  = ws
            , channelMaxPacketSize = ps
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)

testSessionShell05 :: TestTree
testSessionShell05 = testCase "shall throw exception when shell request failed" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    me <- newEmptyMVar
    let s c = shell c $ SessionHandler $ \_ _ _ _ -> pure ()
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
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        exp3 = ChannelRequestFailed

testSessionShell06 :: TestTree
testSessionShell06 = testCase "shall invoke session handler when shell request successful" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    me <- newEmptyMVar
    let s c = shell c $ SessionHandler $ \_ _ _ _ -> pure 123
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
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)

testSessionShell07 :: TestTree
testSessionShell07 = testCase "shall send eof and close after session handler returned" $ do
    (serverStream,clientStream) <- newDummyTransportPair
    let s c = shell c $ SessionHandler $ \_ _ _ _ -> pure 123
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
            }
        lid  = ChannelId 0
        rid  = ChannelId 1
        ws   = 4096
        ps   = 128
        req1 = ChannelOpen (ChannelId 0) ws ps ChannelOpenSession
        req2 = ChannelRequest rid "shell" True $ runPut (put ChannelRequestShell)
        req3 = ChannelEof rid
        req4 = ChannelClose rid
