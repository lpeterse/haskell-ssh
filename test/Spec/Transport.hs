{-# LANGUAGE OverloadedStrings          #-}
module Spec.Transport ( tests ) where

import           Control.Concurrent ( threadDelay )
import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Exception
import           Control.Monad ( forever, forM_, void )
import qualified Crypto.PubKey.Ed25519    as Ed25519
import           Data.Default

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Internal

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Transport"
    [ testGroup "server specific" 
        [ test01
        , test02
        , test033
        , test04
        , test05
        , test06
        , test07
        ]
    , testGroup "client specific"
        [
        ]
    , testGroup "sendMessage / receiveMessage" 
        [ testSendReceive01
        , testSendReceive02
        , testSendReceive05
        , testSendReceive06
        ]
    , testGroup "traffic accounting"
        [ testTraffic01
        , testTraffic02
        ]
    , testGroup "initial key exchange"
        [
        ]
    , testGroup "key re-exchange"
        [ testReKex01
        , testReKex02
        , testReKex03
        , testReKex04
        , testReKex05
        ]
    ]

test04 :: TestTree
test04 = testCase "server shall return ProtocolVersionNotSupported when client sends incorrect version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server -> do
        sendAll clientSocket "GET / HTTP/1.1\n\n"
        wait server >>= assertEqual "res" (Left exceptionProtocolVersionNotSupported)
    where
        runServer stream config agent = withServerTransport config stream agent (const pure)

test05 :: TestTree
test05 = testCase "server shall return ProtocolVersionNotSupprted when client sends incomplete version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server -> do
        sendAll clientSocket "SSH-2.0-OpenSSH_4.3"
        wait server >>= assertEqual "res" (Left exceptionProtocolVersionNotSupported)
    where
        runServer stream config agent = withServerTransport config stream agent (const pure)

test06 :: TestTree
test06 = testCase "server shall return ConnectionLost when client disconnects before sending version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server -> do
        close clientSocket
        wait server >>= assertEqual "res" (Left exceptionConnectionLost)
    where
        runServer stream config agent = withServerTransport config stream agent (const pure)

test07 :: TestTree
test07 = testCase "server shall return DisconnectByApplication when client disconnects gracefully after sending version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server -> do
        sendAll clientSocket $ runPut $ put $ Version "SSH-2.0-OpenSSH_4.3"
        void $ plainEncryptionContext clientSocket 0 (put $ Disconnected DisconnectByApplication "ABC" mempty)
        wait server >>= assertEqual "res" (Left $ Disconnect Remote DisconnectByApplication "ABC")
    where
        runServer stream config agent = withServerTransport config stream agent (const pure)

test01 :: TestTree
test01 = testCase "key exchange shall yield same session id on both sides" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket def `finally` close clientSocket) $ \client -> do
            (Right sid1, Right sid2) <- waitBoth server client
            assertEqual "session ids" sid1 sid2
    where
        runServer stream config agent = withServerTransport config stream agent (const pure)
        runClient stream config  = withClientTransport config stream $ \_ sid _ -> pure sid

---------------------------------------------------------------------------------------------------
-- CLIENT
---------------------------------------------------------------------------------------------------

test02 :: TestTree
test02 = testCase "client shall return server host key after key exchange" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket def `finally` close clientSocket) $ \client -> do
            (Right (), Right pk') <- waitBoth server client
            assertEqual "server host key" (PublicKeyEd25519 pk) pk'
    where
        runServer stream config agent = withServerTransport config stream agent $ \_ _ -> pure ()
        runClient stream config  = withClientTransport config stream $ \_ _ hk -> pure hk


---------------------------------------------------------------------------------------------------
-- GENERIC
---------------------------------------------------------------------------------------------------

test033 :: TestTree
test033 = testCase "client and server version shall be reported correctly" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    withAsync (runServer serverSocket serverConfig agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConfig `finally` close clientSocket) $ \client -> do
            (Right st, Right ct) <- waitBoth server client
            assertEqual "client version on client" (version clientConfig) (clientVersion ct)
            assertEqual "server version on client" (version serverConfig) (serverVersion ct)
            assertEqual "client version on server" (version clientConfig) (clientVersion st)
            assertEqual "server version on server" (version serverConfig) (serverVersion st)
    where
        runServer stream config agent = withServerTransport config stream agent $ \t _ -> pure t
        runClient stream config  = withClientTransport config stream $ \t _ _ -> pure t
        serverConfig = def { version = Version "SSH-2.0-hssh_server" }
        clientConfig = def { version = Version "SSH-2.0-hssh_client" }

---------------------------------------------------------------------------------------------------
-- SENDMESSAGE / RECEIVEMESSAGE
---------------------------------------------------------------------------------------------------

testSendReceive01 :: TestTree
testSendReceive01 = testCase "server sends Ignore and client shall receive it" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    done <- newEmptyMVar
    withAsync (runServer serverSocket def agent done `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket def done `finally` close clientSocket) $ \client -> do
            waitBoth server client
            readMVar done
    where
        runServer stream config agent done = withServerTransport config stream agent $ \t _ -> do
            sendMessage t Ignore
            readMVar done
        runClient stream config done = withClientTransport config stream $ \t _ _ -> do
            Ignore <- receiveMessage t
            putMVar done ()

testSendReceive02 :: TestTree
testSendReceive02 = testCase "server sends Ignore and client shall ignore it when expecting something else" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    done <- newEmptyMVar
    withAsync (runServer serverSocket def agent done `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket def done `finally` close clientSocket) $ \client -> do
            waitBoth server client
            readMVar done
    where
        runServer stream config agent done = withServerTransport config stream agent $ \t _ -> do
            sendMessage t Ignore
            sendMessage t (ChannelData (ChannelId 0) "ABC")
            readMVar done
        runClient stream config done = withClientTransport config stream $ \t _ _ -> do
            ChannelData (ChannelId 0) "ABC" <- receiveMessage t
            putMVar done ()

testSendReceive05 :: TestTree
testSendReceive05 = testCase "server sends ChannelData and client shall receive it" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    done <- newEmptyMVar
    withAsync (runServer serverSocket def agent done `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket def done `finally` close clientSocket) $ \client -> do
            waitBoth server client
            readMVar done
    where
        runServer stream config agent done = withServerTransport config stream agent $ \t _ -> do
            sendMessage t (ChannelData (ChannelId 0) "ABC")
            readMVar done
        runClient stream config done = withClientTransport config stream $ \t _ _ -> do
            ChannelData (ChannelId 0) "ABC" <- receiveMessage t
            putMVar done ()

testSendReceive06 :: TestTree
testSendReceive06 = testCase "client sends ChannelData and server shall receive it" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    done <- newEmptyMVar
    withAsync (runServer serverSocket def agent done `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket def done `finally` close clientSocket) $ \client -> do
            waitBoth server client
            readMVar done
    where
        runServer stream config agent done = withServerTransport config stream agent $ \t _ -> do
            ChannelData (ChannelId 0) "ABC" <- receiveMessage t
            putMVar done ()
        runClient stream config done = withClientTransport config stream $ \t _ _ -> do
            sendMessage t (ChannelData (ChannelId 0) "ABC")
            readMVar done

---------------------------------------------------------------------------------------------------
-- TRAFFIC ACCOUNTING
---------------------------------------------------------------------------------------------------

testTraffic01 :: TestTree
testTraffic01 = testCase "bytes sent/received shall match on client/server after key exchange" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    withAsync (runServer serverSocket serverConfig agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConfig `finally` close clientSocket) $ \client -> do
            (Right (stSent, stReceived), Right (ctSent, ctReceived)) <- waitBoth server client
            assertBool "client bytes sent != 0" (ctSent /= 0)
            assertBool "server bytes sent != 0" (stSent /= 0)
            assertBool "client bytes received != 0" (ctReceived /= 0)
            assertBool "server bytes received != 0" (stReceived /= 0)
            assertEqual "client bytes sent == server bytes received" ctSent stReceived
            assertEqual "server bytes sent == client bytes received" stSent ctReceived
    where
        runServer stream config agent = withServerTransport config stream agent $ \t _ -> do
            (,) <$> getBytesSent t <*> getBytesReceived t
        runClient stream config  = withClientTransport config stream $ \t _ _ -> do
            (,) <$> getBytesSent t <*> getBytesReceived t
        serverConfig = def
        clientConfig = def

testTraffic02 :: TestTree
testTraffic02 = testCase "packets sent/received shall match on client/server after key exchange" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    withAsync (runServer serverSocket serverConfig agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConfig `finally` close clientSocket) $ \client -> do
            (Right (stSent, stReceived), Right (ctSent, ctReceived)) <- waitBoth server client
            assertBool "client packets sent != 0" (ctSent /= 0)
            assertBool "server packets sent != 0" (stSent /= 0)
            assertBool "client packets received != 0" (ctReceived /= 0)
            assertBool "server packets received != 0" (stReceived /= 0)
            assertEqual "client packets sent == server packets received" ctSent stReceived
            assertEqual "server packets sent == client packets received" stSent ctReceived
    where
        runServer stream config agent = withServerTransport config stream agent $ \t _ -> do
            (,) <$> getPacketsSent t <*> getPacketsReceived t
        runClient stream config  = withClientTransport config stream $ \t _ _ -> do
            (,) <$> getPacketsSent t <*> getPacketsReceived t
        serverConfig = def
        clientConfig = def

---------------------------------------------------------------------------------------------------
-- INITIAL KEY EXCHANGE
---------------------------------------------------------------------------------------------------


---------------------------------------------------------------------------------------------------
-- KEY RE-EXCHANGE
---------------------------------------------------------------------------------------------------

testReKex01 :: TestTree
testReKex01 = testCase "kex counter shall be 1 right after initial key exchange" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    withAsync (runServer serverSocket serverConfig agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConfig `finally` close clientSocket) $ \client -> do
            (Right cs, Right cc) <- waitBoth server client
            assertEqual "client kex count" 1 cc
            assertEqual "server kex count" 1 cs
    where
        runServer stream config agent = withServerTransport config stream agent $ \t _ ->
            getKexCount t
        runClient stream config  = withClientTransport config stream $ \t _ _ -> do
            getKexCount t
        serverConfig = def
        clientConfig = def

testReKex02 :: TestTree
testReKex02 = testCase "server shall rekey when bytes sent is exceeded" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    done <- newEmptyMVar
    mt <- newEmptyMVar
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    let runServer stream config agent = withServerTransport config stream agent $ \t _ -> do
            putMVar mt t
            readMVar done -- keep the server alive till end of test
    let runClient stream config  = withClientTransport config stream $ \t _ _ -> forever $ do
            Ignore <- receiveMessage t -- keep the client responsive
            pure ()
    withAsync (runServer serverSocket serverConfig agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConfig `finally` close clientSocket) $ \client -> do
            t <- readMVar mt
            kexCount1 <- getKexCount t
            assertEqual "kexCount" 1 kexCount1
            sent0 <- getBytesSent t
            assertBool "sent0 does not exceed threshold" (sent0 < threshold)
            sendMessage t Ignore
            sent1 <- getBytesSent t
            assertBool "sent1 does not exceed threshold" (sent1 < threshold)
            let messageSize = sent1 - sent0
            let remainingSize = threshold - sent1
            let n = (remainingSize `div` messageSize) + 2
            forM_ [1..n] $ const $ sendMessage t Ignore
            sent2 <- getBytesSent t
            assertBool "sent2 does exceed threshold" (sent2 > threshold)
            kexCount2 <- getKexCount t
            assertEqual "kexCount" 2 kexCount2
            putMVar done ()
    where
        threshold = 1000
        serverConfig = def { maxDataBeforeRekey = threshold }
        clientConfig = def

testReKex03 :: TestTree
testReKex03 = testCase "client shall rekey when bytes sent is exceeded" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    done <- newEmptyMVar
    mt <- newEmptyMVar
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    let runServer stream config agent = withServerTransport config stream agent $ \t _ -> forever $ do
            Ignore <- receiveMessage t -- keep the server responsive
            pure ()
    let runClient stream config  = withClientTransport config stream $ \t _ _ -> do
            putMVar mt t
            readMVar done -- keep the client alive till end of test
    withAsync (runServer serverSocket serverConfig agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConfig `finally` close clientSocket) $ \client -> do
            t <- readMVar mt
            kexCount1 <- getKexCount t
            assertEqual "kexCount" 1 kexCount1
            sent0 <- getBytesSent t
            assertBool "sent0 does not exceed threshold" (sent0 < threshold)
            sendMessage t Ignore
            sent1 <- getBytesSent t
            assertBool "sent1 does not exceed threshold" (sent1 < threshold)
            let messageSize = sent1 - sent0
            let remainingSize = threshold - sent1
            let n = (remainingSize `div` messageSize) + 2
            forM_ [1..n] $ const $ sendMessage t Ignore
            sent2 <- getBytesSent t
            assertBool "sent2 does exceed threshold" (sent2 > threshold)
            kexCount2 <- getKexCount t
            assertEqual "kexCount" 2 kexCount2
            putMVar done ()
    where
        threshold = 1000
        serverConfig = def
        clientConfig = def { maxDataBeforeRekey = threshold }

testReKex04 :: TestTree
testReKex04 = testCase "server shall rekey when time is exceeded" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    done <- newEmptyMVar
    mt <- newEmptyMVar
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    let runServer stream config agent = withServerTransport config stream agent $ \t _ -> do
            putMVar mt t
            readMVar done -- keep the server alive till end of test
    let runClient stream config  = withClientTransport config stream $ \t _ _ -> forever $ do
            Ignore <- receiveMessage t -- keep the client responsive
            pure ()
    withAsync (runServer serverSocket serverConfig agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConfig `finally` close clientSocket) $ \client -> do
            t <- readMVar mt
            kexCount1 <- getKexCount t
            assertEqual "kexCount" 1 kexCount1
            threadDelay 1100000 -- 1.1 seconds
            sendMessage t Ignore -- send something to trigger rekeying
            kexCount2 <- getKexCount t
            assertEqual "kexCount" 2 kexCount2
            putMVar done ()
    where
        threshold = 1 -- 1 second
        serverConfig = def { maxTimeBeforeRekey = threshold }
        clientConfig = def

testReKex05 :: TestTree
testReKex05 = testCase "client shall rekey when time is exceeded" $ do
    (clientSocket, serverSocket) <- newSocketPair
    sk <- Ed25519.generateSecretKey
    done <- newEmptyMVar
    mt <- newEmptyMVar
    let pk = Ed25519.toPublic sk
    let agent = KeyPairEd25519 pk sk
    let runServer stream config agent = withServerTransport config stream agent $ \t _ -> forever $ do
            Ignore <- receiveMessage t -- keep the server responsive
            pure ()
    let runClient stream config  = withClientTransport config stream $ \t _ _ -> do
            putMVar mt t
            readMVar done -- keep the client alive till end of test
    withAsync (runServer serverSocket serverConfig agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConfig `finally` close clientSocket) $ \client -> do
            t <- readMVar mt
            kexCount1 <- getKexCount t
            assertEqual "kexCount" 1 kexCount1
            threadDelay 1100000 -- 1.1 seconds
            sendMessage t Ignore -- send something to trigger rekeying
            kexCount2 <- getKexCount t
            assertEqual "kexCount" 2 kexCount2
            putMVar done ()
    where
        threshold = 1 -- 1 second
        serverConfig = def
        clientConfig = def { maxTimeBeforeRekey = threshold }

{-
assertCorrectSignature ::
    Curve25519.SecretKey -> Curve25519.PublicKey ->
    Version -> Version ->
    KexInit -> KexInit ->
    KexEcdhReply -> Assertion
assertCorrectSignature csk cpk cv sv cki ski ser =
    assertBool "correct signature" $ Ed25519.verify k hash s
    where
        sig@(SignatureEd25519 s) = kexHashSignature ser
        shk@(PublicKeyEd25519 k) = kexServerHostKey ser
        spk    = kexServerEphemeralKey ser
        secret = Curve25519.dh spk csk
        hash  :: Hash.Digest Hash.SHA256
        hash   = Hash.hash $ runPut $ do
            putString cv
            putString sv
            putWord32 (len cki)
            put       cki
            putWord32 (len ski)
            put       ski
            put       shk
            put       cpk
            put       spk
            putAsMPInt secret

exchangeKeys :: Config identity -> Version -> Version -> Transport -> IO SessionId
exchangeKeys config cv sv transport = do
    cki <- newKexInit config
    sendMessage transport cki
    ski <- receiveMessage transport
    assertEqual "kex algorithms" ["curve25519-sha256@libssh.org"] (kexAlgorithms ski)
    assertEqual "kex algorithms server hostkey" ["ssh-ed25519"] (kexServerHostKeyAlgorithms ski)
    assertEqual "kex algorithms encryption client -> server" ["chacha20-poly1305@openssh.com"] (kexEncryptionAlgorithmsClientToServer ski)
    assertEqual "kex algorithms encryption server -> client" ["chacha20-poly1305@openssh.com"] (kexEncryptionAlgorithmsServerToClient ski)
    assertEqual "kex algorithms mac client -> server" [] (kexMacAlgorithmsClientToServer ski)
    assertEqual "kex algorithms mac server -> client" [] (kexMacAlgorithmsServerToClient ski)
    assertEqual "kex algorithms compression client -> server" ["none"] (kexCompressionAlgorithmsClientToServer ski)
    assertEqual "kex algorithms compression server -> client" ["none"] (kexCompressionAlgorithmsServerToClient ski)
    assertEqual "kex languages client -> server" [] (kexLanguagesClientToServer ski)
    assertEqual "kex languages server -> client" [] (kexLanguagesServerToClient ski)
    assertEqual "kex first packet follows" False (kexFirstPacketFollows ski)
    csk <- Curve25519.generateSecretKey
    cpk <- pure (Curve25519.toPublic csk)
    sendMessage transport (KexEcdhInit cpk)
    ser <- receiveMessage transport 
    assertCorrectSignature csk cpk cv sv cki ski ser
    -- set crypto context (client role)
    let shk = kexServerHostKey ser
        spk = kexServerEphemeralKey ser
        sec = Curve25519.dh spk csk
        sid = SessionId $ BA.convert hash
        hash :: Hash.Digest Hash.SHA256
        hash = Hash.hash $ runPut $ do
            putString  cv
            putString  sv
            putWord32  (len cki)
            put        cki
            putWord32  (len ski)
            put        ski
            put        shk
            put        cpk
            put        spk
            putAsMPInt sec
    setChaCha20Poly1305Context transport Client $ deriveKeys sec hash sid
    assertEqual "new keys" (MsgKexNewKeys KexNewKeys) =<< receiveMessage transport
    sendMessage transport KexNewKeys
    switchEncryptionContext transport
    switchDecryptionContext transport
    pure sid
-}