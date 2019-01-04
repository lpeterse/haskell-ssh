{-# LANGUAGE OverloadedStrings          #-}
module Spec.Transport ( tests ) where

import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad ( void )
import qualified Crypto.PubKey.Ed25519    as Ed25519
import           Data.Default

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Internal

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Transport"
    [ test01
    , test02
    , test03
    , test033
    , test04
    , test05
    , test06
    , test07
    ]

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

test03 :: TestTree
test03 = testCase "server sends first message, client receives" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket def `finally` close clientSocket) $ \client -> do
            (s,c) <- waitBoth server client
            assertEqual "s" (Right ()) s
            assertEqual "c" (Right "ABCD") c
    where
        runServer stream config agent = withServerTransport config stream agent $ \transport _ -> do
            sendMessage transport (ChannelData (ChannelId 0) "ABCD")
            pure ()
        runClient stream config  = withClientTransport config stream $ \transport _ _ -> do
            ChannelData _ msg <- receiveMessage transport
            pure msg

test04 :: TestTree
test04 = testCase "client sends incorrect version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server -> do
        sendAll clientSocket "GET / HTTP/1.1\n\n"
        wait server >>= assertEqual "res" (Left exceptionProtocolVersionNotSupported)
    where
        runServer stream config agent = withServerTransport config stream agent (const pure)

test05 :: TestTree
test05 = testCase "client sends incomplete version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server -> do
        sendAll clientSocket "SSH-2.0-OpenSSH_4.3"
        wait server >>= assertEqual "res" (Left exceptionProtocolVersionNotSupported)
    where
        runServer stream config agent = withServerTransport config stream agent (const pure)

test06 :: TestTree
test06 = testCase "client disconnects hard before sending version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server -> do
        close clientSocket
        wait server >>= assertEqual "res" (Left exceptionConnectionLost)
    where
        runServer stream config agent = withServerTransport config stream agent (const pure)

test07 :: TestTree
test07 = testCase "client disconnects gracefully after sending version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    agent <- (\sk -> KeyPairEd25519 (Ed25519.toPublic sk) sk) <$> Ed25519.generateSecretKey
    withAsync (runServer serverSocket def agent `finally` close serverSocket) $ \server -> do
        sendAll clientSocket $ runPut $ put $ Version "SSH-2.0-OpenSSH_4.3"
        void $ plainEncryptionContext clientSocket 0 (put $ Disconnected DisconnectByApplication "ABC" mempty)
        wait server >>= assertEqual "res" (Left $ Disconnect Remote DisconnectByApplication "ABC")
    where
        runServer stream config agent = withServerTransport config stream agent (const pure)

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