{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE LambdaCase, FlexibleContexts #-}
module Spec.Server ( tests ) where

import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad
import           Control.Monad.STM
import           Control.Concurrent.STM.TMVar
import qualified Data.ByteString as BS
import qualified Data.ByteArray as BA
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.Hash              as Hash

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Server
import           Network.SSH.Stream
import           Network.SSH.Constants
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Encoding
import           Network.SSH.Server.Transport
import           Network.SSH.Server.Transport.KeyExchange

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Server"
    [ testGroup "version string exchange"
        [ testVersionStringExchange01
        , testVersionStringExchange02
        ]
    , testGroup "key exchange" 
        [ testKeyExchange01
        , testKeyExchange02
        , testKeyExchange03
        ]
    , testGroup "transport layer"
        [ testTransportLayer01
        ]
    ]

testVersionStringExchange01 :: TestTree
testVersionStringExchange01 = testCase "server exit on invalid client version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    config <- newDefaultConfig
    withAsync (serve config serverSocket `finally` close serverSocket) $ \server -> do
        void $ sendAll clientSocket "GET / HTTP/1.1\n\n"
        assertEqual "server response" mempty =<< receive clientSocket 1024
        waitCatch server >>= \case
            Right () -> assertFailure "should have failed"
            Left e 
                | fromException e == Just exp0 -> pure ()
                | otherwise -> assertFailure "wrong exception"
    where
        exp0 = Disconnect DisconnectProtocolVersionNotSupported mempty mempty

testVersionStringExchange02 :: TestTree
testVersionStringExchange02 = testCase "server sends version string after client version string" $ do
    (clientSocket, serverSocket) <- newSocketPair
    config <- newDefaultConfig
    withAsync (serve config serverSocket `finally` close serverSocket) $ const $ do
        void $ sendAll clientSocket "SSH-2.0-OpenSSH_4.3\r\n"
        assertEqual "server response" (serverVersion <> "\r\n") =<< receive clientSocket (BS.length serverVersion + 2)
    where
        Version serverVersion = version

testKeyExchange01 :: TestTree
testKeyExchange01 = testCase "happy path" $ do
    tmvar <- newEmptyTMVarIO
    (clientSocket, serverSocket) <- newSocketPair
    defaultConfig <- newDefaultConfig
    let config = defaultConfig { onDisconnect = atomically . putTMVar tmvar } 
    withAsync (serve config serverSocket `finally` close serverSocket) $ \thread -> do
        void $ sendAll clientSocket (clientVersion <> "\r\n")
        assertEqual "server version" (serverVersion <> "\r\n") =<< receive clientSocket (BS.length serverVersion + 2)
        withTransport config clientSocket $ \transport-> do
            void $ exchangeKeys config cv sv transport
            sendMessage transport disconnect
            waitCatch thread >>= \case
                Left e -> assertFailure (show e)
                Right () -> atomically (tryReadTMVar tmvar) >>= \case
                    Just (Right d) -> assertEqual "disconnect" disconnect d
                    Just (Left e)  -> assertFailure (show e)
                    Nothing        -> assertFailure "onDisconnect should have been called"
    where
        cv@(Version clientVersion) = Version "SSH-2.0-OpenSSH_4.3"
        sv@(Version serverVersion) = version
        disconnect = Disconnect DisconnectByApplication "yolo" mempty

testKeyExchange02 :: TestTree
testKeyExchange02 = testCase "graceful disconnect after version string" $ do
    tmvar <- newEmptyTMVarIO
    (clientSocket, serverSocket) <- newSocketPair
    defaultConfig <- newDefaultConfig
    let config = defaultConfig { onDisconnect = atomically . putTMVar tmvar } 
    withAsync (serve config serverSocket `finally` close serverSocket) $ \thread -> do
        void $ sendAll clientSocket (clientVersion <> "\r\n")
        assertEqual "server version" (serverVersion <> "\r\n") =<< receive clientSocket (BS.length serverVersion + 2)
        KexInit {} <- receivePlainMessage clientSocket
        sendPlainMessage clientSocket disconnect
        waitCatch thread >>= \case
            Left e -> assertFailure (show e)
            Right () -> atomically (tryReadTMVar tmvar) >>= \case
                Just (Right d) -> assertEqual "disconnect" disconnect d
                Just (Left e)  -> assertFailure (show e)
                Nothing        -> assertFailure "onDisconnect should have been called"
    where
        Version clientVersion = Version "SSH-2.0-OpenSSH_4.3"
        Version serverVersion = version
        disconnect = Disconnect DisconnectByApplication "yolo" mempty

testKeyExchange03 :: TestTree
testKeyExchange03 = testCase "graceful disconnect after kex init" $ do
    tmvar <- newEmptyTMVarIO
    (clientSocket, serverSocket) <- newSocketPair
    defaultConfig <- newDefaultConfig
    let config = defaultConfig { onDisconnect = atomically . putTMVar tmvar } 
    withAsync (serve config serverSocket `finally` close serverSocket) $ \thread -> do
        void $ sendAll clientSocket (clientVersion <> "\r\n")
        assertEqual "server version" (serverVersion <> "\r\n") =<< receive clientSocket (BS.length serverVersion + 2)
        cki <- newKexInit config
        sendPlainMessage clientSocket cki
        KexInit {} <- receivePlainMessage clientSocket
        sendPlainMessage clientSocket disconnect
        waitCatch thread >>= \case
            Left e -> assertFailure (show e)
            Right () -> atomically (tryReadTMVar tmvar) >>= \case
                Just (Right d) -> assertEqual "disconnect" disconnect d
                Just (Left e)  -> assertFailure (show e)
                Nothing        -> assertFailure "onDisconnect should have been called"
    where
        Version clientVersion = Version "SSH-2.0-OpenSSH_4.3"
        Version serverVersion = version
        disconnect = Disconnect DisconnectByApplication "yolo" mempty

testTransportLayer01 :: TestTree
testTransportLayer01 = testCase "graceful disconnect after kex init" $ do
    tmvar <- newEmptyTMVarIO
    (clientSocket, serverSocket) <- newSocketPair
    defaultConfig <- newDefaultConfig
    let config = defaultConfig { onDisconnect = atomically . putTMVar tmvar } 
    withAsync (serve config serverSocket `finally` close serverSocket) $ \thread -> do
        void $ sendAll clientSocket (clientVersion <> "\r\n")
        assertEqual "server version" (serverVersion <> "\r\n") =<< receive clientSocket (BS.length serverVersion + 2)
        cki <- newKexInit config
        sendPlainMessage clientSocket cki
        KexInit {} <- receivePlainMessage clientSocket
        sendPlainMessage clientSocket disconnect
        waitCatch thread >>= \case
            Left e -> assertFailure (show e)
            Right () -> atomically (tryReadTMVar tmvar) >>= \case
                Just (Right d) -> assertEqual "disconnect" disconnect d
                Just (Left e)  -> assertFailure (show e)
                Nothing        -> assertFailure "onDisconnect should have been called"
    where
        Version clientVersion = Version "SSH-2.0-OpenSSH_4.3"
        Version serverVersion = version
        disconnect = Disconnect DisconnectByApplication "yolo" mempty

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
