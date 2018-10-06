{-# LANGUAGE OverloadedStrings          #-}
module Spec.Transport ( tests ) where

import           Control.Concurrent.Async
import           Control.Exception
import qualified Crypto.PubKey.Ed25519    as Ed25519

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.AuthAgent
import           Network.SSH.Algorithms
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Transport

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Transport"
    [ test01
    , test02
    ]

test01 :: TestTree
test01 = testCase "key exchange yields same session id on both sides" $ do
    (clientSocket, serverSocket) <- newSocketPair
    serverConf <- serverConfig <$> Ed25519.generateSecretKey
    clientConf <- pure clientConfig
    withAsync (runServer serverSocket serverConf `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConf `finally` close clientSocket) $ \client -> do
            (Right sid1, Right sid2) <- waitBoth server client
            assertEqual "session ids" sid1 sid2
    where
        clientConfig             = defaultConfig
        serverConfig sk          = defaultConfig { tAuthAgent = Just $ fromKeyPair (KeyPairEd25519 (Ed25519.toPublic sk) sk) }
        runServer stream config  = withTransport config stream (const pure)
        runClient stream config  = withTransport config stream (const pure)

test02 :: TestTree
test02 = testCase "server sends first message, client receives" $ do
    (clientSocket, serverSocket) <- newSocketPair
    serverConf <- serverConfig <$> Ed25519.generateSecretKey
    clientConf <- pure clientConfig
    withAsync (runServer serverSocket serverConf `finally` close serverSocket) $ \server ->
        withAsync (runClient clientSocket clientConf `finally` close clientSocket) $ \client -> do
            (s,c) <- waitBoth server client
            assertEqual "s" (Right ()) s
            assertEqual "c" (Right "ABCD") c
    where
        clientConfig             = defaultConfig
        serverConfig sk          = defaultConfig { tAuthAgent = Just $ fromKeyPair (KeyPairEd25519 (Ed25519.toPublic sk) sk) }
        runServer stream config  = withTransport config stream $ \transport _ -> do
            sendMessage transport (ChannelData (ChannelId 0) "ABCD")
            pure ()
        runClient stream config  = withTransport config stream $ \transport _ -> do
            ChannelData _ msg <- receiveMessage transport
            pure msg

defaultConfig :: TransportConfig
defaultConfig = TransportConfig
    { tAuthAgent          = Nothing
    , tHostKeyAlgorithms  = pure SshEd25519
    , tKexAlgorithms      = pure Curve25519Sha256AtLibsshDotOrg
    , tEncAlgorithms      = pure Chacha20Poly1305AtOpensshDotCom
    , tOnSend             = const (pure ())
    , tOnReceive          = const (pure ())
    , tMaxTimeBeforeRekey = 3600
    , tMaxDataBeforeRekey = 1000 * 1000 * 1000 
    }