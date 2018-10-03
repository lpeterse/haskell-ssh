{-# LANGUAGE OverloadedStrings          #-}
module Spec.Transport ( tests ) where

import           Control.Concurrent.Async
import           Control.Exception
import qualified Crypto.PubKey.Ed25519    as Ed25519

import           Test.Tasty
import           Test.Tasty.HUnit

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
    withAsync (runServer serverSocket serverConf) $ \server ->
        withAsync (runClient clientSocket clientConf) $ \client -> do
            (sid1,sid2) <- waitBoth server client
            assertEqual "session ids" sid1 sid2
    where
        runServer stream config  = withTransport config stream (const pure)
        runClient stream config  = withTransport config stream (const pure)
        serverConfig sk          = TransportServerConfig
            { tHostKeys          = pure (KeyPairEd25519 (Ed25519.toPublic sk) sk)
            , tKexAlgorithms     = pure Curve25519Sha256AtLibsshDotOrg
            , tEncAlgorithms     = pure Chacha20Poly1305AtOpensshDotCom
            }
        clientConfig             = TransportClientConfig
            { tHostKeyAlgorithms = pure SshEd25519
            , tKexAlgorithms     = pure Curve25519Sha256AtLibsshDotOrg
            , tEncAlgorithms     = pure Chacha20Poly1305AtOpensshDotCom
            }

test02 :: TestTree
test02 = testCase "server sends first message, client receives" $ do
    (clientSocket, serverSocket) <- newSocketPair
    serverConf <- serverConfig <$> Ed25519.generateSecretKey
    clientConf <- pure clientConfig
    withAsync (runServer serverSocket serverConf) $ \server ->
        withAsync (runClient clientSocket clientConf) $ \client -> do
            ((),msg) <- waitBoth server client
            assertEqual "msg" "ABCD" msg
    where
        serverConfig sk          = TransportServerConfig
            { tHostKeys          = pure (KeyPairEd25519 (Ed25519.toPublic sk) sk)
            , tKexAlgorithms     = pure Curve25519Sha256AtLibsshDotOrg
            , tEncAlgorithms     = pure Chacha20Poly1305AtOpensshDotCom
            }
        clientConfig             = TransportClientConfig
            { tHostKeyAlgorithms = pure SshEd25519
            , tKexAlgorithms     = pure Curve25519Sha256AtLibsshDotOrg
            , tEncAlgorithms     = pure Chacha20Poly1305AtOpensshDotCom
            }
        runServer stream config  = withTransport config stream $ \transport _ -> do
            sendMessage transport (ChannelData (ChannelId 0) "ABCD")
            pure ()
        runClient stream config  = withTransport config stream $ \transport _ -> do
            ChannelData _ msg <- receiveMessage transport
            pure msg