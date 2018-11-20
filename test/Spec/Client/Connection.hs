{-# LANGUAGE OverloadedStrings #-}
module Spec.Client.Connection ( tests ) where
    
import           Control.Concurrent.Async
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.ByteString          as BS
import           Data.Default

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Client
import           Network.SSH.Internal

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Client.Connection"
    [ testInactive01
    ]

testInactive01 :: TestTree
testInactive01 = testCase "request user auth service" $ do
    pure ()
{-
    (client, server) <- newDummyTransportPair
    withAsync (withAuthentication def server sess with) $ \_ -> do
        sendMessage client req0
        receiveMessage client >>= assertEqual "res0" res0
    where
        sess = SessionId mempty
        with _ = Just undefined
        req0 = ServiceRequest (Name "ssh-userauth")
        res0 = ServiceAccept (Name "ssh-userauth")
-}
