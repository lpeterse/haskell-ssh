{-# LANGUAGE OverloadedStrings #-}
module Spec.Client.UserAuth ( tests ) where
    
import           Control.Concurrent.Async
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.ByteString          as BS
import           Data.Default

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Client.UserAuth
import           Network.SSH.Internal

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Client.UserAuth"
    [ test01
    , test02
    , testGroup "public key authentication"
        [ testPubkey01
        , testPubkey02
        ]
    , testGroup "password authentication"
        [ testPassword01
        , testPassword02
        , testPassword03
        , testPassword04
        ]
    ]

test01 :: TestTree
test01 = testCase "should request ssh-userauth service" $ do
    (client, server) <- newDummyTransportPair
    withAsync (requestServiceWithAuthentication conf client sid srvc) $ \_ -> do
        assertEqual "res0" res0 =<< receiveMessage server
    where
        sid  = undefined
        conf = def
        srvc = Name "ssh-connection"
        res0 = ServiceRequest (Name "ssh-userauth")

test02 :: TestTree
test02 = testCase "should throw exception for default config" $ do
    (client, server) <- newDummyTransportPair
    withAsync (requestServiceWithAuthentication conf client sid srvc) $ \thread -> do
        assertEqual "res0" res0 =<< receiveMessage server
        sendMessage server req1
        assertThrows "exp2" exp2 $ wait thread
    where
        sid  = undefined
        conf = def
        srvc = Name "ssh-connection"
        res0 = ServiceRequest (Name "ssh-userauth")
        req1 = ServiceAccept (Name "ssh-userauth")
        exp2 = exceptionNoMoreAuthMethodsAvailable

testPubkey01 :: TestTree
testPubkey01 = testCase "should try pubkey authentication (when configured)" $ do
    (client, server) <- newDummyTransportPair
    withAsync (requestServiceWithAuthentication conf client sid srvc) $ \thread -> do
        assertEqual "res0" req0 =<< receiveMessage server
        sendMessage server res0
        assertEqual "req1" req1 =<< receiveMessage server
    where
        sid              = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        CryptoPassed sk  = Ed25519.secretKey ("O6J\227b\US\171lG\v$E\249\195\173\223\RS\227K\186,=\132\147\171\&9\166Q\196j\131\129" :: BS.ByteString)
        CryptoPassed sig = Ed25519.signature ("\178\RSJi\245\163\141\159V\242`\218\231bE\SOH\DC2\220M\214\221\217Y\195\203X\173\215\232\186\196\204\DC1v\236\239k\SO\243\CAN\241O\169\133\178W\194\DC4\NUL;K\154$N$\FS\224\244r\136\182\NAK\159\t" :: BS.ByteString)
        pk               = Ed25519.toPublic sk
        keypair          = KeyPairEd25519 pk sk
        conf = def { userName = user, getAgent = pure (Just keypair) }
        user = Name "USER"
        srvc = Name "ssh-connection"
        req0 = ServiceRequest (Name "ssh-userauth")
        res0 = ServiceAccept (Name "ssh-userauth")
        req1 = UserAuthRequest user srvc $ AuthPublicKey (PublicKeyEd25519 pk) (Just (SignatureEd25519 sig))

testPubkey02 :: TestTree
testPubkey02 = testCase "should return when public key accepted" $ do
    (client, server) <- newDummyTransportPair
    withAsync (requestServiceWithAuthentication conf client sid srvc) $ \thread -> do
        assertEqual "res0" req0 =<< receiveMessage server
        sendMessage server res0
        assertEqual "req1" req1 =<< receiveMessage server
        sendMessage server res1
        wait thread
    where
        sid              = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        CryptoPassed sk  = Ed25519.secretKey ("O6J\227b\US\171lG\v$E\249\195\173\223\RS\227K\186,=\132\147\171\&9\166Q\196j\131\129" :: BS.ByteString)
        CryptoPassed sig = Ed25519.signature ("\178\RSJi\245\163\141\159V\242`\218\231bE\SOH\DC2\220M\214\221\217Y\195\203X\173\215\232\186\196\204\DC1v\236\239k\SO\243\CAN\241O\169\133\178W\194\DC4\NUL;K\154$N$\FS\224\244r\136\182\NAK\159\t" :: BS.ByteString)
        pk               = Ed25519.toPublic sk
        keypair          = KeyPairEd25519 pk sk
        conf = def { userName = user, getAgent = pure (Just keypair) }
        user = Name "USER"
        srvc = Name "ssh-connection"
        req0 = ServiceRequest (Name "ssh-userauth")
        res0 = ServiceAccept (Name "ssh-userauth")
        req1 = UserAuthRequest user srvc $ AuthPublicKey (PublicKeyEd25519 pk) (Just (SignatureEd25519 sig))
        res1 = UserAuthSuccess

testPassword01 :: TestTree
testPassword01 = testCase "should try password authentication (when configured)" $ do
    (client, server) <- newDummyTransportPair
    withAsync (requestServiceWithAuthentication conf client sid srvc) $ \thread -> do
        assertEqual "res0" req0 =<< receiveMessage server
        sendMessage server res0
        assertEqual "req1" req1 =<< receiveMessage server
    where
        sid  = undefined
        user = Name "USER"
        pass = Password "PASSWORD"
        conf = def { userName = user, getPassword = pure (Just pass) }
        srvc = Name "ssh-connection"
        req0 = ServiceRequest (Name "ssh-userauth")
        res0 = ServiceAccept (Name "ssh-userauth")
        req1 = UserAuthRequest user srvc $ AuthPassword pass

testPassword02 :: TestTree
testPassword02 = testCase "should return when password accepted" $ do
    (client, server) <- newDummyTransportPair
    withAsync (requestServiceWithAuthentication conf client sid srvc) $ \thread -> do
        assertEqual "res0" req0 =<< receiveMessage server
        sendMessage server res0
        assertEqual "req1" req1 =<< receiveMessage server
        sendMessage server res1
        wait thread
    where
        sid  = undefined
        user = Name "USER"
        pass = Password "PASSWORD"
        conf = def { userName = user, getPassword = pure (Just pass) }
        srvc = Name "ssh-connection"
        req0 = ServiceRequest (Name "ssh-userauth")
        res0 = ServiceAccept (Name "ssh-userauth")
        req1 = UserAuthRequest user srvc $ AuthPassword pass
        res1 = UserAuthSuccess

testPassword03 :: TestTree
testPassword03 = testCase "should throw exception when password rejected" $ do
    (client, server) <- newDummyTransportPair
    withAsync (requestServiceWithAuthentication conf client sid srvc) $ \thread -> do
        assertEqual "res0" req0 =<< receiveMessage server
        sendMessage server res0
        assertEqual "req1" req1 =<< receiveMessage server
        sendMessage server res1
        assertThrows "exp2" exp2 $ wait thread
    where
        sid  = undefined
        user = Name "USER"
        pass = Password "PASSWORD"
        conf = def { userName = user, getPassword = pure (Just pass) }
        srvc = Name "ssh-connection"
        req0 = ServiceRequest (Name "ssh-userauth")
        res0 = ServiceAccept (Name "ssh-userauth")
        req1 = UserAuthRequest user srvc $ AuthPassword pass
        res1 = UserAuthFailure [] False
        exp2 = exceptionNoMoreAuthMethodsAvailable

testPassword04 :: TestTree
testPassword04 = testCase "should expect a banner in this state" $ do
    (client, server) <- newDummyTransportPair
    withAsync (requestServiceWithAuthentication conf client sid srvc) $ \thread -> do
        assertEqual "res0" req0 =<< receiveMessage server
        sendMessage server res0
        assertEqual "req1" req1 =<< receiveMessage server
        sendMessage server res10
        sendMessage server res11
        wait thread
    where
        sid   = undefined
        user  = Name "USER"
        pass  = Password "PASSWORD"
        conf  = def { userName = user, getPassword = pure (Just pass) }
        srvc  = Name "ssh-connection"
        req0  = ServiceRequest (Name "ssh-userauth")
        res0  = ServiceAccept (Name "ssh-userauth")
        req1  = UserAuthRequest user srvc $ AuthPassword pass
        res10 = UserAuthBanner "BANNER" "LANG"
        res11 = UserAuthSuccess
