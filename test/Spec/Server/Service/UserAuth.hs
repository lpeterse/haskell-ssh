{-# LANGUAGE OverloadedStrings #-}
module Spec.Server.Service.UserAuth ( tests ) where
    
import           Control.Concurrent.Async
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.ByteString          as BS

import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Message
import           Network.SSH.Server.Config

import           Test.Tasty
import           Test.Tasty.HUnit

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Server.Service.UserAuth"
    [ testGroup "service inactive (state 0)"
        [ testInactive01
        , testInactive02
        , testInactive03
        ]
    , testGroup "service active (state 1)"
        [ testActive01
        , testActive02
        , testActive03
        , testActive04
        , testActive05
        , testActive06
        , testActive07
        ]
    ]

testInactive01 :: TestTree
testInactive01 = testCase "request user auth service" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config server sess with) $ \_ -> do
        sendMessage client req0
        receiveMessage client >>= assertEqual "res0" res0
    where
        sess = SessionId mempty
        with = const undefined
        req0 = ServiceRequest (ServiceName "ssh-userauth")
        res0 = ServiceAccept (ServiceName "ssh-userauth")

testInactive02 :: TestTree
testInactive02 = testCase "request other service" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config server sess with) $ \thread -> do
        sendMessage client req0
        assertThrows "exp0" exp0 (wait thread)
    where
        sess = SessionId mempty
        with = const undefined
        req0 = ServiceRequest (ServiceName "other-service")
        exp0 = Disconnect DisconnectServiceNotAvailable mempty mempty

testInactive03 :: TestTree
testInactive03 = testCase "dispatch other message" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config server sess with) $ \thread -> do
        sendMessage client req0
        assertThrows "exp0" exp0 (wait thread)
    where
        sess = SessionId mempty
        with = const undefined
        req0 = MsgUnknown 1
        exp0 = Disconnect DisconnectProtocolError "invalid/unexpected message" mempty

testActive01 :: TestTree
testActive01 = testCase "authenticate by public key (no signature)" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config server sess with) $ \_ -> do
        sendMessage client req0
        receiveMessage client >>= assertEqual "res0" res0
        sendMessage client req1
        receiveMessage client >>= assertEqual "res1" res1
    where
        with = const undefined
        user = UserName "fnord"
        srvc = ServiceName "ssh-connection"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("\185\EOT\150\CAN\142)\175\161\242\141/\SI\214=n$?\189Z\172\214\190\EM\190^\226\r\241\197\&8\235\130" :: BS.ByteString))
        auth = AuthPublicKey algo pubk Nothing
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = ServiceAccept (ServiceName "ssh-userauth")
        req1 = MsgUserAuthRequest $ UserAuthRequest user srvc auth
        res1 = UserAuthPublicKeyOk algo pubk
        pass (CryptoPassed x) = x
        pass _                = undefined

testActive02 :: TestTree
testActive02 = testCase "authenticate by public key (incorrect signature)" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config server sess with) $ \_ -> do
        sendMessage client req0
        receiveMessage client >>= assertEqual "res0" res0
        sendMessage client req1
        receiveMessage client >>= assertEqual "res1" res1
    where
        with = const undefined
        user = UserName "fnord"
        srvc = ServiceName "ssh-connection"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("\185\EOT\150\CAN\142)\175\161\242\141/\SI\214=n$?\189Z\172\214\190\EM\190^\226\r\241\197\&8\235\130" :: BS.ByteString))
        sign = SignatureEd25519 (pass $ Ed25519.signature ("\NUL\NULG\NULw2\NUL\b|\ETX\239\136\213&|\145Zp\ACK\240p\243\128\vL\139N\ESC\207LI\t?\139D\DC36\206\252p\172\190)\238 {\\*\206\203\253\176\vE\EM\SYNkG\211\&2\192\201\EOT\ACK" :: BS.ByteString))
        auth = AuthPublicKey (Algorithm "ssh-ed25519") pubk (Just sign)
        req0 = ServiceRequest (ServiceName "ssh-userauth")
        res0 = ServiceAccept (ServiceName "ssh-userauth")
        req1 = UserAuthRequest user srvc auth
        res1 = UserAuthFailure [AuthMethodName "publickey"] False
        pass (CryptoPassed x) = x
        pass _                = undefined

testActive03 :: TestTree
testActive03 = testCase "authenticate by public key (correct signature, user accepted)" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config { onAuthRequest = onAuth } server sess with) $ \thread -> do
        sendMessage client req0
        receiveMessage client >>= assertEqual "res0" res0
        sendMessage client req1
        receiveMessage client >>= assertEqual "res1" res1
        wait thread >>= assertEqual "idnt" idnt
    where
        idnt = "identity" :: String
        user = UserName "fnord"
        srvc = ServiceName "ssh-connection"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("\185\EOT\150\CAN\142)\175\161\242\141/\SI\214=n$?\189Z\172\214\190\EM\190^\226\r\241\197\&8\235\130" :: BS.ByteString))
        sign = SignatureEd25519 (pass $ Ed25519.signature ("\152\211G\164w2\253\b|\ETX\239\136\213&|\145Zp\ACK\240p\243\128\vL\139N\ESC\207LI\t?\139D\DC36\206\252p\172\190)\238 {\\*\206\203\253\176\vE\EM\SYNkG\211\&2\192\201\EOT\ACK" :: BS.ByteString))
        auth = AuthPublicKey algo pubk (Just sign)
        req0 = ServiceRequest (ServiceName "ssh-userauth")
        res0 = ServiceAccept (ServiceName "ssh-userauth")
        req1 = UserAuthRequest user srvc auth
        res1 = UserAuthSuccess
        pass (CryptoPassed x) = x
        pass _                = undefined
        with = pure
        onAuth u s p
            | u /= user = pure Nothing
            | s /= srvc = pure Nothing
            | p /= pubk = pure Nothing
            | otherwise = pure (Just idnt)

testActive04 :: TestTree
testActive04 = testCase "authenticate by public key (correct signature, user accepted, service not available)" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config { onAuthRequest = \_ _ _ -> pure (Just idnt) } server sess with) $ \thread -> do
        sendMessage client req0
        receiveMessage client >>= assertEqual "res0" res0
        sendMessage client req1
        assertThrows "exp1" exp1 $ wait thread
    where
        idnt = "identity" :: String
        user = UserName "fnord"
        srvc = ServiceName "unavailable-service"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("J\190r%\232\247\220\n\160\129m\132\RS\193\NULL\128\152}\142\SUB\161\f\229\f\137\254M\192>n\182" :: BS.ByteString))
        sign = SignatureEd25519 (pass $ Ed25519.signature ("\244\173\199<\202 \204Q\185z\EOTU\v\236\&37\"u\248TE^3fk\158|@^\215\142\DC4\234\234\DC1\224\236\FS{\CAN\144^\140\148X\169\174+\\:y\226\&9K\141\182:\NUL_\245\DC1a\228\b" :: BS.ByteString))
        auth = AuthPublicKey algo pubk (Just sign)
        req0 = ServiceRequest (ServiceName "ssh-userauth")
        res0 = ServiceAccept (ServiceName "ssh-userauth")
        req1 = UserAuthRequest user srvc auth
        exp1 = Disconnect DisconnectServiceNotAvailable mempty mempty
        pass (CryptoPassed x) = x
        pass _                = undefined
        with = pure

testActive05 :: TestTree
testActive05 = testCase "authenticate by public key (correct signature, user rejected)" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config { onAuthRequest = \_ _ _ -> pure Nothing } server sess with) $ \_ -> do
        sendMessage client req0
        receiveMessage client >>= assertEqual "res0" res0
        sendMessage client req1
        receiveMessage client >>= assertEqual "res1" res1
    where
        user = UserName "fnord"
        srvc = ServiceName "ssh-connection"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("\185\EOT\150\CAN\142)\175\161\242\141/\SI\214=n$?\189Z\172\214\190\EM\190^\226\r\241\197\&8\235\130" :: BS.ByteString))
        sign = SignatureEd25519 (pass $ Ed25519.signature ("\152\211G\164w2\253\b|\ETX\239\136\213&|\145Zp\ACK\240p\243\128\vL\139N\ESC\207LI\t?\139D\DC36\206\252p\172\190)\238 {\\*\206\203\253\176\vE\EM\SYNkG\211\&2\192\201\EOT\ACK" :: BS.ByteString))
        auth = AuthPublicKey algo pubk (Just sign)
        req0 = ServiceRequest (ServiceName "ssh-userauth")
        res0 = ServiceAccept (ServiceName "ssh-userauth")
        req1 = UserAuthRequest user srvc auth
        res1 = UserAuthFailure [AuthMethodName "publickey"] False
        pass (CryptoPassed x) = x
        pass _                = undefined
        with = pure

testActive06 :: TestTree
testActive06 = testCase "authenticate by public key (key/signature type mismatch)" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config { onAuthRequest = \_ _ _ -> pure Nothing } server sess with) $ \_ -> do
        sendMessage client req0
        receiveMessage client >>= assertEqual "res0" res0
        sendMessage client req1
        receiveMessage client >>= assertEqual "res1" res1
    where
        user = UserName "fnord"
        srvc = ServiceName "ssh-connection"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyRSA $ RSA.PublicKey 24 65537 2834792
        sign = SignatureEd25519 (pass $ Ed25519.signature ("\152\211G\164w2\253\b|\ETX\239\136\213&|\145Zp\ACK\240p\243\128\vL\139N\ESC\207LI\t?\139D\DC36\206\252p\172\190)\238 {\\*\206\203\253\176\vE\EM\SYNkG\211\&2\192\201\EOT\ACK" :: BS.ByteString))
        auth = AuthPublicKey algo pubk (Just sign)
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = ServiceAccept (ServiceName "ssh-userauth")
        req1 = MsgUserAuthRequest $ UserAuthRequest user srvc auth
        res1 = UserAuthFailure [AuthMethodName "publickey"] False
        pass (CryptoPassed x) = x
        pass _                = undefined
        with = pure

testActive07 :: TestTree
testActive07 = testCase "authenticate by other method (AuthNone)" $ do
    config <- newDefaultConfig
    (client, server) <- newDummyTransportPair
    withAsync (withUserAuth config { onAuthRequest = \_ _ _ -> pure Nothing } server sess with) $ \_ -> do
        sendMessage client req0
        receiveMessage client >>= assertEqual "res0" res0
        sendMessage client req1
        receiveMessage client >>= assertEqual "res1" res1
    where
        sess = SessionId mempty
        req0 = ServiceRequest (ServiceName "ssh-userauth")
        res0 = ServiceAccept (ServiceName "ssh-userauth")
        req1 = UserAuthRequest (UserName "fnord") (ServiceName "ssh-connection") AuthNone
        res1 = UserAuthFailure [AuthMethodName "publickey"] False
        with = pure
