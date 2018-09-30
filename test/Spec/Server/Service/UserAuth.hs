{-# LANGUAGE OverloadedStrings #-}
module Spec.Server.Service.UserAuth ( tests ) where
    
import           Control.Applicative
import           Control.Concurrent (threadDelay)
import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad
import           Control.Monad.STM
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Crypto.Error
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.ByteString          as BS
import           System.Exit

import           Network.SSH.Server.Service.UserAuth
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Internal
import           Network.SSH.Stream (send, sendAll, receive)

import           Test.Tasty
import           Test.Tasty.HUnit

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
        , testActive09
        , testActive10
        ]
    ]

testInactive01 :: TestTree
testInactive01 = testCase "request user auth service" $ do
    chan <- newTChanIO
    done <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let withIdentity = undefined 
    conf <- newDefaultConfig
    dispatcher conf sess sender withIdentity req0 $
        Continuation $ \continue0 -> do
            assertEqual "res0" res0 =<< receiver
            atomically (writeTVar done True)
    assertEqual "done" True =<< atomically (readTVar done)
    where
        sess = SessionId mempty
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = Just $ MsgServiceAccept $ ServiceAccept (ServiceName "ssh-userauth")

testInactive02 :: TestTree
testInactive02 = testCase "request other service" $ do
    chan <- newTChanIO
    done <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let withIdentity = undefined 
    conf <- newDefaultConfig
    assertThrows "exp0" exp0 $ dispatcher conf sess sender withIdentity req0 $
        Continuation $ \continue0 -> pure ()
    where
        sess = SessionId mempty
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "invalid-service")
        exp0 = Disconnect DisconnectServiceNotAvailable mempty mempty

testInactive03 :: TestTree
testInactive03 = testCase "dispatch other message" $ do
    chan <- newTChanIO
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let withIdentity = undefined 
    conf <- newDefaultConfig
    assertThrows "exp0" exp0 $ dispatcher conf sess sender withIdentity req0 $
        Continuation $ \continue0 -> pure ()
    where
        sess = SessionId mempty
        req0 = MsgUnknown 1
        exp0 = Disconnect DisconnectProtocolError "unexpected message type (user auth module)" mempty

        testActive02 :: TestTree
        testActive02 = testCase "authenticate by public key (incorrect signature)" $ do
            chan <- newTChanIO
            done <- newTVarIO False
            let sender msg = atomically $ writeTChan chan msg
            let receiver   = atomically $ tryReadTChan chan
            let onAuth u s p = assertFailure "must not reach this point!"
            conf <- newDefaultConfig
            dispatcher conf { onAuthRequest = onAuth } sess sender undefined req0 $
                Continuation $ \continue0 -> do
                    assertEqual "res0" res0 =<< receiver
                    continue0 req1 $ Continuation $ \continue1 -> do
                        assertEqual "res1" res1 =<< receiver
                        atomically (writeTVar done True)
            assertEqual "done" True =<< atomically (readTVar done)
            where
                idnt = "identity" :: String
                user = UserName "fnord"
                srvc = ServiceName "ssh-connection"
                sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
                pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("\185\EOT\150\CAN\142)\175\161\242\141/\SI\214=n$?\189Z\172\214\190\EM\190^\226\r\241\197\&8\235\130" :: BS.ByteString))
                sign = SignatureEd25519 (pass $ Ed25519.signature ("\NUL\NULG\NULw2\NUL\b|\ETX\239\136\213&|\145Zp\ACK\240p\243\128\vL\139N\ESC\207LI\t?\139D\DC36\206\252p\172\190)\238 {\\*\206\203\253\176\vE\EM\SYNkG\211\&2\192\201\EOT\ACK" :: BS.ByteString))
                auth = AuthPublicKey (Algorithm "ssh-ed25519") pubk (Just sign)
                req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
                res0 = Just $ MsgServiceAccept $ ServiceAccept (ServiceName "ssh-userauth")
                req1 = MsgUserAuthRequest $ UserAuthRequest user srvc auth
                res1 = Just $ MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False
                pass (CryptoPassed x) = x
                pass _                = undefined

testActive01 :: TestTree
testActive01 = testCase "authenticate by public key (no signature)" $ do
    chan <- newTChanIO
    done <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let onAuth u s p = assertFailure "must not reach this point!"
    conf <- newDefaultConfig
    dispatcher conf { onAuthRequest = onAuth } sess sender undefined req0 $
        Continuation $ \continue0 -> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ \continue1 -> do
                assertEqual "res1" res1 =<< receiver
                continue1 `seq` atomically (writeTVar done True)
    assertEqual "done" True =<< atomically (readTVar done)
    where
        idnt = "identity" :: String
        user = UserName "fnord"
        srvc = ServiceName "ssh-connection"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("\185\EOT\150\CAN\142)\175\161\242\141/\SI\214=n$?\189Z\172\214\190\EM\190^\226\r\241\197\&8\235\130" :: BS.ByteString))
        auth = AuthPublicKey algo pubk Nothing
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = Just $ MsgServiceAccept $ ServiceAccept (ServiceName "ssh-userauth")
        req1 = MsgUserAuthRequest $ UserAuthRequest user srvc auth
        res1 = Just $ MsgUserAuthPublicKeyOk $ UserAuthPublicKeyOk algo pubk
        pass (CryptoPassed x) = x
        pass _                = undefined

testActive02 :: TestTree
testActive02 = testCase "authenticate by public key (incorrect signature)" $ do
    chan <- newTChanIO
    done <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let onAuth u s p = assertFailure "must not reach this point!"
    conf <- newDefaultConfig
    dispatcher conf { onAuthRequest = onAuth } sess sender undefined req0 $
        Continuation $ \continue0 -> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ \continue1 -> do
                assertEqual "res1" res1 =<< receiver
                continue1 `seq` atomically (writeTVar done True)
    assertEqual "done" True =<< atomically (readTVar done)
    where
        idnt = "identity" :: String
        user = UserName "fnord"
        srvc = ServiceName "ssh-connection"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("\185\EOT\150\CAN\142)\175\161\242\141/\SI\214=n$?\189Z\172\214\190\EM\190^\226\r\241\197\&8\235\130" :: BS.ByteString))
        sign = SignatureEd25519 (pass $ Ed25519.signature ("\NUL\NULG\NULw2\NUL\b|\ETX\239\136\213&|\145Zp\ACK\240p\243\128\vL\139N\ESC\207LI\t?\139D\DC36\206\252p\172\190)\238 {\\*\206\203\253\176\vE\EM\SYNkG\211\&2\192\201\EOT\ACK" :: BS.ByteString))
        auth = AuthPublicKey algo pubk (Just sign)
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = Just $ MsgServiceAccept $ ServiceAccept (ServiceName "ssh-userauth")
        req1 = MsgUserAuthRequest $ UserAuthRequest user srvc auth
        res1 = Just $ MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False
        pass (CryptoPassed x) = x
        pass _                = undefined

testActive03 :: TestTree
testActive03 = testCase "authenticate by public key (correct signature, user accepted)" $ do
    chan <- newTChanIO
    done <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let withIdentity i = \_ _ -> do
            assertEqual "idnt" idnt i
            atomically (writeTVar done True)
    let onAuth u s p = do
            assertEqual "user" user u
            assertEqual "srvc" srvc s
            assertEqual "pubk" pubk p
            pure (Just idnt)
    conf <- newDefaultConfig
    dispatcher conf { onAuthRequest = onAuth } sess sender withIdentity req0 $
        Continuation $ \continue0 -> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ \continue1 -> do
                assertEqual "res1" res1 =<< receiver
                continue1 req2 undefined
    assertEqual "done" True =<< atomically (readTVar done)
    where
        idnt = "identity" :: String
        user = UserName "fnord"
        srvc = ServiceName "ssh-connection"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("\185\EOT\150\CAN\142)\175\161\242\141/\SI\214=n$?\189Z\172\214\190\EM\190^\226\r\241\197\&8\235\130" :: BS.ByteString))
        sign = SignatureEd25519 (pass $ Ed25519.signature ("\152\211G\164w2\253\b|\ETX\239\136\213&|\145Zp\ACK\240p\243\128\vL\139N\ESC\207LI\t?\139D\DC36\206\252p\172\190)\238 {\\*\206\203\253\176\vE\EM\SYNkG\211\&2\192\201\EOT\ACK" :: BS.ByteString))
        auth = AuthPublicKey algo pubk (Just sign)
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = Just $ MsgServiceAccept $ ServiceAccept (ServiceName "ssh-userauth")
        req1 = MsgUserAuthRequest $ UserAuthRequest user srvc auth
        res1 = Just $ MsgUserAuthSuccess UserAuthSuccess
        req2 = MsgIgnore Ignore
        pass (CryptoPassed x) = x
        pass _                = undefined

testActive04 :: TestTree
testActive04 = testCase "authenticate by public key (correct signature, user accepted, service not available)" $ do
    chan <- newTChanIO
    done <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let withIdentity i = \_ _ ->
            assertFailure "must not reach this point!"
    let onAuth u s p = do
            assertEqual "user" user u
            assertEqual "srvc" srvc s
            assertEqual "pubk" pubk p
            atomically (writeTVar done True)
            pure (Just idnt)
    conf <- newDefaultConfig
    assertThrows "exp1" exp1 $ dispatcher conf { onAuthRequest = onAuth } sess sender withIdentity req0 $
        Continuation $ \continue0 -> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ \continue1 -> do
                assertEqual "res1" res1 =<< receiver
                continue1 req2 undefined
    assertEqual "done" True =<< atomically (readTVar done)
    where
        idnt = "identity" :: String
        user = UserName "fnord"
        srvc = ServiceName "unavailable-service"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("J\190r%\232\247\220\n\160\129m\132\RS\193\NULL\128\152}\142\SUB\161\f\229\f\137\254M\192>n\182" :: BS.ByteString))
        sign = SignatureEd25519 (pass $ Ed25519.signature ("\244\173\199<\202 \204Q\185z\EOTU\v\236\&37\"u\248TE^3fk\158|@^\215\142\DC4\234\234\DC1\224\236\FS{\CAN\144^\140\148X\169\174+\\:y\226\&9K\141\182:\NUL_\245\DC1a\228\b" :: BS.ByteString))
        auth = AuthPublicKey algo pubk (Just sign)
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = Just $ MsgServiceAccept $ ServiceAccept (ServiceName "ssh-userauth")
        req1 = MsgUserAuthRequest $ UserAuthRequest user srvc auth
        res1 = Just $ MsgUserAuthSuccess UserAuthSuccess
        req2 = MsgIgnore Ignore
        exp1 = Disconnect DisconnectServiceNotAvailable mempty mempty
        pass (CryptoPassed x) = x
        pass _                = undefined

testActive05 :: TestTree
testActive05 = testCase "authenticate by public key (correct signature, user rejected)" $ do
    chan <- newTChanIO
    done <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let withIdentity i = \_ _ ->
            assertFailure "must not reach this point!"
    let onAuth u s p = do
            assertEqual "user" user u
            assertEqual "srvc" srvc s
            assertEqual "pubk" pubk p
            pure Nothing
    conf <- newDefaultConfig
    dispatcher conf { onAuthRequest = onAuth } sess sender withIdentity req0 $
        Continuation $ \continue0 -> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ \continue1 -> do
                assertEqual "res1" res1 =<< receiver
                continue1 `seq` atomically (writeTVar done True)
    assertEqual "done" True =<< atomically (readTVar done)
    where
        idnt = "identity" :: String
        user = UserName "fnord"
        srvc = ServiceName "ssh-connection"
        algo = Algorithm "ssh-ed25519"
        sess = SessionId "\196\249b\160;FF\DLE\173\&1>\179w=\238\210\140\&8!:\139=QUx\169C\209\165\FS\185I"
        pubk = PublicKeyEd25519 (pass $ Ed25519.publicKey ("\185\EOT\150\CAN\142)\175\161\242\141/\SI\214=n$?\189Z\172\214\190\EM\190^\226\r\241\197\&8\235\130" :: BS.ByteString))
        sign = SignatureEd25519 (pass $ Ed25519.signature ("\152\211G\164w2\253\b|\ETX\239\136\213&|\145Zp\ACK\240p\243\128\vL\139N\ESC\207LI\t?\139D\DC36\206\252p\172\190)\238 {\\*\206\203\253\176\vE\EM\SYNkG\211\&2\192\201\EOT\ACK" :: BS.ByteString))
        auth = AuthPublicKey algo pubk (Just sign)
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = Just $ MsgServiceAccept $ ServiceAccept (ServiceName "ssh-userauth")
        req1 = MsgUserAuthRequest $ UserAuthRequest user srvc auth
        res1 = Just (MsgUserAuthFailure (UserAuthFailure [AuthMethodName "publickey"] False))
        pass (CryptoPassed x) = x
        pass _                = undefined

testActive09 :: TestTree
testActive09 = testCase "authenticate by other method (AuthNone)" $ do
    chan <- newTChanIO
    done <- newTVarIO False
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let withIdentity = undefined 
    conf <- newDefaultConfig
    dispatcher conf sess sender withIdentity req0 $
        Continuation $ \continue0 -> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ \continue1 -> do
                assertEqual "res1" res1 =<< receiver
                continue1 `seq` atomically (writeTVar done True)
    assertEqual "done" True =<< atomically (readTVar done)
    where
        sess = SessionId mempty
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = Just $ MsgServiceAccept $ ServiceAccept (ServiceName "ssh-userauth")
        req1 = MsgUserAuthRequest $ UserAuthRequest (UserName "fnord") (ServiceName "ssh-connection") AuthNone
        res1 = Just $ MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False

testActive10 :: TestTree
testActive10 = testCase "dispatch other message" $ do
    chan <- newTChanIO
    let sender msg = atomically $ writeTChan chan msg
    let receiver   = atomically $ tryReadTChan chan
    let withIdentity = undefined 
    conf <- newDefaultConfig
    assertThrows "exp1" exp1 $ dispatcher conf sess sender withIdentity req0 $
        Continuation $ \continue0 -> do
            assertEqual "res0" res0 =<< receiver
            continue0 req1 $ Continuation $ const $ pure ()
    where
        sess = SessionId mempty
        req0 = MsgServiceRequest $ ServiceRequest (ServiceName "ssh-userauth")
        res0 = Just $ MsgServiceAccept $ ServiceAccept (ServiceName "ssh-userauth")
        req1 = MsgUnknown 1
        exp1 = Disconnect DisconnectProtocolError "unexpected message type (user auth module)" mempty

assertThrows :: (Eq e, Exception e) => String -> e -> IO a -> Assertion
assertThrows label e action = (action >> failure0) `catch` \e'-> when (e /= e') (failure1 e')
    where
        failure0 = assertFailure (label ++ ": should have thrown " ++ show e)
        failure1 e' = assertFailure (label ++ ": should have thrown " ++ show e ++ " (saw " ++ show e' ++ " instead)")
