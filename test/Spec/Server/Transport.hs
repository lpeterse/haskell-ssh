{-# LANGUAGE OverloadedStrings, FlexibleInstances, LambdaCase #-}
module Spec.Server.Transport ( tests ) where
    
import           Control.Concurrent.MVar
import qualified Data.ByteString as BS
import           Control.Exception
import           Control.Monad

import           Network.SSH.Server.Transport
import           Network.SSH.Stream
import           Network.SSH.Message

import           Test.Tasty
import           Test.Tasty.HUnit

tests :: TestTree
tests = testGroup "Network.SSH.Server.Transport.receiveClientVersion"
    [ testCase "correct version string #1" $ do 
        s <- newMVar ["SSH-2.0-OpenSSH_4.3\x0d\x0a" :: BS.ByteString]
        v <- receiveClientVersion s
        v @=? Version "SSH-2.0-OpenSSH_4.3"

    , testCase "correct version string #2 (maximum length)" $ do
        let x = "SSH-2.0-OpenSSH_4.3"
            i = 255 - 2 - BS.length x
            y = BS.replicate i 64
        s <- newMVar [x, y, "\x0d\x0a" :: BS.ByteString]
        v <- receiveClientVersion s
        v @=? Version (x <> y)

    , testCase "incorrect version string #1" $ do
        s <- newMVar ["GET /index.html HTTP/1.1\x0d\x0a\x0d\x0a" :: BS.ByteString]
        assertThrowsExact disconnectException (receiveClientVersion s)

    , testCase "incorrect version string #2" $ do
        s <- newMVar ["SSH-2.0-OpenSSH_4.3\x0d" :: BS.ByteString]
        assertThrowsExact disconnectException (receiveClientVersion s)

    , testCase "incorrect version string #3" $ do
        s <- newMVar ["SSH-2.0-OpenSSH_4.3\x0a" :: BS.ByteString]
        assertThrowsExact disconnectException (receiveClientVersion s)

    , testCase "incorrect version string #4" $ do
        s <- newMVar ["SSH-2.0-OpenSSH_4.3\x0d \x0a" :: BS.ByteString]
        assertThrowsExact disconnectException (receiveClientVersion s)

    , testCase "incorrect version string #5" $ do 
        s <- newMVar ([] :: [BS.ByteString])
        assertThrowsExact disconnectException (receiveClientVersion s)

    , testCase "incorrect version string #6" $ do 
        s <- newMVar ["S" :: BS.ByteString]
        assertThrowsExact disconnectException (receiveClientVersion s)

    , testCase "incorrect version string #6 (> maximum length)" $ do
        let x = "SSH-2.0-OpenSSH_4.3"
            i = 256 - 2 - BS.length x
            y = BS.replicate i 64
        s <- newMVar [x, y, "\x0d\x0a" :: BS.ByteString]
        assertThrowsExact disconnectException (receiveClientVersion s)

    , testCase "incorrect version string #7 (> maximum length)" $ do
        let x = "SSH-2.0-OpenSSH_4.3"
            i = 257 - 2 - BS.length x
            y = BS.replicate i 64
        s <- newMVar [x, y, "\x0d\x0a" :: BS.ByteString]
        assertThrowsExact disconnectException (receiveClientVersion s)
    ]
     where
       disconnectException = Disconnect DisconnectProtocolVersionNotSupported "" ""

instance InputStream (MVar [BS.ByteString]) where
    receive s i = i `seq` modifyMVar s $ \case
        [] -> pure ([], "")
        (x:xs) -> pure (xs,x)

assertThrowsExact :: (Exception e, Eq e) => e -> IO a -> Assertion
assertThrowsExact e action = (action >> assertFailure "should have thrown") `catch` \e'-> when (e /= e') (throwIO e')
