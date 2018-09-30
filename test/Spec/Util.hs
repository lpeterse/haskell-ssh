{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE StandaloneDeriving         #-}
module Spec.Util where

import           Crypto.Error
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.ByteString          as BS
import qualified Data.Serialize           as B
import           Control.Monad.STM
import           Control.Concurrent.STM.TVar
import           System.Exit
import           Control.Exception
import           Control.Monad

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Server
import           Network.SSH.Stream
import           Network.SSH.Constants
import qualified Network.SSH.TStreamingQueue as Q


assertThrows :: (Eq e, Exception e) => String -> e -> IO a -> Assertion
assertThrows label e action = (action >> failure0) `catch` \e'-> when (e /= e') (failure1 e')
    where
        failure0 = assertFailure (label ++ ": should have thrown " ++ show e)
        failure1 e' = assertFailure (label ++ ": should have thrown " ++ show e ++ " (saw " ++ show e' ++ " instead)")


data DummySocket = DummySocket Q.TStreamingQueue Q.TStreamingQueue

newSocketPair :: IO (DummySocket, DummySocket)
newSocketPair = atomically $ do
    window <- newTVar maxBound
    x <- Q.newTStreamingQueue maxBound window
    y <- Q.newTStreamingQueue maxBound window
    pure (DummySocket x y, DummySocket y x)

instance DuplexStream DummySocket

instance OutputStream DummySocket where
    send (DummySocket q _) bs = fromIntegral <$> atomically (Q.enqueue q bs)

instance InputStream DummySocket where
    receive (DummySocket _ q) i = atomically $ Q.dequeue q $ fromIntegral $ min i maxBoundIntWord32

close :: DummySocket -> IO ()
close (DummySocket q _) = atomically $ Q.terminate q
