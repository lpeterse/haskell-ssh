{-# LANGUAGE OverloadedStrings          #-}
module Spec.Util where

import qualified Data.ByteString          as BS
import           Control.Monad.STM
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TChan
import           Control.Exception
import           Control.Monad

import           Test.Tasty.HUnit

import           Network.SSH.Internal
import           Network.SSH.TWindowBuffer

assertThrows :: (Eq e, Exception e) => String -> e -> IO a -> Assertion
assertThrows label e action = (action >> failure0) `catch` \e'-> when (e /= e') (failure1 e')
    where
        failure0 = assertFailure (label ++ ": should have thrown " ++ show e)
        failure1 e' = assertFailure (label ++ ": should have thrown " ++ show e ++ " (saw " ++ show e' ++ " instead)")

data DummySocket = DummySocket TWindowBuffer TWindowBuffer

newSocketPair :: IO (DummySocket, DummySocket)
newSocketPair = atomically $ do
    window <- newTVar 1000000000
    x <- newTWindowBufferSTM 1000000000 window
    y <- newTWindowBufferSTM 1000000000 window
    pure (DummySocket x y, DummySocket y x)

instance DuplexStream DummySocket

instance OutputStream DummySocket where
    send (DummySocket q _) = send q

instance InputStream DummySocket where
    peek (DummySocket _ q) = peek q
    receive (DummySocket _ q) = receive q
    receiveUnsafe (DummySocket _ q) = receiveUnsafe q

close :: DummySocket -> IO ()
close (DummySocket q _) = atomically $ sendEofSTM q

newtype DummyTransport = DummyTransport (TChan BS.ByteString, TChan BS.ByteString)

newDummyTransportPair :: IO (DummyTransport, DummyTransport)
newDummyTransportPair = do
    inbound <- newTChanIO
    outbound <- newTChanIO
    pure (DummyTransport (inbound, outbound), DummyTransport (outbound,inbound))

instance MessageStream DummyTransport where
    sendMessage (DummyTransport (c,_)) msg = atomically $ writeTChan c $ runPut (put msg)
    receiveMessage (DummyTransport (_,c)) = do
        bs <- atomically $ readTChan c
        case runGet bs of
            Nothing  -> throwIO (exceptionUnexpectedMessage bs)
            Just msg -> pure msg
