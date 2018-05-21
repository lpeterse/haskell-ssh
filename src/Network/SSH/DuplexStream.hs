module Network.SSH.DuplexStream where

import           Control.Arrow         (second)
import           Control.Exception
import           Control.Monad         (unless, when)
import           Control.Monad.STM
import qualified Data.ByteArray        as BA
import           Data.Monoid           ((<>))
import qualified Data.Serialize        as B
import qualified Data.Serialize.Get    as B
import qualified Data.Serialize.Put    as B
import           Data.Typeable

import           Network.SSH.Exception

class (InputStream stream, OutputStream stream) => DuplexStream stream where

class OutputStream stream where
    send    :: BA.ByteArrayAccess ba => stream -> ba -> IO Int

class InputStream stream where
    receive :: BA.ByteArray ba => stream -> Int -> IO ba

sendAll :: (DuplexStream stream, BA.ByteArray ba) => stream -> ba -> IO ()
sendAll stream ba = sendAll' 0
    where
        len = BA.length ba
        sendAll' offset
            | offset >= len = pure ()
            | otherwise = do
                sent <- send stream (BA.dropView ba offset)
                sendAll' (offset + sent)

receiveAll :: (DuplexStream stream, BA.ByteArray ba) => stream -> Int -> IO ba
receiveAll stream len =
    receive stream len >>= loop
    where
        loop ba
            | BA.length ba >= len = pure ba
            | otherwise = do
                  ba' <- receive stream (len - BA.length ba)
                  when (BA.null ba') (throwIO SshUnexpectedEndOfInputException)
                  loop (ba <> ba')

sendPutter :: (DuplexStream stream) => stream -> B.Put -> IO ()
sendPutter stream =
    sendAll stream . B.runPut

receiveGetter :: (DuplexStream stream, BA.ByteArray ba) => stream -> B.Get a -> ba -> IO (a, ba)
receiveGetter stream getter initial =
    f (B.runGetPartial getter $ BA.convert initial)
    where
        chunkSize              = 1024
        f (B.Done a remainder) = pure (a, BA.convert remainder)
        f (B.Fail e _        ) = throwIO (SshSyntaxErrorException e)
        f (B.Partial continue) = f =<< (continue <$> receive stream chunkSize)
