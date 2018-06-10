module Data.Stream where

import           Control.Arrow     (second)
import           Control.Exception
import           Control.Monad     (unless, when)
import           Control.Monad.STM
import qualified Data.ByteArray    as BA
import           Data.Count        (Count (..))
import qualified Data.Count        as Count
import           Data.Monoid       ((<>))

import           Data.Typeable
import           Data.Word
import           System.IO.Error

class (InputStream stream, OutputStream stream) => DuplexStream stream where

class OutputStream stream where
    send    :: BA.ByteArrayAccess ba => stream -> ba -> IO (Count Word8)

class InputStream stream where
    receive :: BA.ByteArray ba => stream -> Count Word8 -> IO ba

sendAll :: (DuplexStream stream, BA.ByteArray ba) => stream -> ba -> IO ()
sendAll stream ba = sendAll' 0
    where
        len = fromIntegral (BA.length ba) :: Word64
        sendAll' offset
            | offset >= len = pure ()
            | otherwise = do
                Count sent <- send stream (BA.dropView ba $ fromIntegral offset)
                sendAll' (offset + sent)

receiveAll :: (DuplexStream stream, BA.ByteArray ba) => stream -> Count Word8 -> IO ba
receiveAll stream (Count len) =
    receive stream (Count len) >>= loop
    where
        loop ba
            | fromIntegral (BA.length ba) >= len = pure ba
            | otherwise = do
                  ba' <- receive stream $ Count $ len - fromIntegral (BA.length ba)
                  when (BA.null ba') (throwIO $ userError "unexpected end of input")
                  loop (ba <> ba')

