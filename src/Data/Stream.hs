module Data.Stream where

import           Control.Arrow     (second)
import           Control.Exception
import           Control.Monad     (unless, when)
import           Control.Monad.STM
import qualified Data.ByteString   as BS
import           Data.Monoid       ((<>))

import           Data.Typeable
import           Data.Word
import           System.IO.Error

class (InputStream stream, OutputStream stream) => DuplexStream stream where

class OutputStream stream where
    send    :: stream -> BS.ByteString -> IO Int

class InputStream stream where
    receive :: stream -> Int -> IO BS.ByteString

sendAll :: (OutputStream stream) => stream -> BS.ByteString -> IO Int
sendAll stream bs = sendAll' 0
    where
        len = BS.length bs
        sendAll' offset
            | offset >= len = pure len
            | otherwise = do
                sent <- send stream (BS.drop offset bs)
                sendAll' (offset + sent)

receiveAll :: (InputStream stream) => stream -> Int -> IO BS.ByteString
receiveAll stream len =
    receive stream len >>= loop
    where
        loop bs
            | fromIntegral (BS.length bs) >= len = pure bs
            | otherwise = do
                  bs' <- receive stream $ len - fromIntegral (BS.length bs)
                  when (BS.null bs') (throwIO $ userError "unexpected end of input")
                  loop (bs <> bs')
