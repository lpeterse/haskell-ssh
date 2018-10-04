module Network.SSH.Stream where

import           Control.Exception
import           Control.Monad     (when)
import qualified Data.ByteString   as BS
import           Data.Monoid       ((<>))

class (InputStream stream, OutputStream stream) => DuplexStream stream where
class (InputStreamPeekable stream, DuplexStream stream) => DuplexStreamPeekable stream where

class OutputStream stream where
    send    :: stream -> BS.ByteString -> IO Int

class InputStream stream where
    receive :: stream -> Int -> IO BS.ByteString

class InputStream stream => InputStreamPeekable stream where
    peek    :: stream -> Int -> IO BS.ByteString

sendAll :: (OutputStream stream) => stream -> BS.ByteString -> IO Int
sendAll stream bs = sendAll' 0
    where
        len = BS.length bs
        sendAll' offset
            | offset >= len = pure len
            | otherwise = do
                sent <- send stream (BS.drop offset bs)
                when (sent <= 0) (throwIO $ userError "eof")
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
