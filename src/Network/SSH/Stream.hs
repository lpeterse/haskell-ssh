module Network.SSH.Stream where

import qualified Data.ByteString   as BS

class (InputStream stream, OutputStream stream) => DuplexStream stream where

class OutputStream stream where
    send        :: stream -> BS.ByteString -> IO Int

class InputStream stream where
    peek    :: stream -> Int -> IO BS.ByteString
    receive :: stream -> Int -> IO BS.ByteString
