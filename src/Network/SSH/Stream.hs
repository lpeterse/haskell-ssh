module Network.SSH.Stream where

import qualified Data.ByteString   as BS

class (InputStream stream, OutputStream stream) => DuplexStream stream where
class (InputStreamPeekable stream, DuplexStream stream) => DuplexStreamPeekable stream where

class OutputStream stream where
    send    :: stream -> BS.ByteString -> IO Int

class InputStream stream where
    receive :: stream -> Int -> IO BS.ByteString

class InputStream stream => InputStreamPeekable stream where
    peek    :: stream -> Int -> IO BS.ByteString


