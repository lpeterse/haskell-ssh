module Network.SSH.Stream where

import qualified Data.ByteString   as BS
import qualified Data.ByteArray    as BA

class (InputStream stream, OutputStream stream) => DuplexStream stream where

class OutputStream stream where
    send          :: stream -> BS.ByteString -> IO Int
    sendUnsafe    :: stream -> BA.MemView -> IO Int

class InputStream stream where
    peek          :: stream -> Int -> IO BS.ByteString
    receive       :: stream -> Int -> IO BS.ByteString
    receiveUnsafe :: stream -> BA.MemView -> IO Int
    receiveUnsafe q (BA.MemView ptr n) = do
        bs <- receive q n
        BA.copyByteArrayToPtr bs ptr
        pure (BS.length bs)
