module Network.SSH.Stream where

import           Control.Exception    ( throwIO )
import           Control.Monad        ( when )
import           Foreign.Ptr
import qualified Data.ByteString   as BS
import qualified Data.ByteArray    as BA

-- | A `DuplexStream` is an abstraction over all things that
--   behave like file handles or sockets.
class (InputStream stream, OutputStream stream) => DuplexStream stream where

-- | An `OutputStream` is something that chunks of bytes can be written to.
class OutputStream stream where
    -- | Send a chunk of bytes into the stream.
    --
    -- (1) This method shall block until at least one byte could be sent or
    --     the connection got closed.
    -- (2) Returns the number of bytes sent or 0 if the other side
    --     closed the connection. The return value must be checked when
    --     using a loop for sending or the program will get stuck in
    --     endless recursion!
    send          :: stream -> BS.ByteString -> IO Int
    -- | Like `send`, but allows for more efficiency with less memory
    --   allocations when working with builders and re-usable buffers.
    sendUnsafe    :: stream -> BA.MemView -> IO Int
    sendUnsafe stream view = do
        bs <- BA.copy view (const $ pure ())
        send stream bs

-- | An `InputStream` is something that bytes can be read from.
class InputStream stream where
    -- | Like `receive`, but does not actually remove anything
    --   from the input buffer.
    --
    -- (1) Use with care! There are very few legitimate use cases
    --     for this.
    peek          :: stream -> Int -> IO BS.ByteString
    -- | Receive a chunk of bytes from the stream.
    --
    -- (1) This method shall block until at least one byte becomes
    --     available or the connection got closed.
    -- (2) As with sockets, the chunk boundaries are not guaranteed to
    --     be preserved during transmission although this will be most often
    --     the case. Never rely on this behaviour!
    -- (3) The second parameter determines how many bytes to receive at most,
    --     but the `BS.ByteString` returned might be shorter.
    -- (4) Returns a chunk which is guaranteed to be shorter or equal
    --     than the given limit. It is empty when the connection got
    --     closed and all subsequent attempts to read shall return the
    --     empty string. This must be checked when collecting chunks in
    --     a loop or the program will get stuck in endless recursion!
    receive       :: stream -> Int -> IO BS.ByteString
    -- | Like `receive`, but allows for more efficiency with less memory
    --   allocations when working with builders and re-usable buffers.
    receiveUnsafe :: stream -> BA.MemView -> IO Int
    receiveUnsafe stream (BA.MemView ptr n) = do
        bs <- receive stream n
        BA.copyByteArrayToPtr bs ptr
        pure (BS.length bs)

-- | Try to send the complete `BS.ByteString`.
--
--   * Blocks until either the `BS.ByteString` has been sent
--     or throws an exception when the connection got terminated
--     while sending it.
sendAll :: OutputStream stream => stream -> BS.ByteString -> IO ()
sendAll stream bs
    | BS.null bs = pure ()
    | otherwise  = BA.withByteArray bs $ sendAll' (BS.length bs)
    where
        sendAll' remaining ptr
            | remaining <= 0 = pure ()
            | otherwise = do
                sent <- sendUnsafe stream (BA.MemView ptr remaining)
                when (sent <= 0) (throwIO $ userError "sendAll: connection lost")
                sendAll' (remaining - sent) (plusPtr ptr sent)

-- | Try to receive a `BS.ByteString` of the designated length in bytes.
--
--   * Blocks until either the complete `BS.ByteString` has been received
--     or throws an exception when the connection got terminated
--     before enough bytes arrived.
receiveAll :: InputStream stream => stream -> Int -> IO BS.ByteString
receiveAll stream n
    | n <= 0    = pure mempty
    | otherwise = BA.alloc n $ receiveAll' n
    where
        receiveAll' remaining ptr
            | remaining <= 0 = pure ()
            | otherwise = do
                received <- receiveUnsafe stream (BA.MemView ptr remaining)
                when (received <= 0) (throwIO $ userError "receiveAll: connection lost")
                receiveAll' (remaining - received) (plusPtr ptr received)
