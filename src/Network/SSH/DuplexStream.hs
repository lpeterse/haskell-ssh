module Network.SSH.DuplexStream where

import           Control.Arrow         (second)
import           Control.Exception
import           Control.Monad         (unless, when)
import           Control.Monad.STM
import qualified Data.Binary           as B
import qualified Data.Binary.Get       as B
import qualified Data.Binary.Put       as B
import qualified Data.ByteArray        as BA
import qualified Data.ByteString.Lazy  as LBS
import           Data.Monoid           ((<>))
import           Data.Typeable

import           Network.SSH.Exception

class DuplexStream stream where
    waitReadableSTM         :: stream -> STM ()
    waitWritableSTM         :: stream -> STM ()
    sendChunk               :: BA.ByteArray ba => stream -> ba -> IO ba
    sendChunkNonBlocking    :: BA.ByteArray ba => stream -> ba -> IO (Maybe ba)
    receiveChunk            :: BA.ByteArray ba => stream -> Int -> IO ba
    receiveChunkNonBlocking :: BA.ByteArray ba => stream -> Int -> IO (Maybe ba)

sendAll :: (DuplexStream stream, BA.ByteArray ba) => stream -> ba -> IO ()
sendAll stream ba = do
    ba' <- sendChunk stream ba
    unless (BA.null ba') (sendAll stream ba')

receiveAll :: (DuplexStream stream, BA.ByteArray ba) => stream -> Int -> IO ba
receiveAll stream len = loop mempty
    where
        loop ba
            | BA.length ba >= len = pure ba
            | otherwise = do
                  ba' <- receiveChunk stream 1024
                  when (BA.null ba') (throwIO SshUnexpectedEndOfInputException)
                  loop (ba <> ba')

sendPutter :: (DuplexStream stream) => stream -> B.Put -> IO ()
sendPutter stream =
    sendAll stream . LBS.toStrict . B.runPut

receiveGetter :: (DuplexStream stream, BA.ByteArray ba) => stream -> B.Get a -> ba -> IO (a, ba)
receiveGetter stream getter initial =
    second BA.convert <$> case B.runGetIncremental getter of
        B.Done _ _ a       -> pure (a, initial)
        B.Fail _ _ e       -> throwIO (SshSyntaxErrorException e)
        B.Partial continue -> f (continue $ Just $ BA.convert initial)
    where
        chunkSize = 1024
        nothingIfEmpty ba
            | BA.null ba = Nothing
            | otherwise  = Just ba
        f (B.Done remainder _ a) = pure (a, BA.convert remainder)
        f (B.Fail _ _ e        ) = throwIO (SshSyntaxErrorException e)
        f (B.Partial continue  ) = f =<< (continue . nothingIfEmpty <$> receiveChunk stream chunkSize)
