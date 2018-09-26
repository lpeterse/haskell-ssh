{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiWayIf        #-}
module Network.SSH.TByteStringQueue where

import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Monad.STM
import           Control.Applicative
import qualified Data.ByteString               as BS
import           Prelude                 hiding ( head
                                                , tail
                                                )

import qualified Network.SSH.Stream            as S

data TByteStringQueue
    = TByteStringQueue
    { aqSize      :: TVar Int
    , aqSizeLimit :: Int
    , aqHead      :: TVar BS.ByteString
    , aqTail      :: TChan BS.ByteString
    }

sizeTByteStringQueue :: TByteStringQueue -> STM Int
sizeTByteStringQueue q = readTVar (aqSize q)

maxSizeTByteStringQueue :: TByteStringQueue -> Int
maxSizeTByteStringQueue = aqSizeLimit

newTByteStringQueue :: Int -> STM TByteStringQueue
newTByteStringQueue i =
    TByteStringQueue <$> newTVar 0 <*> pure i <*> newTVar mempty <*> newTChan

enqueue :: TByteStringQueue -> BS.ByteString -> STM Int
enqueue q bs
    | BS.null bs = pure 0
    | otherwise = do
        size <- readTVar (aqSize q)
        head <- readTVar (aqHead q)
        let bsLen     = BS.length bs
        let available = aqSizeLimit q - size
        if
            | bsLen == 0 -> pure 0
            | BS.null head && available > bsLen -> do
                writeTVar (aqHead q) bs
                pure bsLen
            | available > bsLen -> do
                writeTChan (aqTail q) bs
                pure bsLen
            | available > 0 -> do
                let n = bsLen - available
                writeTChan (aqTail q) (BS.take n bs)
                pure n
            | otherwise -> retry

enqueueUnlimited :: TByteStringQueue -> BS.ByteString -> STM ()
enqueueUnlimited q bs
    | BS.null bs = pure ()
    | otherwise = do
        head <- readTVar (aqHead q)
        if
            | BS.null head -> writeTVar (aqHead q) bs
            | otherwise    -> writeTChan (aqTail q) bs

dequeue :: TByteStringQueue -> Int -> STM BS.ByteString
dequeue q i
    | i < 1 = pure mempty
    | otherwise = do
        head <- readTVar (aqHead q)
        if
            | BS.null head -> retry
            | BS.length head <= i -> do
                head' <- readTChan (aqTail q) <|> pure mempty
                size  <- readTVar (aqSize q)
                writeTVar (aqSize q) $! size - BS.length head
                writeTVar (aqHead q) head'
                pure head
            | otherwise -> do
                writeTVar (aqHead q) $! BS.drop i head
                size <- readTVar (aqSize q)
                writeTVar (aqSize q) $! size - i
                pure (BS.take i head)

instance S.DuplexStream TByteStringQueue

instance S.OutputStream TByteStringQueue where
    send q ba = atomically (enqueue q ba)

instance S.InputStream TByteStringQueue where
    receive q i = atomically $ dequeue q i
