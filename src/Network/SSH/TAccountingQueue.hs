{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiWayIf        #-}
module Network.SSH.TAccountingQueue where

import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Monad.STM
import qualified Data.ByteArray               as BA
import qualified Data.Count                   as Count
import qualified Data.Stream                  as S

data TAccountingQueue
    = TAccountingQueue
    { aqMaxSize :: Int
    , aqTaken   :: TVar Int
    , aqHead    :: TVar (BA.View BA.Bytes)
    , aqTail    :: TChan (BA.View BA.Bytes)
    , aqSize    :: TVar Int
    }

newTAccountingQueue :: Int -> STM TAccountingQueue
newTAccountingQueue i = TAccountingQueue i
    <$> newTVar 0
    <*> newTVar (BA.takeView BA.empty 0)
    <*> newTChan
    <*> newTVar 0

bytesEnqueued :: TAccountingQueue -> STM Int
bytesEnqueued q = do
    n <- bytesDequeued q
    m <- readTVar (aqSize q)
    pure (n + m)

bytesDequeued :: TAccountingQueue -> STM Int
bytesDequeued q = do
    readTVar (aqTaken q)

enqueue :: TAccountingQueue -> BA.Bytes -> STM Int
enqueue q ba = do
    queueSize <- readTVar (aqSize q)
    let len = BA.length ba
    let available = aqMaxSize q - queueSize
    if  | len == 0 -> pure 0
        | available > 0 -> do
            let n = min available len
            writeTChan (aqTail q) (BA.takeView ba n)
            writeTVar (aqSize q) (queueSize + n)
            pure n
        | otherwise -> retry

dequeue :: TAccountingQueue -> Int -> STM BA.Bytes
dequeue _ 0   = pure BA.empty
dequeue q len = do
    queueSize <- readTVar (aqSize q)
    check (queueSize > 0) -- retry when queue is empty
    h0 <- readTVar (aqHead q)
    h1 <- if BA.null h0 then readTChan (aqTail q) else pure h0
    let n = min (BA.length h1) len
    writeTVar (aqHead q) $ BA.dropView (BA.convert $ BA.dropView h1 n :: BA.Bytes) 0
    writeTVar (aqSize q) (queueSize - n)
    taken <- readTVar (aqTaken q)
    writeTVar (aqTaken q) $! taken + n
    pure $ BA.convert $ BA.takeView h1 n

instance S.DuplexStream TAccountingQueue

instance S.OutputStream TAccountingQueue where
    send q ba = Count.Count . fromIntegral <$> atomically (enqueue q (BA.convert ba))

instance S.InputStream TAccountingQueue where
    receive q i = atomically $ BA.convert <$> dequeue q (Count.toIntDefault maxBound i)
