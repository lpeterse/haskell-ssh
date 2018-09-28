{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiWayIf        #-}
module Network.SSH.TStreamingQueue where

import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Control.Monad.STM
import           Control.Applicative
import           Data.Word
import qualified Data.ByteString               as BS
import           Prelude                 hiding ( head
                                                , tail
                                                )

import qualified Network.SSH.Stream            as S
import           Network.SSH.Constants

data TStreamingQueue
    = TStreamingQueue
    { qCapacity  :: Word32
    , qWindow    :: TVar Word32
    , qSize      :: TVar Word32
    , qEof       :: TVar Bool
    , qHead      :: TMVar BS.ByteString
    , qTail      :: TChan BS.ByteString
    }

newTStreamingQueue :: Word32 -> TVar Word32 -> STM TStreamingQueue
newTStreamingQueue c window =
    TStreamingQueue c window <$> newTVar 0 <*> newTVar False <*> newEmptyTMVar <*> newTChan

capacity :: TStreamingQueue -> Word32
capacity = qCapacity

getSize :: TStreamingQueue -> STM Word32
getSize = readTVar . qSize

getFree :: TStreamingQueue -> STM Word32
getFree q = (capacity q -) <$> getSize q

getWindowSpace :: TStreamingQueue -> STM Word32
getWindowSpace = readTVar . qWindow

addWindowSpace :: TStreamingQueue -> Word32 -> STM ()
addWindowSpace q increment = do
    wndw <- getWindowSpace q :: STM Word32
    check $ (fromIntegral wndw + fromIntegral increment :: Word64) <= fromIntegral (maxBound :: Word32)
    writeTVar (qWindow q) $! wndw + increment

askWindowSpaceAdjustRecommended :: TStreamingQueue -> STM Bool
askWindowSpaceAdjustRecommended q = do
    size <- getSize q
    wndw <- getWindowSpace q
    let threshold = capacity q `div` 2
    -- 1st condition: window size must be below half of its maximum
    -- 2nd condition: queue size must be below half of its capacity
    -- in order to avoid byte-wise adjustment and flapping
    pure $ size <= threshold && wndw <= threshold

fillWindowSpace :: TStreamingQueue -> STM Word32
fillWindowSpace q = do
    free <- getFree q
    wndw <- getWindowSpace q
    writeTVar (qWindow q) $! wndw + free
    pure free

terminate :: TStreamingQueue -> STM ()
terminate q =
    writeTVar (qEof q) True

enqueue :: TStreamingQueue -> BS.ByteString -> STM Word32
enqueue q bs
    | BS.null bs = pure 0
    | otherwise = do
        eof  <- readTVar (qEof q)
        if eof then pure 0 else do
            size <- getSize q
            wndw <- getWindowSpace q
            let free       = capacity q - size
                requested  = fromIntegral (BS.length bs) :: Word32
                available  = min (min free wndw) maxBoundIntWord32 :: Word32
            check $ available > 0 -- Block until there's free capacity and window space.
            if  | available >= requested -> do
                    writeTVar (qSize q)   $! size + requested
                    writeTVar (qWindow q) $! wndw - requested
                    writeTChan (qTail q) bs
                    pure requested
                | otherwise -> do
                    writeTVar (qSize q)   $! size + available
                    writeTVar (qWindow q) $! wndw - available
                    writeTChan (qTail q)  $! BS.take (fromIntegral available) bs
                    pure available

dequeue :: TStreamingQueue -> Word32 -> STM BS.ByteString
dequeue q maxBufSize = do
    size <- getSize q
    eof  <- readTVar (qEof q)
    check $ size > 0 || eof -- Block until there's at least 1 byte available.
    if size == 0 && eof
        then pure mempty
        else mconcat <$> f size requested
    where
        f s 0 = do
            writeTVar (qSize q) $! s - requested
            pure []
        f s j = do
            bs <- takeTMVar (qHead q) <|> readTChan (qTail q) <|> pure mempty
            if | BS.null bs -> do
                    writeTVar (qSize q) $! s - (requested - j)
                    pure []
               | fromIntegral (BS.length bs) <= j ->
                    (bs:) <$> f s (j - fromIntegral (BS.length bs))
               | otherwise -> do
                    writeTVar (qSize q) $! s - requested
                    putTMVar  (qHead q) $! BS.drop (fromIntegral j) bs
                    pure [ BS.take (fromIntegral j) bs ]
        requested = min maxBufSize maxBoundIntWord32

instance S.DuplexStream TStreamingQueue

instance S.OutputStream TStreamingQueue where
    send q bs = fromIntegral <$> atomically (enqueue q bs)

instance S.InputStream TStreamingQueue where
    receive q i = atomically $ dequeue q $ fromIntegral $ min i maxBoundIntWord32
