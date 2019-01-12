module Network.SSH.TWindowBuffer where

import           Control.Applicative ((<|>))
import           Control.Concurrent.STM.TVar
import           Control.Exception
import           Control.Monad.STM
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Short as SBS
import           Data.Word

import qualified Network.SSH.Stream    as S
import           Network.SSH.Constants ( maxBoundIntWord32 )

data TWindowBuffer
    = TWindowBuffer
    { bCapacity :: !Word32
    , bWindow   :: !(TVar Word32)
    , bQueue    :: !(TVar Queue)
    }

data TWindowBufferException
    = TWindowBufferWriteAfterEof
    deriving (Eq, Ord, Show)

instance Exception TWindowBufferException where

newTWindowBufferSTM :: Word32 -> TVar Word32 -> STM TWindowBuffer
newTWindowBufferSTM capacity window = TWindowBuffer capacity window
    <$> newTVar (Queue 0 False [] [])

getSizeSTM :: TWindowBuffer -> STM Word32
getSizeSTM b = fromIntegral . qSize <$> readTVar (bQueue b)

getAvailableSTM :: TWindowBuffer -> STM Word32
getAvailableSTM b = min <$> getAvailableCapacitySTM b <*> getAvailableWindowSTM b

getAvailableCapacitySTM :: TWindowBuffer -> STM Word32
getAvailableCapacitySTM b = (bCapacity b -) <$> getSizeSTM b

getAvailableWindowSTM :: TWindowBuffer -> STM Word32
getAvailableWindowSTM b = readTVar (bWindow b)

askEofSTM :: TWindowBuffer -> STM Bool
askEofSTM b = qEof <$> readTVar (bQueue b)

-- | Returns number of bytes that may be added to the window.
--
-- The transaction blocks unless an adjustment is
-- recommended which is when the adjust would be greater
-- than 50% of the buffer capacity.
--
-- +-----------------+--------------------------------------+
-- |*****************|                                      |
-- | capacity                                               |
-- | size            | available capacity                   |
-- |                 | available window    | window adjust  |
-- +-----------------+---------------------+----------------+
getRecommendedWindowAdjustSTM :: TWindowBuffer -> STM Word32
getRecommendedWindowAdjustSTM b = do
    let capacity = bCapacity b
    let threshold = capacity `div` 2
    size <- getSizeSTM b
    availableWindow <- getAvailableWindowSTM b
    -- Condition: Window adjust must be > 50 % of capacity.
    check $ size + availableWindow <= threshold
    -- Recommend adjusting the window up to full buffer capacity.
    pure $ capacity - size - availableWindow

throwWhenEofSTM :: Exception e => TWindowBuffer -> e -> STM a
throwWhenEofSTM b e = readTVar (bQueue b) >>= check . qEof >> throwSTM e

enqueueSTM :: TWindowBuffer -> BS.ByteString -> STM Word32
enqueueSTM b bs = do
    throwWhenEofSTM b TWindowBufferWriteAfterEof <|> pure ()
    availableWindow <- getAvailableWindowSTM b
    availableCapacity <- getAvailableCapacitySTM b
    let available = min availableWindow availableCapacity
    check $ available > 0 -- Block until there's at least 1 byte available
    let sbs = SBS.toShort $ BS.take (fromIntegral available) bs
    let sbsLen = fromIntegral $ SBS.length sbs
    q <- readTVar (bQueue b)
    writeTVar (bQueue b) $! qEnqueueShort sbs q
    writeTVar (bWindow b) $! availableWindow - sbsLen
    pure sbsLen

enqueueShortSTM :: TWindowBuffer -> SBS.ShortByteString -> STM Word32
enqueueShortSTM b bs = do
    throwWhenEofSTM b TWindowBufferWriteAfterEof <|> pure ()
    availableWindow <- getAvailableWindowSTM b
    availableCapacity <- getAvailableCapacitySTM b
    let available = min availableWindow availableCapacity
    check $ available > 0 -- Block until there's at least 1 byte available
    let sbs = takeShort (fromIntegral available) bs
    let sbsLen = fromIntegral $ SBS.length sbs
    q <- readTVar (bQueue b)
    writeTVar (bQueue b) $! qEnqueueShort sbs q
    writeTVar (bWindow b) $! availableWindow - sbsLen
    pure sbsLen

dequeueSTM :: TWindowBuffer -> Word32 -> STM BS.ByteString
dequeueSTM b n = SBS.fromShort <$> dequeueShortSTM b n

dequeueShortSTM :: TWindowBuffer -> Word32 -> STM SBS.ShortByteString
dequeueShortSTM b n = do
    q <- readTVar (bQueue b)
    dequeue q <|> eof q
    where
        eof q = check (qEof q) >> pure mempty
        dequeue q = do 
            check $ qSize q > 0
            let (sbs, q') = qDequeueShort (fromIntegral n) q
            writeTVar (bQueue b) $! q'
            pure sbs

lookAheadSTM :: TWindowBuffer -> Word32 -> STM BS.ByteString
lookAheadSTM b n = SBS.fromShort <$> lookAheadShortSTM b n

lookAheadShortSTM :: TWindowBuffer -> Word32 -> STM SBS.ShortByteString
lookAheadShortSTM b n = do
    q <- readTVar (bQueue b)
    lookAhead q <|> eof q
    where
        eof q = check (qEof q) >> pure mempty
        lookAhead q = do
            check $ qSize q > 0
            pure $ fst $ qDequeueShort (fromIntegral n) q

---------------------------------------------------------------------------------------------------
-- STREAM INSTANCES
---------------------------------------------------------------------------------------------------

instance S.DuplexStream TWindowBuffer

instance S.OutputStream TWindowBuffer where
    send b bs = fromIntegral <$> atomically (enqueueSTM b bs)

instance S.InputStream TWindowBuffer where
    peek b i = atomically $ lookAheadSTM b $ fromIntegral $ min i maxBoundIntWord32
    receive b i = atomically $ dequeueSTM b $ fromIntegral $ min i maxBoundIntWord32

instance S.DuplexStreamSTM TWindowBuffer

instance S.InputStreamSTM TWindowBuffer where
    peekSTM b i = lookAheadSTM b $ fromIntegral $ min i maxBoundIntWord32
    receiveSTM b i = dequeueSTM b $ fromIntegral $ min i maxBoundIntWord32

instance S.OutputStreamSTM TWindowBuffer where
    sendSTM b bs = fromIntegral <$> enqueueSTM b bs
    sendEofSTM b = do
        q <- readTVar (bQueue b)
        writeTVar (bQueue b) $! q { qEof = True }

---------------------------------------------------------------------------------------------------
-- QUEUE
---------------------------------------------------------------------------------------------------

data Queue = Queue
    { qSize       :: !Int
    , qEof        :: !Bool
    , qLeftStack  :: [SBS.ShortByteString]
    , qRightStack :: [SBS.ShortByteString]
    }

qEnqueueShort :: SBS.ShortByteString -> Queue -> Queue
qEnqueueShort bs (Queue sz eof ls rs) =
    Queue (sz + SBS.length bs) eof ls (bs:rs)

qDequeueShort :: Int -> Queue -> (SBS.ShortByteString, Queue)
qDequeueShort n q@(Queue sz eof ls rs)
    | n >= 0    = (bs, Queue (sz - SBS.length bs) eof ls' rs')
    | otherwise = (mempty, q)
    where
        (acc', ls', rs') = f n [] ls rs
        bs = case acc' of
            []  -> mempty
            [x] -> x -- save an allocation in this most likely case
            _   -> mconcat (reverse acc')
        -- Use two stacks as queue. Avalanche (right stack is reversed to left stack) happens
        -- only once for each element and time is therefor constant per enqueue/dequeue.
        f 0 acc xs     ys                    = (acc, xs, ys)
        f _ acc [] []                        = (acc, [], [])
        f i acc []     ys                    = f i acc (reverse ys) [] -- avalanche
        f i acc (x:xs) ys | SBS.length x > i = let (a,b) = splitShortAt i x in (a:acc, b:xs, ys)
                          | SBS.length x < i = f (i - SBS.length x) (x:acc) xs ys 
                          | otherwise        = (x:acc, xs, ys)

takeShort :: Int -> SBS.ShortByteString -> SBS.ShortByteString
takeShort i = SBS.toShort . BS.take i . SBS.fromShort

splitShortAt :: Int -> SBS.ShortByteString -> (SBS.ShortByteString, SBS.ShortByteString)
splitShortAt i sbs =
    let (a,b) = BS.splitAt i (SBS.fromShort sbs)
    in  (SBS.toShort a, SBS.toShort b)
