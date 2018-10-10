{-# LANGUAGE LambdaCase, RankNTypes #-}
module Network.SSH.Encoding where

import           Control.Applicative
import           Control.Monad                  ( when )
import qualified Control.Monad.Fail            as Fail
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Short         as SBS
import qualified Data.Serialize.Get            as G
import           Data.Word
import           System.Exit

import qualified Network.SSH.Builder           as B 

type Get = G.Get

tryParse :: Encoding a => BS.ByteString -> Maybe a
tryParse = runGet get
{-# INLINEABLE tryParse #-}

runPut :: B.ByteArrayBuilder -> BS.ByteString
runPut = B.toByteArray
{-# INLINEABLE runPut #-}

runGet :: (Fail.MonadFail m) => Get a -> BS.ByteString -> m a
runGet g bs = case G.runGet g bs of
    Left  e -> Fail.fail e
    Right a -> pure a
{-# INLINEABLE runGet #-}

class Encoding a where
    put :: forall b. B.Builder b => a -> b
    get :: Get a

len :: Encoding a => a -> Word32
len = fromIntegral . B.length . put

instance Encoding ExitCode where
    put = \case
        ExitSuccess -> B.word32BE 0
        ExitFailure x -> B.word32BE (fromIntegral x)
    get = getWord32 >>= \case
        0 -> pure ExitSuccess
        c -> pure (ExitFailure $ fromIntegral c)

instance Encoding BS.ByteString where
    put = putByteString
    get = G.getBytes =<< G.remaining

instance (Encoding a, Encoding b) => Encoding (Either a b) where -- FIXME: WHY?
    put (Left x)  = put x
    put (Right x) = put x
    get           = (Right <$> get) <|> (Left <$> get)

getFramed :: Get a -> Get a
getFramed g = do
    w <- getWord32
    G.isolate (fromIntegral w) g

putWord8 :: B.Builder b => Word8 -> b
putWord8 = B.word8

getWord8 :: Get Word8
getWord8 = G.getWord8

expectWord8 :: Word8 -> Get ()
expectWord8 i = do
    i' <- getWord8
    when (i /= i') (fail "")

lenWord32 :: Word32
lenWord32 = 4

getWord32 :: Get Word32
getWord32 = G.getWord32be

lenBytes :: BA.ByteArrayAccess ba => ba -> Word32
lenBytes = fromIntegral . BA.length

putBytes :: B.Builder b => BA.ByteArrayAccess ba => ba -> b
putBytes = B.byteArray

getBytes :: BA.ByteArray ba => Word32 -> Get ba
getBytes i = BA.convert <$> G.getByteString (fromIntegral i)

lenByteString :: BS.ByteString -> Word32
lenByteString = fromIntegral . BA.length

putByteString :: B.Builder b => BS.ByteString -> b
putByteString = B.byteString

getByteString :: Word32 -> Get BS.ByteString
getByteString = G.getByteString . fromIntegral

getRemainingByteString :: Get BS.ByteString
getRemainingByteString = G.remaining >>= G.getBytes

lenString :: BA.ByteArrayAccess ba => ba -> Word32
lenString ba = lenWord32 + lenBytes ba

putString :: (B.Builder b, BA.ByteArrayAccess ba) => ba -> b
putString ba = B.word32BE (lenBytes ba) <> putBytes ba

putShortString :: B.Builder b => SBS.ShortByteString -> b
putShortString bs = B.word32BE (fromIntegral $ SBS.length bs) <> B.shortByteString bs

getString :: BA.ByteArray ba => Get ba
getString = do
    getBytes =<< getWord32

lenBool :: Word32
lenBool = 1

putBool :: B.Builder b => Bool -> b
putBool False = putWord8 0
putBool True  = putWord8 1

getBool :: Get Bool
getBool = (expectWord8 0 >> pure False) <|> (expectWord8 1 >> pure True)

getTrue :: Get ()
getTrue = expectWord8 1

getFalse :: Get ()
getFalse = expectWord8 0

getRemaining :: Get Int
getRemaining = G.remaining

isolate :: Int -> Get a -> Get a
isolate = G.isolate

skip :: Int -> Get ()
skip = G.skip

putPacked :: B.ByteArrayBuilder -> B.ByteArrayBuilder
putPacked payload =
    B.word32BE packetLen <>
    putWord8 (fromIntegral paddingLen) <>
    payload <>
    putByteString padding
  where
    payloadLen = let l = B.babLength payload in fromIntegral l :: Word32
    paddingLen = 16 - (4 + 1 + payloadLen) `mod` 8 :: Word32
    packetLen  = 1 + payloadLen + paddingLen :: Word32
    padding    = BS.replicate (fromIntegral paddingLen) 0 :: BS.ByteString

getUnpacked :: Encoding a => Get a
getUnpacked = do
    packetLen <- fromIntegral <$> getWord32
    isolate packetLen $ do
        paddingLen <- fromIntegral <$> getWord8
        x          <- isolate (packetLen - 1 - paddingLen) get
        skip paddingLen
        pure x

putAsMPInt :: (B.Builder b, BA.ByteArrayAccess ba) => ba -> b
putAsMPInt ba = f 0
  where
    baLen = BA.length ba
    f i | i >= baLen =
            mempty
        | BA.index ba i == 0 =
            f (i + 1)
        | BA.index ba i >= 128 =
            B.word32BE (fromIntegral $ baLen - i + 1) <>
            putWord8 0 <>
            putWord8 (BA.index ba i) <>
            g (i + 1)
        | otherwise =
            B.word32BE (fromIntegral $ baLen - i) <>
            putWord8 (BA.index ba i) <>
            g (i + 1)
    g i | i >= baLen =
            mempty
        | otherwise =
            putWord8 (BA.index ba i) <>
            g (i + 1)
