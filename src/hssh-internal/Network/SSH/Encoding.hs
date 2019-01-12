{-# LANGUAGE LambdaCase, RankNTypes #-}
module Network.SSH.Encoding where

import           Control.Applicative
import           Control.Monad                  ( when )
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Short         as SBS
import qualified Data.Serialize.Get            as G
import           Data.Word
import           System.Exit

import qualified Network.SSH.Builder           as B
import           Network.SSH.Name

type Get = G.Get

class Encoding a where
    put :: forall b. B.Builder b => a -> b

class Decoding a where
    get :: Get a

runPut :: B.ByteArrayBuilder -> BS.ByteString
runPut = B.toByteArray
{-# INLINEABLE runPut #-}

runGet :: (Monad m, Decoding a) => BS.ByteString -> m a
runGet bs = case G.runGet get bs of
    Left  e -> fail e
    Right a -> pure a
{-# INLINEABLE runGet #-}

runGetter :: Monad m => BS.ByteString -> Get a -> m a
runGetter bs getter = case G.runGet getter bs of
    Left  e -> fail e
    Right a -> pure a
{-# INLINEABLE runGetter #-}

putExitCode :: B.Builder b => ExitCode -> b
putExitCode = \case
    ExitSuccess -> B.word32BE 0
    ExitFailure x -> B.word32BE (fromIntegral x)
{-# INLINEABLE putExitCode #-}

getExitCode :: Get ExitCode
getExitCode = getWord32 >>= \case
    0 -> pure ExitSuccess
    x -> pure (ExitFailure $ fromIntegral x)
{-# INLINEABLE getExitCode #-}

getFramed :: Get a -> Get a
getFramed g = do
    w <- getWord32
    G.isolate (fromIntegral w) g
{-# INLINEABLE getFramed #-}

putWord8 :: B.Builder b => Word8 -> b
putWord8 = B.word8
{-# INLINEABLE putWord8 #-}

getWord8 :: Get Word8
getWord8 = G.getWord8
{-# INLINEABLE getWord8 #-}

expectWord8 :: Word8 -> Get ()
expectWord8 i = do
    i' <- getWord8
    when (i /= i') (fail mempty)
{-# INLINEABLE expectWord8 #-}

getWord32 :: Get Word32
getWord32 = G.getWord32be
{-# INLINEABLE getWord32 #-}

putBytes :: B.Builder b => BA.ByteArrayAccess ba => ba -> b
putBytes = B.byteArray
{-# INLINEABLE putBytes #-}

getBytes :: BA.ByteArray ba => Word32 -> Get ba
getBytes i = BA.convert <$> G.getByteString (fromIntegral i)
{-# INLINEABLE getBytes #-}

lenByteString :: BS.ByteString -> Word32
lenByteString = fromIntegral . BA.length
{-# INLINEABLE lenByteString #-}

putByteString :: B.Builder b => BS.ByteString -> b
putByteString = B.byteString
{-# INLINEABLE putByteString #-}

getByteString :: Word32 -> Get BS.ByteString
getByteString = G.getByteString . fromIntegral
{-# INLINEABLE getByteString #-}

getRemainingByteString :: Get BS.ByteString
getRemainingByteString = G.remaining >>= G.getBytes
{-# INLINEABLE getRemainingByteString #-}

putString :: (B.Builder b, BA.ByteArrayAccess ba) => ba -> b
putString ba = B.word32BE (fromIntegral $ BA.length ba) <> putBytes ba
{-# INLINEABLE putString #-}

putShortString :: B.Builder b => SBS.ShortByteString -> b
putShortString bs = B.word32BE (fromIntegral $ SBS.length bs) <> B.shortByteString bs
{-# INLINEABLE putShortString #-}

getShortString :: Get SBS.ShortByteString
getShortString = SBS.toShort <$> getString
{-# INLINEABLE getShortString #-}

getString :: BA.ByteArray ba => Get ba
getString = getWord32 >>= getBytes
{-# INLINEABLE getString #-}

getName :: Get Name
getName = Name <$> getShortString
{-# INLINEABLE getName #-}

putName :: B.Builder b => Name -> b
putName (Name n) = putShortString n
{-# INLINEABLE putName #-}

putBool :: B.Builder b => Bool -> b
putBool False = putWord8 0
putBool True  = putWord8 1
{-# INLINEABLE putBool #-}

getBool :: Get Bool
getBool = (expectWord8 0 >> pure False) <|> (expectWord8 1 >> pure True)
{-# INLINEABLE getBool #-}

getTrue :: Get ()
getTrue = expectWord8 1
{-# INLINEABLE getTrue #-}

getFalse :: Get ()
getFalse = expectWord8 0
{-# INLINEABLE getFalse #-}

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
