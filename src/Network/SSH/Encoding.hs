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
import           Network.SSH.Name

type Get = G.Get

class Encoding a where
    put :: forall b. B.Builder b => a -> b
    get :: Get a

runPut :: B.ByteArrayBuilder -> BS.ByteString
runPut = B.toByteArray
{-# INLINEABLE runPut #-}

runGet :: (Fail.MonadFail m, Encoding a) => BS.ByteString -> m a
runGet bs = case G.runGet get bs of
    Left  e -> Fail.fail e
    Right a -> pure a
{-# INLINEABLE runGet #-}

putExitCode :: B.Builder b => ExitCode -> b
putExitCode = \case
    ExitSuccess -> B.word32BE 0
    ExitFailure x -> B.word32BE (fromIntegral x)

getExitCode :: Get ExitCode
getExitCode = getWord32 >>= \case
    0 -> pure ExitSuccess
    x -> pure (ExitFailure $ fromIntegral x)

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
    when (i /= i') (fail mempty)

getWord32 :: Get Word32
getWord32 = G.getWord32be

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

putString :: (B.Builder b, BA.ByteArrayAccess ba) => ba -> b
putString ba = B.word32BE (fromIntegral $ BA.length ba) <> putBytes ba

putShortString :: B.Builder b => SBS.ShortByteString -> b
putShortString bs = B.word32BE (fromIntegral $ SBS.length bs) <> B.shortByteString bs

getShortString :: Get SBS.ShortByteString
getShortString = SBS.toShort <$> getString

getString :: BA.ByteArray ba => Get ba
getString = getWord32 >>= getBytes

getName :: Get Name
getName = Name <$> getShortString

putName :: B.Builder b => Name -> b
putName (Name n) = putShortString n

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
