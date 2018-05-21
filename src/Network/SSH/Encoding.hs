{-# LANGUAGE LambdaCase #-}
module Network.SSH.Encoding where

import           Control.Applicative
import           Control.Monad       (when)
import qualified Control.Monad.Fail  as Fail
import           Data.Bits
import qualified Data.ByteArray      as BA
import qualified Data.ByteString     as BS
import qualified Data.Serialize.Get  as G
import qualified Data.Serialize.Put  as P
import           Data.Word
import           System.Exit

type Put = P.Put
type Get = G.Get

runPut :: BA.ByteArray ba => Put -> ba
runPut = BA.convert . P.runPut

runGet :: (Fail.MonadFail m, BA.ByteArray ba) => Get a -> ba -> m a
runGet g ba = case G.runGet g (BA.convert ba) of
    Left e  -> Fail.fail e
    Right a -> pure a

class Encoding a where
    len :: a -> Word32
    put :: a -> Put
    get :: Get a

instance Encoding ExitCode where
    len = const 4
    put = \case
        ExitSuccess -> putWord32 0
        ExitFailure x -> putWord32 (fromIntegral x)
    get = getWord32 >>= \case
        0 -> pure ExitSuccess
        c -> pure (ExitFailure $ fromIntegral c)

lenWord8 :: Word32
lenWord8 = 1

putWord8 :: Word8 -> Put
putWord8 = P.putWord8

getWord8 :: Get Word8
getWord8 = G.getWord8

expectWord8 :: Word8 -> Get ()
expectWord8 i = do
    i' <- getWord8
    when (i /= i') (fail "")

lenWord32 :: Word32
lenWord32 = 4

putWord32 :: Word32 -> Put
putWord32 = P.putWord32be

getWord32 :: Get Word32
getWord32 = G.getWord32be

lenBytes :: BA.ByteArrayAccess ba => ba -> Word32
lenBytes = fromIntegral . BA.length

putBytes :: BA.ByteArrayAccess ba => ba -> Put
putBytes = P.putByteString . BA.convert

getBytes :: BA.ByteArray ba => Word32 -> Get ba
getBytes i = BA.convert <$> G.getByteString (fromIntegral i)

putByteString :: BS.ByteString -> Put
putByteString = P.putByteString

getByteString :: Word32 -> Get BS.ByteString
getByteString = G.getByteString . fromIntegral

lenString :: BA.ByteArrayAccess ba => ba -> Word32
lenString ba = lenWord32 + lenBytes ba

putString :: BA.ByteArrayAccess ba => ba -> Put
putString ba = do
    putWord32 (lenBytes ba)
    putBytes ba

getString :: BA.ByteArray ba => Get ba
getString = do
    len <- getWord32
    getBytes len

lenBool :: Word32
lenBool = 1

putBool :: Bool -> Put
putBool False = putWord8 0
putBool True  = putWord8 1

getBool :: Get Bool
getBool = (expectWord8 0 >> pure False) <|> (expectWord8 1 >> pure True)

getTrue :: Get ()
getTrue = expectWord8 1

getFalse :: Get ()
getFalse = expectWord8 0
