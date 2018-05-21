{-# LANGUAGE LambdaCase #-}
module Network.SSH.Encoding where

import           Control.Applicative
import           Data.Bits
import qualified Data.ByteArray       as BA
import qualified Data.ByteArray.Pack  as BA
import qualified Data.ByteArray.Parse as BP
import           Data.Word
import           System.Exit

type Putter = BA.Packer ()
type Getter = BP.Parser BA.Bytes

class Encoding a where
    len :: a -> Word32
    put :: a -> Putter
    get :: Getter a

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

putWord8 :: Word8 -> Putter
putWord8 = BA.putWord8

getWord8 :: Getter Word8
getWord8 = BP.anyByte

lenWord32 :: Word32
lenWord32 = 4

putWord32 :: Word32 -> Putter
putWord32 w = do
    putWord8 $ fromIntegral $ shiftR w 24
    putWord8 $ fromIntegral $ shiftR w 16
    putWord8 $ fromIntegral $ shiftR w  8
    putWord8 $ fromIntegral $ shiftR w  0

getWord32 :: Getter Word32
getWord32 = do
    w0 <- flip shiftL 24 . fromIntegral <$> BP.anyByte
    w1 <- flip shiftL 16 . fromIntegral <$> BP.anyByte
    w2 <- flip shiftL  8 . fromIntegral <$> BP.anyByte
    w3 <- flip shiftL  0 . fromIntegral <$> BP.anyByte
    pure $ w0 .|. w1 .|. w2 .|. w3

lenString :: BA.ByteArrayAccess ba => ba -> Word32
lenString = fromIntegral . BA.length

putString :: BA.ByteArrayAccess ba => ba -> Putter
putString ba = do
    putWord32 (fromIntegral $ BA.length ba)
    BA.putBytes ba

getString :: BA.ByteArray ba => Getter ba
getString = do
    len <- getWord32
    BA.convert <$> BP.take (fromIntegral len)

lenBool :: Word32
lenBool = 1

putBool :: Bool -> Putter
putBool False = putWord8 0
putBool True  = putWord8 1

getBool :: Getter Bool
getBool = (BP.byte 0 >> pure False) <|> (BP.byte 1 >> pure True)

getTrue :: Getter ()
getTrue = BP.byte 1

getFalse :: Getter ()
getFalse = BP.byte 0
