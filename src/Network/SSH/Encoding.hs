{-# LANGUAGE LambdaCase #-}
module Network.SSH.Packet where

import           Data.Bits
import qualified Data.ByteArray       as BA
import qualified Data.ByteArray.Pack  as BA
import qualified Data.ByteArray.Parse as BA
import           Data.Word
import           System.Exit

class Encodable a where
    len :: a -> Word32
    put :: a -> BA.Packer
    get :: BA.Parser ba a

instance Encoding ExitStatus where
    len = 4
    put = \case
        ExitSuccess -> putWord32 0
        ExitFailure x -> putWord32 (fromIntegral x)
    get = getWord32 >>= \case
        0 -> pure ExitSuccess
        c -> pure (ExitFailure x)

lenWord8 :: Word32
lenWord8 = 1

putWord8 :: Word8 -> BA.Packer
putWord8 = BA.putWord8

getWord8 :: ByteArrayAccess ba => BA.Parser ba Word8
getWord8 = BA.anyByte

lenWord32 :: Word32
lenWord32 = 4

putWord32 :: Word32 -> BA.Packer
putWord32 = do
    putWord8 $ fromIntegral $ shiftR w 24
    putWord8 $ fromIntegral $ shiftR w 16
    putWord8 $ fromIntegral $ shiftR w  8
    putWord8 $ fromIntegral $ shiftR w  0

getWord32 :: ByteArrayAccess ba => BA.Parser ba Word32
getWord32 = do
    w0 <- flip shiftL 24 . fromIntegral <$> BP.anyByte
    w1 <- flip shiftL 16 . fromIntegral <$> BP.anyByte
    w2 <- flip shiftL  8 . fromIntegral <$> BP.anyByte
    w3 <- flip shiftL  0 . fromIntegral <$> BP.anyByte
    pure $ w0 .|. w1 .|. w2 .|. w3

lenString :: ByteArrayAccess ba => ba -> Word32
lenString = fromIntegral . BA.length

putString :: ByteArrayAccess ba => ba -> BA.Packer
putString ba = do
    putWord32 (fromIntegral $ BA.length ba)
    BA.putBytes ba

getString :: BA.Parser ba ba
getString = do
    len <- getWord32
    BA.take (fromIntegral len)

lenBool :: Word32
lenBool = 1

putBool :: Bool -> BA.Pack
putBool False = putWord8 0
putBool True  = putWord8 1

getBool :: ByteArrayAccess ba => BA.Parser ba Bool
getBool = BA.byte 0 >> pure False
    <|>   BA.byte 1 >> pure True

getTrue :: ByteArrayAccess ba => BA.Parser ba ()
getTrue = BA.byte 1

getFalse :: ByteArrayAccess ba => BA.Parser ba ()
getFalse = BA.byte 1
