{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Message.Util where

import           Control.Monad            (void, when)
import           Crypto.Error
import qualified Crypto.Error             as DH
import qualified Crypto.Hash              as Hash
import qualified Crypto.Hash.Algorithms   as Hash
import qualified Crypto.PubKey.Curve25519 as DH
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA.PKCS15
import qualified Data.Binary              as B
import qualified Data.Binary.Get          as B
import qualified Data.Binary.Put          as B
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as LBS
import           Data.Foldable
import           Data.Int
import qualified Data.List                as L
import           Data.Monoid
import           Data.Word

getNameList :: B.Get [BS.ByteString]
getNameList = do
  len <- fromIntegral <$> B.getWord32be
  BS.split 0x2c <$> B.getByteString len

putNameList :: [BS.ByteString] -> B.Put
putNameList xs =
  B.putWord32be (fromIntegral $ g xs)
  <> mconcat (B.putByteString <$> L.intersperse "," xs)
  where
    g [] = 0
    g xs = sum (BS.length <$> xs) + length xs - 1

getSize    :: B.Get Int
getSize     = fromIntegral <$> getUint32

putSize    :: Int -> B.Put
putSize   x = putUint32 (fromIntegral x)

getBool    :: B.Get Bool
getBool     = getByte >>= \case { 0 -> pure False; _ -> pure True; }

putBool    :: Bool -> B.Put
putBool   x = B.putWord8 (if x then 0x01 else 0x00)

getByte    :: B.Get Word8
getByte     = B.getWord8

putByte    :: Word8 -> B.Put
putByte     = B.putWord8

getUint32  :: B.Get Word32
getUint32   = B.getWord32be

putUint32  :: Word32 -> B.Put
putUint32   = B.putWord32be

getString  :: B.Get BS.ByteString
getString   = B.getByteString =<< getSize

putString  :: BS.ByteString -> B.Put
putString x = B.putWord32be (fromIntegral $ BS.length x) <> B.putByteString x

-- Observing the encoded length is far cheaper than calculating the
-- log2 of the resulting integer.
getIntegerAndSize :: B.Get (Integer, Int)
getIntegerAndSize = do
  bs <- BS.dropWhile (==0) <$> getString -- eventually remove leading 0 byte
  pure (foldl' (\i b-> i*256 + fromIntegral b) 0 $ BS.unpack bs, BS.length bs * 8)

putInteger :: Integer -> B.Put
putInteger x = B.putWord32be (fromIntegral $ BS.length bs) <> B.putByteString bs
  where
    bs      = BS.pack $ g $ f x []
    f 0 acc = acc
    f i acc = let (q,r) = quotRem i 256
              in  f q (fromIntegral r : acc)
    g []        = []
    g xxs@(x:_) | x > 128   = 0:xxs
                | otherwise = xxs

-- Observing the encoded length is far cheaper than calculating the
-- log2 of the resulting integer.
getSizedInteger :: B.Get (Int, Integer)
getSizedInteger  = do
  bs <- BS.dropWhile (==0) <$> getString -- eventually remove leading 0 byte
  pure (BS.length bs * 8, foldl' (\i b-> i*256 + fromIntegral b) 0 $ BS.unpack bs)

putFramed :: B.Put -> B.Put
putFramed b = B.putWord32be (fromIntegral $ LBS.length lbs) <> B.putLazyByteString lbs
  where
    lbs = B.runPut b

getFramed :: (Int -> B.Get a) -> B.Get a
getFramed f = do
  i <- getSize
  B.isolate i (f i)
