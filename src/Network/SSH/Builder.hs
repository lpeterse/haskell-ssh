{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE RankNTypes                 #-}
module Network.SSH.Builder where

import           Control.Monad (void)
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as SBS
import qualified Data.ByteString.Short.Internal as SBS
import qualified Data.ByteArray  as BA
import           Foreign.Ptr
import           Foreign.Storable
import           Data.Word
import           Data.Semigroup
import           Data.List.NonEmpty ( NonEmpty ((:|)) )
import           Prelude hiding (length)

class Monoid a => Builder a where
    word8      :: Word8 -> a
    word16BE   :: Word16 -> a
    word16BE x  = word8 (fromIntegral $ x `unsafeShiftR` 8)
               <> word8 (fromIntegral   x)
    word32BE   :: Word32 -> a
    word32BE x  = word8 (fromIntegral $ x `unsafeShiftR` 24)
               <> word8 (fromIntegral $ x `unsafeShiftR` 16)
               <> word8 (fromIntegral $ x `unsafeShiftR`  8)
               <> word8 (fromIntegral   x)
    word64BE   :: Word64 -> a
    word64BE x  = word8 (fromIntegral $ x `unsafeShiftR` 56)
               <> word8 (fromIntegral $ x `unsafeShiftR` 48)
               <> word8 (fromIntegral $ x `unsafeShiftR` 40)
               <> word8 (fromIntegral $ x `unsafeShiftR` 32)
               <> word8 (fromIntegral $ x `unsafeShiftR` 24)
               <> word8 (fromIntegral $ x `unsafeShiftR` 16)
               <> word8 (fromIntegral $ x `unsafeShiftR`  8)
               <> word8 (fromIntegral   x)
    byteArray :: forall ba. BA.ByteArrayAccess ba => ba -> a
    byteArray x =
        foldl (\acc i-> acc <> word8 (BA.index x i)) mempty [0.. BA.length x - 1]
    byteString :: BS.ByteString -> a
    byteString = byteArray 
    shortByteString :: SBS.ShortByteString -> a
    shortByteString x = 
        foldl (\acc i-> acc <> word8 (SBS.index x i)) mempty [0.. SBS.length x - 1]
    {-# MINIMAL word8 #-}

newtype Length = Length { length :: Int }
    deriving (Eq, Ord, Show, Num)

newtype PtrWriter = PtrWriter { runPtrWriter :: Ptr Word8 -> IO (Ptr Word8) }

instance Semigroup Length where
    Length i <> Length j = Length (i + j)
    sconcat (Length i :| is) = Length (f is i)
        where
            f [] acc = acc
            f (Length j:js) acc = f js $! acc + j

instance Monoid Length where
    mempty = 0
    mconcat is = Length (f is 0)
        where
            f [] acc = acc
            f (Length j:js) acc = f js $! acc + j

instance Builder Length where
    word8           = const 1
    word16BE        = const 2
    word32BE        = const 4
    word64BE        = const 8
    byteArray       = Length. BA.length
    byteString      = Length . BS.length
    shortByteString = Length . SBS.length
{-# SPECIALIZE word8           :: Word8           -> Length #-}
{-# SPECIALIZE word16BE        :: Word16          -> Length #-}
{-# SPECIALIZE word32BE        :: Word32          -> Length #-}
{-# SPECIALIZE word64BE        :: Word64          -> Length #-}
{-# SPECIALIZE byteArray       :: byteArray       -> Length #-}
{-# SPECIALIZE byteString      :: byteString      -> Length #-}
{-# SPECIALIZE shortByteString :: shortByteString -> Length #-}

instance Semigroup PtrWriter where
    PtrWriter f <> PtrWriter g = PtrWriter $ \ptr -> f ptr >>= g

instance Monoid PtrWriter where
    mempty = PtrWriter pure

instance Builder PtrWriter where
    word8 x = PtrWriter $ \ptr -> do
        poke ptr x
        pure (plusPtr ptr 1)
    byteArray x = PtrWriter $ \ptr -> do
        BA.copyByteArrayToPtr x ptr
        pure (plusPtr ptr $ BA.length x)
    byteString x = PtrWriter $ \ptr -> do
        BA.copyByteArrayToPtr x ptr
        pure (plusPtr ptr $ BA.length x)
    shortByteString x = PtrWriter $ \ptr -> do
        let l = SBS.length x
        SBS.copyToPtr x 0 ptr l
        pure (plusPtr ptr l) 
{-# SPECIALIZE word8           :: Word8           -> PtrWriter #-}
{-# SPECIALIZE word16BE        :: Word16          -> PtrWriter #-}
{-# SPECIALIZE word32BE        :: Word32          -> PtrWriter #-}
{-# SPECIALIZE word64BE        :: Word64          -> PtrWriter #-}
{-# SPECIALIZE byteArray       :: byteArray       -> PtrWriter #-}
{-# SPECIALIZE byteString      :: byteString      -> PtrWriter #-}
{-# SPECIALIZE shortByteString :: shortByteString -> PtrWriter #-}

data ByteArrayWriter = ByteArrayWriter Length PtrWriter

instance Semigroup ByteArrayWriter where
    ByteArrayWriter c0 w0 <> ByteArrayWriter c1 w1 =
        ByteArrayWriter (c0 <> c1) (w0 <> w1)

instance Monoid ByteArrayWriter where
    mempty = ByteArrayWriter mempty mempty

instance Builder ByteArrayWriter where
    word8           x = ByteArrayWriter (word8           x) (word8           x)
    word16BE        x = ByteArrayWriter (word16BE        x) (word16BE        x)
    word32BE        x = ByteArrayWriter (word32BE        x) (word32BE        x)
    word64BE        x = ByteArrayWriter (word64BE        x) (word64BE        x)
    byteArray       x = ByteArrayWriter (byteArray       x) (byteArray       x)
    byteString      x = ByteArrayWriter (byteString      x) (byteString      x)
    shortByteString x = ByteArrayWriter (shortByteString x) (shortByteString x)

toByteArray :: BA.ByteArray ba => ByteArrayWriter -> ba
toByteArray (ByteArrayWriter c w) = BA.allocAndFreeze (length c) $ void . runPtrWriter w
