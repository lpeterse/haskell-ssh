-- |
-- Module      : Network.SSH.Crypto.Poly1305
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Poly1305 implementation
--
-- This module is a copy taken from the cryptonite library and extended by mutable state
-- in order to reduce memory allocations when performing the
-- same operation again and again. Remove when cryptonite offers this funtionality!
--
module Network.SSH.Crypto.Poly1305 where

import           Data.Word
import           Data.ByteArray (ByteArrayAccess, ScrubbedBytes)
import qualified Data.ByteArray as B
import           Foreign.Ptr
import           Foreign.C.Types

newtype MutableState = MutableState ScrubbedBytes

new :: IO MutableState
new = MutableState <$> B.alloc 84 (const $ pure ())

authUnsafe :: (ByteArrayAccess key, ByteArrayAccess ba) => MutableState -> key -> ba -> Ptr Word8 -> IO ()
authUnsafe (MutableState ctx) key d dstPtr
    | B.length key /= 32 = error "Poly1305: key length expected 32 bytes"
    | otherwise          = 
        B.withByteArray ctx $ \ctxPtr ->
        B.withByteArray key $ \keyPtr -> do
            c_poly1305_init (castPtr ctxPtr) keyPtr
            B.withByteArray d $ \dataPtr ->
                c_poly1305_update (castPtr ctxPtr) dataPtr (fromIntegral $ B.length d)
            c_poly1305_finalize dstPtr (castPtr ctxPtr)

foreign import ccall unsafe "cryptonite_poly1305.h cryptonite_poly1305_init"
    c_poly1305_init :: Ptr state -> Ptr Word8 -> IO ()

foreign import ccall unsafe "cryptonite_poly1305.h cryptonite_poly1305_update"
    c_poly1305_update :: Ptr state -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall unsafe "cryptonite_poly1305.h cryptonite_poly1305_finalize"
    c_poly1305_finalize :: Ptr Word8 -> Ptr state -> IO ()