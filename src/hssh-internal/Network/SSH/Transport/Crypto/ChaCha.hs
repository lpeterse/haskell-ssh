-- |
-- Module      : Network.SSH.Transport.Crypto.ChaCha
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
-- ChaCha implementation
--
-- This module is a copy taken from the cryptonite library and extended by mutable state
-- in order to reduce memory allocations when performing the
-- same operation again and again. Remove when cryptonite offers this funtionality!
--
module Network.SSH.Transport.Crypto.ChaCha where

import           Data.Word
import           Data.ByteArray (ByteArrayAccess, ScrubbedBytes)
import qualified Data.ByteArray as B
import           Foreign.Ptr
import           Foreign.C.Types

newtype MutableState = MutableState ScrubbedBytes

new :: IO MutableState
new = MutableState <$> B.alloc 132 (const $ pure ())

initialize :: (ByteArrayAccess key, ByteArrayAccess nonce)
    => MutableState -> Int -> key -> nonce -> IO ()
initialize (MutableState state) rounds key nonce =
    B.withByteArray state $ \statePtr ->
    B.withByteArray nonce $ \noncePtr  ->
    B.withByteArray key   $ \keyPtr ->
        ccryptonite_chacha_init statePtr (fromIntegral rounds) keyLen keyPtr nonceLen noncePtr
    where
        keyLen   = B.length key
        nonceLen = B.length nonce

generateUnsafe :: MutableState -> Ptr Word8 -> Int -> IO ()
generateUnsafe (MutableState state) dstPtr len =
    B.withByteArray state $ \statePtr ->
        ccryptonite_chacha_generate dstPtr statePtr (fromIntegral len)

combineUnsafe :: MutableState -> Ptr Word8 -> Ptr Word8 -> Int -> IO ()
combineUnsafe (MutableState state) dstPtr srcPtr len =
    B.withByteArray state $ \statePtr ->
        ccryptonite_chacha_combine dstPtr statePtr srcPtr (fromIntegral len)

foreign import ccall unsafe "cryptonite_chacha_init"
    ccryptonite_chacha_init :: Ptr state -> Int -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> IO ()

foreign import ccall unsafe "cryptonite_chacha_combine"
    ccryptonite_chacha_combine :: Ptr Word8 -> Ptr state -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall unsafe "cryptonite_chacha_generate"
    ccryptonite_chacha_generate :: Ptr Word8 -> Ptr state -> CUInt -> IO ()
