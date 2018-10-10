-- |
-- Module      : Network.SSH.Crypto.ChaCha
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
module Network.SSH.Crypto.ChaCha where

import           Data.Word
import           Data.ByteArray (ByteArrayAccess, ScrubbedBytes)
import qualified Data.ByteArray as B
import           Foreign.Ptr
import           Foreign.C.Types

newtype MutableState = MutableState ScrubbedBytes

new :: IO MutableState
new = MutableState <$> B.alloc 132 (const $ pure ())

initialize :: (ByteArrayAccess key, ByteArrayAccess nonce)
    => MutableState
    -> Int   -- ^ number of rounds (8,12,20)
    -> key   -- ^ the key (128 or 256 bits)
    -> nonce -- ^ the nonce (64 or 96 bits)
    -> IO () -- ^ the initial ChaCha state
initialize (MutableState st) nbRounds key nonce
    | not (kLen `elem` [16,32])       = error "ChaCha: key length should be 128 or 256 bits"
    | not (nonceLen `elem` [8,12])    = error "ChaCha: nonce length should be 64 or 96 bits"
    | not (nbRounds `elem` [8,12,20]) = error "ChaCha: rounds should be 8, 12 or 20"
    | otherwise                       =
        B.withByteArray st $ \stPtr ->
        B.withByteArray nonce $ \noncePtr  ->
        B.withByteArray key   $ \keyPtr ->
            ccryptonite_chacha_init stPtr (fromIntegral nbRounds) kLen keyPtr nonceLen noncePtr
    where
        kLen     = B.length key
        nonceLen = B.length nonce

generateUnsafe :: MutableState
    -> Ptr Word8
    -> Int
    -> IO ()
generateUnsafe (MutableState st) dstPtr len =
    B.withByteArray st $ \ctx ->
        ccryptonite_chacha_generate dstPtr ctx (fromIntegral len)

combineUnsafe :: MutableState
    -> Ptr Word8
    -> Ptr Word8
    -> Int
    -> IO ()
combineUnsafe (MutableState st) dstPtr srcPtr len =
    B.withByteArray st $ \ctx ->
        ccryptonite_chacha_combine dstPtr ctx srcPtr (fromIntegral len)

foreign import ccall unsafe "cryptonite_chacha_init"
    ccryptonite_chacha_init :: Ptr state -> Int -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> IO ()

foreign import ccall unsafe "cryptonite_chacha_combine"
    ccryptonite_chacha_combine :: Ptr Word8 -> Ptr state -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall unsafe "cryptonite_chacha_generate"
    ccryptonite_chacha_generate :: Ptr Word8 -> Ptr state -> CUInt -> IO ()
