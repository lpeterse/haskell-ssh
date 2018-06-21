module Network.SSH.Server.Coding where

import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad
import           Control.Monad.IO.Class
import           Control.Monad.STM
import qualified Crypto.Cipher.ChaCha     as ChaCha
import qualified Crypto.Hash              as Hash
import qualified Crypto.MAC.Poly1305      as Poly1305
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import           Crypto.Random.Types      (MonadRandom)
import           Data.Bits
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as LBS
import           Data.Monoid              ((<>))
import qualified Data.Serialize           as B
import qualified Data.Serialize.Get       as B
import qualified Data.Serialize.Get       as C
import qualified Data.Serialize.Put       as B
import qualified Data.Serialize.Put       as C
import           Data.Stream
import           Data.Typeable
import           Data.Word

data Decoder cipher plain
    = DecoderMore (cipher -> Decoder cipher plain)
    | DecoderDone plain cipher
    | DecoderFail String

chacha20Poly1305Encode :: (BA.ByteArrayAccess headerKey, BA.ByteArrayAccess mainKey, BA.ByteArray plain, BA.ByteArray cipher)
                    => headerKey -> mainKey -> Word64 -> plain -> cipher
chacha20Poly1305Encode headerKey mainKey seqnr plain = cipher
    where
        cipher        = BA.convert $ ciph3 <> mac
        plainlen      = BA.length plain                :: Int
        padlen        = let p = 8 - ((1 + plainlen) `mod` 8)
                        in  if p < 4 then p + 8 else p :: Int
        paclen        = 1 + plainlen + padlen          :: Int
        padding       = BA.replicate padlen 0
        padlenBA      = BA.singleton (fromIntegral padlen)
        paclenBA      = BA.pack
            [ fromIntegral $ paclen `shiftR` 24
            , fromIntegral $ paclen `shiftR` 16
            , fromIntegral $ paclen `shiftR`  8
            , fromIntegral $ paclen `shiftR`  0
            ]
        nonceBA       = BA.pack
            [ fromIntegral $ seqnr  `shiftR` 56
            , fromIntegral $ seqnr  `shiftR` 48
            , fromIntegral $ seqnr  `shiftR` 40
            , fromIntegral $ seqnr  `shiftR` 32
            , fromIntegral $ seqnr  `shiftR` 24
            , fromIntegral $ seqnr  `shiftR` 16
            , fromIntegral $ seqnr  `shiftR`  8
            , fromIntegral $ seqnr  `shiftR`  0
            ] :: BA.Bytes
        st1           = ChaCha.initialize 20 mainKey nonceBA
        st2           = ChaCha.initialize 20 headerKey nonceBA
        (poly, st3)   = ChaCha.generate st1 64
        ciph1         = fst $ ChaCha.combine st2 paclenBA
        ciph2         = fst $ ChaCha.combine st3 $ padlenBA <> plain <> padding
        ciph3         = ciph1 <> ciph2
        mac           = BA.convert (Poly1305.auth (BS.take 32 poly) ciph3)

chacha20Poly1305Decoder :: (BA.ByteArrayAccess headerKey, BA.ByteArrayAccess mainKey, BA.ByteArray plain, BA.ByteArray cipher, Show cipher)
                    => headerKey -> mainKey -> Word64 -> cipher -> Decoder cipher plain
chacha20Poly1305Decoder headerKey mainKey seqnr = st0
    where
        st0 cipher
            | BA.length cipher < 4 =
                DecoderMore $ st0 . (cipher <>)
            | otherwise =
                st1 paclen paclenCiph (BA.drop 4 cipher)
            where
                cc = ChaCha.initialize 20 headerKey nonce
                paclenCiph = BA.take 4 cipher
                paclenPlain = fst $ ChaCha.combine cc paclenCiph
                paclen = fromIntegral (BA.index paclenPlain 0) `shiftL` 24
                    .|.  fromIntegral (BA.index paclenPlain 1) `shiftL` 16
                    .|.  fromIntegral (BA.index paclenPlain 2) `shiftL`  8
                    .|.  fromIntegral (BA.index paclenPlain 3) `shiftL`  0

        st1 paclen paclenCiph cipher
            | BA.length cipher < paclen =
                DecoderMore $ st1 paclen paclenCiph . (cipher <>)
            | otherwise =
                st2 paclenCiph (BA.take paclen cipher) (BA.drop paclen cipher)

        st2 paclenCiph pacCiph cipher
            | BA.length cipher < maclen =
                DecoderMore $ st2 paclenCiph pacCiph . (cipher <>)
            | otherwise = if mac == macExpected
                then DecoderDone plain (BA.drop maclen cipher)
                else DecoderFail "message authentication failed"
            where
                maclen      = 16
                cc          = ChaCha.initialize 20 mainKey nonce
                (poly, cc') = ChaCha.generate cc 64
                mac         = Poly1305.Auth (BA.convert $ BA.take maclen cipher)
                macExpected = Poly1305.auth (BS.take 32 poly) (paclenCiph <> pacCiph)
                plain       = unpad $ fst $ ChaCha.combine cc' pacCiph
                unpad ba    = case BA.uncons ba of
                    Nothing    -> BA.convert ba -- invalid input, unavoidable anyway
                    Just (h,t) -> BA.convert $ BA.take (BA.length t - fromIntegral h) t

        nonce = BA.pack
            [ fromIntegral $ seqnr  `shiftR` 56
            , fromIntegral $ seqnr  `shiftR` 48
            , fromIntegral $ seqnr  `shiftR` 40
            , fromIntegral $ seqnr  `shiftR` 32
            , fromIntegral $ seqnr  `shiftR` 24
            , fromIntegral $ seqnr  `shiftR` 16
            , fromIntegral $ seqnr  `shiftR`  8
            , fromIntegral $ seqnr  `shiftR`  0
            ] :: BA.Bytes
