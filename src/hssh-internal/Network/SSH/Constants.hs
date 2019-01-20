{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Constants where

import qualified Data.ByteString               as BS
import qualified Data.ByteString.Short         as SBS
import qualified Data.Version                  as V
import           Data.Word
import           Data.Monoid                    ( (<>) )

import           Network.SSH.Message

import qualified Paths_hssh                    as Library

defaultVersion :: Version
defaultVersion = Version ("SSH-2.0-hssh_" <> v)
  where
    v = SBS.toShort $ BS.pack $ fmap (fromIntegral . fromEnum) (V.showVersion Library.version)

-- | Maximum transport packet size.
--
-- RFC 4253: "All implementations MUST be able to process packets with an
-- uncompressed payload length of 32768 bytes or less and a total packet
-- size of 35000 bytes or less"
maxPacketLength :: Word32
maxPacketLength = 35000

-- | Maximum connection layer data packet size.
--
-- TODO: Not quite sure how to interpret the RFC. This value should
-- leave enough space for all forms of misinterpretation.
maxDataPacketLength :: Word32
maxDataPacketLength = 32000

maxBoundIntWord32 :: Num a => a
maxBoundIntWord32 = fromIntegral $ min maxBoundInt maxBoundWord32
  where
    maxBoundInt    = fromIntegral (maxBound :: Int) :: Word64
    maxBoundWord32 = fromIntegral (maxBound :: Word32) :: Word64
