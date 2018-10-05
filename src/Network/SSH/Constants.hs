{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Constants where

import qualified Data.ByteString               as BS
import qualified Data.Version                  as V
import           Data.Word
import           Data.Monoid                    ( (<>) )

import           Network.SSH.Message

import qualified Paths_hssh                    as Library

version :: Version
version = Version ("SSH-2.0-hssh_" <> v)
  where
    v = BS.pack $ fmap (fromIntegral . fromEnum) (V.showVersion Library.version)

maxPacketLength :: Word32
maxPacketLength = 35000

maxBoundIntWord32 :: Num a => a
maxBoundIntWord32 = fromIntegral $ min maxBoundInt maxBoundWord32
  where
    maxBoundInt    = fromIntegral (maxBound :: Int) :: Word64
    maxBoundWord32 = fromIntegral (maxBound :: Word32) :: Word64
