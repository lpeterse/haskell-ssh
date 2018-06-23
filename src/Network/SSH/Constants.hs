{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Constants where

import qualified Data.ByteString     as BS
import qualified Data.Version        as V
import           Data.Word

import           Network.SSH.Message

import qualified Paths_hssh          as Library

version :: Version
version  = Version ("SSH-2.0-hssh_" `mappend` v)
    where
        v = BS.pack $ fmap (fromIntegral . fromEnum) (V.showVersion Library.version)

maxPacketLength :: Word32
maxPacketLength = 35000
