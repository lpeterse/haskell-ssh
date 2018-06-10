module Data.Count where

import           Control.Monad.Fail
import           Data.Word

newtype Count a = Count Word64
    deriving (Eq, Ord, Show)

fromIntDefault :: Count a -> Int -> Count a
fromIntDefault def i
    | i < 0     = def
    | otherwise = Count (fromIntegral i)

toIntDefault :: Int -> Count a -> Int
toIntDefault def (Count a)
    | a > fromIntegral (maxBound :: Int) = def
    | otherwise = fromIntegral a
