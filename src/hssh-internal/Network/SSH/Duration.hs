module Network.SSH.Duration where

import Data.Word

newtype Duration = Duration { asMicroSeconds :: Word64 }
    deriving (Eq, Ord, Show)

seconds :: Int -> Duration
seconds i = Duration (1000000 * fromIntegral i)
