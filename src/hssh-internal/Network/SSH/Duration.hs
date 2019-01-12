module Network.SSH.Duration where

import Data.Word

newtype Duration = Duration Word64 -- Microseconds
    deriving (Eq, Ord, Show)

seconds :: Integral a => a -> Duration
seconds i = Duration (1000000 * fromIntegral i)