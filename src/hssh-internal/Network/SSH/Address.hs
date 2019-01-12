module Network.SSH.Address where

import qualified Data.ByteString as BS

data Address
    = Address
    { host :: BS.ByteString
    , port :: BS.ByteString
    } deriving (Eq, Ord, Show)