module Network.SSH.HostAddress where

import qualified Data.ByteString as BS
import           Data.Word
import           Data.String

data HostAddress = HostAddress Host Port

newtype Host = Host BS.ByteString
    deriving (Eq, Ord, Show, IsString)

newtype Port = Port Word32
    deriving (Eq, Ord, Show, Num)