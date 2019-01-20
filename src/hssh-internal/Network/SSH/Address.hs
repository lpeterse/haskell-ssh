module Network.SSH.Address where

import           Data.Word

import           Network.SSH.Name

type SourceAddress      = Address
type DestinationAddress = Address

data Address = Address Name Port
    deriving (Eq, Ord, Show)

newtype Port = Port Word32
    deriving (Eq, Ord, Show, Num)