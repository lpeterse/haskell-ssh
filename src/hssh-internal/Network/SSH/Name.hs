module Network.SSH.Name where

import qualified Data.ByteString       as BS
import           Data.String

newtype Name = Name BS.ByteString
    deriving (Eq, Ord, Show, IsString)

class HasName a where
    name :: a -> Name

instance HasName Name where
    name = id

instance HasName () where
    name = const (Name "()")