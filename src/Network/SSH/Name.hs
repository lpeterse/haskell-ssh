module Network.SSH.Name where

import qualified Data.ByteArray        as BA
import qualified Data.ByteString.Short as SBS
import           Data.String

newtype Name = Name SBS.ShortByteString
    deriving (Eq, Ord, Show)

instance IsString Name where
    fromString = Name . SBS.toShort . BA.pack . fmap (fromIntegral . fromEnum)

class HasName a where
    name :: a -> Name