module Network.SSH.Environment where

import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BS8
import           System.Environment


-- | The `Environment` is list of key-value pairs.
--
--   > Environment [ ("LC_ALL", "en_US.UTF-8") ]
newtype Environment = Environment [(BS.ByteString, BS.ByteString)]
    deriving (Eq, Ord, Show)

getDefaultEnvironment :: IO Environment
getDefaultEnvironment = do
    env <- fmap f <$> getEnvironment
    pure $ Environment $ filter predicate env
    where
        f (k, v) = (BS8.pack k, BS8.pack v)
        predicate k = fst k == "LANG" || "LC_" `BS.isPrefixOf` fst k 
