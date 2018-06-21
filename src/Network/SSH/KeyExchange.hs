module Network.SSH.KeyExchange where

import           Control.Concurrent.Async
import           Control.Concurrent.STM.TChan
import           Control.Exception
import           Control.Monad
import           Control.Monad.IO.Class
import           Control.Monad.STM
import qualified Crypto.Cipher.ChaCha         as ChaCha
import qualified Crypto.Hash                  as Hash
import qualified Crypto.MAC.Poly1305          as Poly1305
import qualified Crypto.PubKey.Curve25519     as Curve25519
import qualified Crypto.PubKey.Ed25519        as Ed25519
import           Crypto.Random.Types          (MonadRandom)
import           Data.Bits
import qualified Data.ByteArray               as BA
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Lazy         as LBS
import           Data.Monoid                  ((<>))
import qualified Data.Serialize               as B
import qualified Data.Serialize.Get           as B
import qualified Data.Serialize.Get           as C
import qualified Data.Serialize.Put           as B
import qualified Data.Serialize.Put           as C
import           Data.Stream
import           Data.Typeable
import           Data.Word

import           Network.SSH.Encoding
import           Network.SSH.Key
import           Network.SSH.Message

exchangeHash ::
    Version ->               -- client version string
    Version ->               -- server version string
    KexInit ->               -- client kex init msg
    KexInit ->               -- server kex init msg
    PublicKey ->             -- server host key
    Curve25519.PublicKey ->  -- client ephemeral key
    Curve25519.PublicKey ->  -- server ephemeral key
    Curve25519.DhSecret ->   -- dh secret
    Hash.Digest Hash.SHA256
exchangeHash (Version vc) (Version vs) ic is ks qc qs k
    = Hash.hash $ runPut $ do
        putString vc
        putString vs
        putWord32 (len ic)
        put       ic
        putWord32 (len is)
        put       is
        put       ks
        put       qc
        put       qs
        putAsMPInt k

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> BS.ByteString -> SessionId -> [BA.ScrubbedBytes]
deriveKeys sec hash i (SessionId sess) = BA.convert <$> k1 : f [k1]
  where
    k1   = Hash.hashFinalize    $
      flip Hash.hashUpdate sess $
      Hash.hashUpdate st i :: Hash.Digest Hash.SHA256
    f ks = kx : f (ks ++ [kx])
      where
        kx = Hash.hashFinalize (foldl Hash.hashUpdate st ks)
    st =
      flip Hash.hashUpdate hash $
      Hash.hashUpdate Hash.hashInit (runPut $ putAsMPInt sec)
