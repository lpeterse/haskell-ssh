{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH
  ( packetize, unpacketize
  , exchangeHash
  , deriveKeys
  , verifyAuthSignature
  , SshException (..)
  ) where

import           Control.Exception
import qualified Crypto.Hash              as Hash
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA.PKCS15 as RSA.PKCS15
import qualified Data.Binary              as B
import qualified Data.Binary.Get          as B
import qualified Data.Binary.Put          as B
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as LBS
import           Data.Monoid              ((<>))
import           Data.Typeable
import           Data.Word

import           Network.SSH.Message

data SshException
  = SshMacMismatchException
  | SshUnexpectedEndOfInputException
  deriving (Eq, Ord, Show, Typeable)

instance Exception SshException

packetize :: B.Put -> B.Put
packetize payload = mconcat
  [ B.putWord32be $ fromIntegral packetLen
  , B.putWord8    $ fromIntegral paddingLen
  , payload
  , padding
  ]
  where
    packetLen  = 1 + payloadLen + paddingLen
    payloadLen = fromIntegral $ LBS.length (B.runPut payload)
    paddingLen = 16 - (4 + 1 + payloadLen) `mod` 8
    padding    = B.putByteString (BS.replicate paddingLen 0)

unpacketize :: B.Get a -> B.Get a
unpacketize parser = do
  packetLen <- fromIntegral <$> B.getWord32be
  B.isolate packetLen $ do
    paddingLen <- fromIntegral <$> B.getWord8
    x <- parser
    B.skip paddingLen
    pure x

exchangeHash ::
  Version ->               -- client version string
  Version ->               -- server version string
  KexInit ->               -- client kex init msg
  KexInit ->               -- server kex init msg
  Ed25519.PublicKey ->     -- server host key
  Curve25519.PublicKey ->  -- client ephemeral key
  Curve25519.PublicKey ->  -- server ephemeral key
  Curve25519.DhSecret ->   -- dh secret
  Hash.Digest Hash.SHA256
exchangeHash (Version vc) (Version vs) ic is ks qc qs k
  = Hash.hash $ LBS.toStrict $ B.runPut $ mconcat
  [ B.putWord32be              vcLen
  , B.putByteString            vc
  , B.putWord32be              vsLen
  , B.putByteString            vs
  , B.putWord32be              icLen
  , B.putWord8                 20 -- SSH2_MSG_KEXINIT
  , B.put                      ic
  , B.putWord32be              isLen
  , B.putWord8                 20 -- SSH2_MSG_KEXINIT
  , B.put                      is
  , ed25519PublicKeyBuilder    ks
  , curve25519BlobBuilder      qc
  , curve25519BlobBuilder      qs
  , putMpint (BA.unpack k)
  ] :: Hash.Digest Hash.SHA256
  where
    vcLen = fromIntegral $     BS.length vc
    vsLen = fromIntegral $     BS.length vs
    icLen = fromIntegral $ 1 + LBS.length (B.runPut $ B.put ic)
    isLen = fromIntegral $ 1 + LBS.length (B.runPut $ B.put is)

    ed25519PublicKeyBuilder :: Ed25519.PublicKey -> B.Put
    ed25519PublicKeyBuilder key = mconcat
      [ B.putWord32be     51 -- host key len
      , B.putWord32be     11 -- host key algorithm name len
      , B.putByteString   "ssh-ed25519"
      , B.putWord32be     32 -- host key data len
      , B.putByteString $ BS.pack $ BA.unpack key
      ]

    curve25519BlobBuilder :: Curve25519.PublicKey -> B.Put
    curve25519BlobBuilder key =
      B.putWord32be 32 <> B.putByteString (BS.pack $ BA.unpack key)

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> BS.ByteString -> SessionId -> [BA.ScrubbedBytes]
deriveKeys sec hash i (SessionId sess) = BA.pack . BA.unpack <$> k1 : f [k1]
  where
    k1   = Hash.hashFinalize    $
      flip Hash.hashUpdate sess $
      Hash.hashUpdate st i :: Hash.Digest Hash.SHA256
    f ks = kx : f (ks ++ [kx])
      where
        kx = Hash.hashFinalize (foldl Hash.hashUpdate st ks)
    st =
      flip Hash.hashUpdate hash $
      Hash.hashUpdate Hash.hashInit secmpint
    secmpint =
      LBS.toStrict $ B.runPut $ putMpint $ BA.unpack sec

verifyAuthSignature :: SessionId -> UserName -> ServiceName -> Algorithm -> PublicKey -> Signature -> Bool
verifyAuthSignature sessionIdentifier userName serviceName algorithm publicKey signature =
  case (publicKey,signature) of
    (PublicKeyEd25519 k, SignatureEd25519 s) -> Ed25519.verify k signedData s
    (PublicKeyRSA     k, SignatureRSA     s) -> RSA.PKCS15.verify (Just Hash.SHA1) k signedData s
    _                                        -> False
  where
    signedData :: BS.ByteString
    signedData = LBS.toStrict $ B.runPut $ mconcat
      [ B.put           sessionIdentifier
      , B.putWord8      50
      , B.put           userName
      , B.put           serviceName
      , B.putWord32be   9
      , B.putByteString "publickey"
      , B.putWord8      1
      , B.put           algorithm
      , B.put           publicKey
      ]

putMpint :: [Word8] -> B.Put
putMpint xs = zs
  where
    prepend [] = []
    prepend (a:as)
      | a >= 128  = 0:a:as
      | otherwise = a:as
    ys = BS.pack $ prepend $ dropWhile (==0) xs
    zs = B.putWord32be (fromIntegral $ BS.length ys) <> B.putByteString ys
