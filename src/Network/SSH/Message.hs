{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Message
  ( Message (..)
  , ChannelRequest (..)
  , MaxPacketSize (..)
  , InitWindowSize (..)
  , DisconnectReason (..)
  , ChannelId (..)
  , ChannelType (..)
  , ChannelOpenFailureReason (..)
  , Password (..)
  , Algorithm (..)
  , UserName (..)
  , ServiceName (..)
  , AuthMethodName (..)
  , AuthMethod (..)
  , SessionId (..)
  , PublicKey (..)
  , Signature (..)
  ) where

import           Control.Monad         (void)
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA     as RSA
import qualified Data.Binary           as B
import qualified Data.Binary.Get       as B
import qualified Data.Binary.Put       as B
import qualified Data.ByteArray        as BA
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Lazy  as LBS
import           Data.Foldable
import qualified Data.List             as L
import           Data.Monoid           ((<>))
import           Data.Word

data Message
  = Disconnect              DisconnectReason BS.ByteString BS.ByteString
  | Ignore
  | Unimplemented
  | ServiceRequest          ServiceName
  | ServiceAccept           ServiceName
  | UserAuthRequest         UserName ServiceName AuthMethod
  | UserAuthFailure         [AuthMethodName] Bool
  | UserAuthSuccess
  | UserAuthBanner          BS.ByteString BS.ByteString
  | UserAuthPublicKeyOk     PublicKey
  | ChannelOpen             ChannelType ChannelId InitWindowSize MaxPacketSize
  | ChannelOpenConfirmation ChannelId ChannelId InitWindowSize MaxPacketSize
  | ChannelOpenFailure      ChannelId ChannelOpenFailureReason
  | ChannelRequest          ChannelId ChannelRequest
  | ChannelRequestSuccess   ChannelId
  | ChannelRequestFailure   ChannelId
  | ChannelData             ChannelId BS.ByteString
  | ChannelDataExtended     ChannelId Word32 BS.ByteString
  | ChannelEof              ChannelId
  | ChannelClose            ChannelId
  deriving (Eq, Show)

data ChannelRequest
  = ChannelRequestPTY
    { crptyWantReply     :: Bool
    , crptyTerminal      :: BS.ByteString
    , crptyWidthCols     :: Word32
    , crptyHeightRows    :: Word32
    , crptyWidthPixels   :: Word32
    , crptyHeightPixels  :: Word32
    , crptyTerminalModes :: BS.ByteString
    }
  | ChannelRequestShell
    { crshlWantReply     :: Bool
    }
  | ChannelRequestOther
    { crother           :: BS.ByteString
    } deriving (Eq, Ord, Show)

data AuthMethod
  = AuthNone
  | AuthHostBased
  | AuthPassword  Password
  | AuthPublicKey Algorithm PublicKey (Maybe Signature)
  deriving (Eq, Show)

newtype Algorithm = Algorithm BS.ByteString deriving (Eq, Ord, Show)
newtype Password  = Password  BS.ByteString deriving (Eq, Ord, Show)

data PublicKey
  = PublicKeyEd25519 Ed25519.PublicKey
  | PublicKeyRSA     RSA.PublicKey
  | PublicKeyOther   BS.ByteString BS.ByteString
  deriving (Eq, Show)

data Signature
  = SignatureEd25519 Ed25519.Signature
  | SignatureRSA     BS.ByteString
  | SignatureOther   BS.ByteString BS.ByteString
  deriving (Eq, Show)

newtype DisconnectReason = DisconnectReason Word32        deriving (Eq, Ord, Show)
newtype SessionId        = SessionId        BS.ByteString deriving (Eq, Ord, Show)
newtype UserName         = UserName         BS.ByteString deriving (Eq, Ord, Show)
newtype AuthMethodName   = AuthMethodName   BS.ByteString deriving (Eq, Ord, Show)
newtype ServiceName      = ServiceName      BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelType      = ChannelType      BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelId        = ChannelId        Word32        deriving (Eq, Ord, Show)
newtype InitWindowSize   = InitWindowSize   Word32        deriving (Eq, Ord, Show)
newtype MaxPacketSize    = MaxPacketSize    Word32        deriving (Eq, Ord, Show)

data ChannelOpenFailureReason
  = ChannelOpenFailureReason
  { reasonCode        :: Word32
  , reasonDescription :: BS.ByteString
  , reasonLanguageTag :: BS.ByteString
  } deriving (Eq, Ord, Show)

getMessage :: B.Get Message
getMessage = getByte >>= \case
  1   -> Disconnect              <$> B.get <*> getString <*> getString
  2   -> pure Ignore
  3   -> pure Unimplemented
  5   -> ServiceRequest          <$> B.get
  6   -> ServiceAccept           <$> B.get
  50  -> UserAuthRequest         <$> B.get <*> B.get <*> authMethodParser
  51  -> UserAuthFailure         <$> (fmap AuthMethodName <$> getNameList) <*> getBool
  52  -> pure UserAuthSuccess
  53  -> UserAuthBanner          <$> getString    <*> getString
  60  -> UserAuthPublicKeyOk     <$> B.get
  90  -> ChannelOpen             <$> B.get <*> B.get <*> B.get  <*> B.get
  91  -> ChannelOpenConfirmation <$> B.get <*> B.get <*> B.get  <*> B.get
  92  -> ChannelOpenFailure      <$> B.get <*> B.get
  94  -> ChannelData             <$> B.get <*> getString
  95  -> ChannelDataExtended     <$> B.get <*> getUint32 <*> getString
  96  -> ChannelEof              <$> B.get
  97  -> ChannelClose            <$> B.get
  98  -> ChannelRequest          <$> B.get <*> channelRequestParser
  99  -> ChannelRequestSuccess   <$> B.get
  100 -> ChannelRequestFailure   <$> B.get
  x   -> fail ("UNKNOWN MESSAGE TYPE " ++ show x)
  where
    channelRequestParser = getString >>= \case
      "pty-req" -> ChannelRequestPTY
        <$> getBool
        <*> getString
        <*> getUint32
        <*> getUint32
        <*> getUint32
        <*> getUint32
        <*> getString
      "shell"   -> ChannelRequestShell <$> getBool
      other     -> pure (ChannelRequestOther other)

    authMethodParser = getString >>= \case
      "none"      -> pure AuthNone
      "hostbased" -> pure AuthHostBased
      "password"  -> void getBool >> AuthPassword  <$> (Password <$> getString)
      "publickey" -> do
        signed <- getBool
        algo   <- Algorithm <$> getString
        key    <- B.get
        msig   <- if signed then Just <$> B.get else pure Nothing
        pure (AuthPublicKey algo key msig)

putMessage :: Message -> B.Put
putMessage = \case
  Disconnect (DisconnectReason r) x y ->
    putByte   1 <> putUint32 r <> putString x <> putString y
  Ignore ->
    putByte   2
  Unimplemented ->
    putByte   3
  ServiceRequest (ServiceName sn) ->
    putByte   5 <> putString sn
  ServiceAccept  (ServiceName sn) ->
    putByte   6 <> putString sn
  UserAuthRequest (UserName un) (ServiceName sn) am ->
    putByte  50 <> putString un <> putString sn <> authMethodBuilder am
  UserAuthFailure methods partialSuccess ->
    putByte  51 <> putNameList ((\(AuthMethodName x)->x) <$> methods) <> putBool partialSuccess
  UserAuthSuccess ->
    putByte  52
  UserAuthBanner banner lang ->
    putByte  53 <> putString banner <> putString lang
  UserAuthPublicKeyOk pk ->
    putByte  60 <> B.put pk
  ChannelOpen (ChannelType a) (ChannelId b) (InitWindowSize c) (MaxPacketSize d) ->
    putByte  90 <> putString a <> putUint32 b <> putUint32 c <> putUint32 d
  ChannelOpenConfirmation (ChannelId a) (ChannelId b) (InitWindowSize c) (MaxPacketSize d) ->
    putByte  91 <> putUint32 a <> putUint32 b <> putUint32 c <> putUint32 d
  ChannelOpenFailure (ChannelId rid) (ChannelOpenFailureReason reason descr lang) ->
    putByte  92 <> putUint32 rid <> putUint32 reason <> putString descr <> putString lang
  ChannelData (ChannelId lid) bs ->
    putByte  94 <> putUint32 lid <> putString bs
  ChannelDataExtended (ChannelId lid) x bs ->
    putByte  95 <> putUint32 lid <> putUint32 x <> putString bs
  ChannelEof   (ChannelId lid) ->
    putByte  96 <> putUint32 lid
  ChannelClose (ChannelId lid) ->
    putByte  97 <> putUint32 lid
  ChannelRequest (ChannelId lid) req ->
    putByte  98 <> putUint32 lid <> channelRequestBuilder req
  ChannelRequestSuccess (ChannelId lid) ->
    putByte  99 <> putUint32 lid
  ChannelRequestFailure (ChannelId lid) ->
    putByte 100 <> putUint32 lid
  where
    channelRequestBuilder (ChannelRequestPTY a b c d e f g) = mconcat
      [ putString "pty-req", putBool a, putString b, putUint32 c, putUint32 d, putUint32 e, putUint32 f, putString g]
    channelRequestBuilder (ChannelRequestShell wantReply) = mconcat
      [ putString "shell", putBool wantReply ]
    channelRequestBuilder (ChannelRequestOther other) = mconcat
      [ putString other ]

    authMethodBuilder AuthNone = mconcat
      [ putString "none" ]
    authMethodBuilder AuthHostBased = mconcat
      [ putString "hostbased" ]
    authMethodBuilder (AuthPassword (Password pw)) = mconcat
      [ putString "password", putBool False, putString pw ]
    authMethodBuilder (AuthPublicKey (Algorithm algo) pk msig) = mconcat $ case msig of
      Nothing  -> [ putString "publickey", putBool False, putString algo, B.put pk ]
      Just sig -> [ putString "publickey", putBool True,  putString algo, B.put pk, B.put sig ]

-------------------------------------------------------------------------------
-- Binary instances
-------------------------------------------------------------------------------

instance B.Binary Message where
  put = putMessage
  get = getMessage

instance B.Binary DisconnectReason where
  put (DisconnectReason x) = B.putWord32be x
  get = DisconnectReason <$> B.getWord32be

instance B.Binary ChannelOpenFailureReason where
  put (ChannelOpenFailureReason c d l) = B.putWord32be c <> putString d <> putString l
  get = ChannelOpenFailureReason <$> B.getWord32be <*> getString <*> getString

instance B.Binary ChannelId where
  put (ChannelId x) = B.putWord32be x
  get = ChannelId <$> B.getWord32be

instance B.Binary InitWindowSize where
  put (InitWindowSize x) = B.putWord32be x
  get = InitWindowSize <$> B.getWord32be

instance B.Binary MaxPacketSize where
  put (MaxPacketSize x) = B.putWord32be x
  get = MaxPacketSize <$> B.getWord32be

instance B.Binary ChannelType where
  put (ChannelType s) = putString s
  get = ChannelType <$> getString

instance B.Binary SessionId where
  put (SessionId s) = putString s
  get = SessionId <$> getString

instance B.Binary ServiceName where
  put (ServiceName s) = putString s
  get = ServiceName <$> getString

instance B.Binary UserName where
  put (UserName s) = putString s
  get = UserName <$> getString

instance B.Binary PublicKey where
  put = \case
    PublicKeyEd25519    pk -> ed25519Builder    pk
    PublicKeyRSA        pk -> rsaBuilder        pk
    PublicKeyOther name pk -> otherBuilder name pk
    where
      ed25519Builder :: Ed25519.PublicKey -> B.Put
      ed25519Builder key = mconcat
        [ putUint32  51 -- total length is constant for ed25519
        , putString  "ssh-ed25519"
        , putString  (BS.pack $ BA.unpack key)
        ]

      rsaBuilder :: RSA.PublicKey -> B.Put
      rsaBuilder (RSA.PublicKey _ n e) = putFramed $ mconcat
        [ putString "ssh-rsa"
        , putInteger n
        , putInteger e
        ]

      otherBuilder :: BS.ByteString -> BS.ByteString -> B.Put
      otherBuilder name pk = putFramed $ mconcat
        [ putString name
        , putString pk
        ]
  get = getFramed $ \keysize-> getString >>= \case
    "ssh-ed25519" ->
      Ed25519.publicKey <$> getString >>= \case
        CryptoPassed k -> pure (PublicKeyEd25519 k)
        CryptoFailed e -> fail (show e)
    "ssh-rsa" -> do
      (n,_) <- getIntegerAndSize
      (e,s) <- getIntegerAndSize
      pure $ PublicKeyRSA $ RSA.PublicKey s n e
    other ->
      PublicKeyOther other <$> getString

instance B.Binary Signature where
  put = putFramed . \case
    SignatureEd25519    sig -> putString "ssh-ed25519" <> putString (BS.pack $ BA.unpack sig)
    SignatureRSA        sig -> putString "ssh-rsa"     <> putString sig
    SignatureOther algo sig -> putString algo          <> putString sig
  get = getFramed $ \sigsize-> getString >>= \case
    "ssh-ed25519" ->
      Ed25519.signature <$> getString >>= \case
        CryptoPassed s -> pure (SignatureEd25519 s)
        CryptoFailed e -> fail (show e)
    "ssh-rsa" ->
      SignatureRSA <$> getString
    other ->
      SignatureOther other <$> getString

-------------------------------------------------------------------------------
-- Util functions
-------------------------------------------------------------------------------

getNameList :: B.Get [BS.ByteString]
getNameList = do
  len <- fromIntegral <$> B.getWord32be
  BS.split 0x2c <$> B.getByteString len

putNameList :: [BS.ByteString] -> B.Put
putNameList xs =
  B.putWord32be (fromIntegral $ g xs)
  <> mconcat (B.putByteString <$> L.intersperse "," xs)
  where
    g [] = 0
    g xs = sum (BS.length <$> xs) + length xs - 1

getSize    :: B.Get Int
getSize     = fromIntegral <$> getUint32

putSize    :: Int -> B.Put
putSize   x = putUint32 (fromIntegral x)

getBool    :: B.Get Bool
getBool     = getByte >>= \case { 0 -> pure False; _ -> pure True; }

putBool    :: Bool -> B.Put
putBool   x = B.putWord8 (if x then 0x01 else 0x00)

getByte    :: B.Get Word8
getByte     = B.getWord8

putByte    :: Word8 -> B.Put
putByte     = B.putWord8

getUint32  :: B.Get Word32
getUint32   = B.getWord32be

putUint32  :: Word32 -> B.Put
putUint32   = B.putWord32be

getString  :: B.Get BS.ByteString
getString   = B.getByteString =<< getSize

putString  :: BS.ByteString -> B.Put
putString x = B.putWord32be (fromIntegral $ BS.length x) <> B.putByteString x

-- Observing the encoded length is far cheaper than calculating the
-- log2 of the resulting integer.
getIntegerAndSize :: B.Get (Integer, Int)
getIntegerAndSize = do
  bs <- BS.dropWhile (==0) <$> getString -- eventually remove leading 0 byte
  pure (foldl' (\i b-> i*256 + fromIntegral b) 0 $ BS.unpack bs, BS.length bs * 8)

putInteger :: Integer -> B.Put
putInteger x = B.putWord32be (fromIntegral $ BS.length bs) <> B.putByteString bs
  where
    bs      = BS.pack $ g $ f x []
    f 0 acc = acc
    f i acc = let (q,r) = quotRem i 256
              in  f q (fromIntegral r : acc)
    g []        = []
    g xxs@(x:_) | x > 128   = 0:xxs
                | otherwise = xxs

-- Observing the encoded length is far cheaper than calculating the
-- log2 of the resulting integer.
getSizedInteger :: B.Get (Int, Integer)
getSizedInteger  = do
  bs <- BS.dropWhile (==0) <$> getString -- eventually remove leading 0 byte
  pure (BS.length bs * 8, foldl' (\i b-> i*256 + fromIntegral b) 0 $ BS.unpack bs)

putFramed :: B.Put -> B.Put
putFramed b = B.putWord32be (fromIntegral $ LBS.length lbs) <> B.putLazyByteString lbs
  where
    lbs = B.runPut b

getFramed :: (Int -> B.Get a) -> B.Get a
getFramed f = do
  i <- getSize
  B.isolate i (f i)
