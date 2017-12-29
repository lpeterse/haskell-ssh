{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Message
  ( Message (..), getMessage, putMessage
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
  , PublicKey (..), getPublicKey, putPublicKey
  , Signature (..), getSignature, putSignature
  ) where

import           Control.Monad            (void, when)
import           Crypto.Error
import qualified Crypto.Error             as DH
import qualified Crypto.Hash              as Hash
import qualified Crypto.Hash.Algorithms   as Hash
import qualified Crypto.PubKey.Curve25519 as DH
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA.PKCS15
import qualified Data.Binary              as B
import qualified Data.Binary.Get          as B
import qualified Data.Binary.Put          as B
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Builder  as BS
import qualified Data.ByteString.Lazy     as LBS
import           Data.Foldable
import           Data.Int
import qualified Data.List                as L
import           Data.Monoid
import           Data.Word

import           Network.SSH.Message.Util

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
    putByte  60 <> putPublicKey pk
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
      Nothing  -> [ putString "publickey", putBool False, putString algo, putPublicKey pk ]
      Just sig -> [ putString "publickey", putBool True,  putString algo, putPublicKey pk, putSignature sig ]

getPublicKey :: B.Get PublicKey
getPublicKey = getFramed $ \keysize-> getString >>= \case
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

putPublicKey :: PublicKey -> B.Put
putPublicKey = \case
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

getSignature:: B.Get Signature
getSignature = getFramed $ \sigsize-> getString >>= \case
  "ssh-ed25519" ->
    Ed25519.signature <$> getString >>= \case
      CryptoPassed s -> pure (SignatureEd25519 s)
      CryptoFailed e -> fail (show e)
  "ssh-rsa" ->
    SignatureRSA <$> getString
  other ->
    SignatureOther other <$> getString

putSignature :: Signature -> B.Put
putSignature = putFramed . \case
  SignatureEd25519    sig -> putString "ssh-ed25519" <> putString (BS.pack $ BA.unpack sig)
  SignatureRSA        sig -> putString "ssh-rsa"     <> putString sig
  SignatureOther algo sig -> putString algo          <> putString sig

-------------------------------------------------------------------------------
-- Binary instances
-------------------------------------------------------------------------------

instance B.Binary DisconnectReason where
  put (DisconnectReason x) = B.putWord32be x
  get = DisconnectReason <$> B.getWord32be

instance B.Binary ChannelOpenFailureReason where
  put (ChannelOpenFailureReason c d l) = B.putWord32be c <> putString' d <> putString' l
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
  put (ChannelType s) = putString' s
  get = ChannelType <$> getString

instance B.Binary ServiceName where
  put (ServiceName s) = putString' s
  get = ServiceName <$> getString

instance B.Binary UserName where
  put (UserName s) = putString' s
  get = UserName <$> getString

instance B.Binary PublicKey where
  put = undefined
  get = getPublicKey

instance B.Binary Signature where
  put = undefined
  get = getSignature

putString'  :: BS.ByteString -> B.Put
putString' x = B.putWord32be (fromIntegral $ BS.length x) <> B.putByteString x

putFramed' :: B.Put -> B.Put
putFramed' x = let lbs = B.runPut x in B.putWord32be (fromIntegral $ LBS.length lbs) <> B.put lbs
