{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Message
  ( -- * Message
    Message (..)
    -- ** Disconnect (1)
  , Disconnect (..)
    -- ** Ignore (2)
  , Ignore (..)
    -- ** Unimplemented (3)
  , Unimplemented (..)
    -- ** Debug (4)
  , Debug (..)
    -- ** ServiceRequest (5)
  , ServiceRequest (..)
    -- ** ServiceAccept (6)
  , ServiceAccept (..)
    -- ** KexInit (20)
  , KexInit (..)
    -- ** NewKeys (21)
  , NewKeys (..)
    -- ** KexEcdhInit (30)
  , KexEcdhInit (..)
    -- ** KexEcdhReply (31)
  , KexEcdhReply (..)
    -- ** UserAuthRequest (50)
  , UserAuthRequest (..)
    -- ** UserAuthFailure (51)
  , UserAuthFailure (..)
    -- ** UserAuthSuccess (52)
  , UserAuthSuccess (..)
    -- ** UserAuthBanner (53)
  , UserAuthBanner (..)
    -- ** UserAuthPublicKeyOk (60)
  , UserAuthPublicKeyOk (..)
    -- ** ChannelOpen (90)
  , ChannelOpen (..)
    -- ** ChannelOpenConfirmation (91)
  , ChannelOpenConfirmation (..)
    -- ** ChannelOpenFailure (92)
  , ChannelOpenFailure (..)
    -- ** ChannelData (94)
  , ChannelData (..)
    -- ** ChannelDataExtended (95)
  , ChannelDataExtended (..)
    -- ** ChannelEof (96)
  , ChannelEof (..)
    -- ** ChannelClose (97)
  , ChannelClose (..)
    -- ** ChannelRequest (98)
  , ChannelRequest (..)
    -- ** ChannelRequestSuccess (99)
  , ChannelRequestSuccess (..)
    -- ** ChannelRequestFailure (100)
  , ChannelRequestFailure (..)

    -- * Misc
  , Algorithm (..)
  , AuthMethod (..)
  , AuthMethodName (..)
  , ChannelId (..)
  , ChannelOpenFailureReason (..)
  , ChannelType (..)
  , Cookie (), newCookie, nilCookie
  , InitWindowSize (..)
  , MaxPacketSize (..)
  , Password (..)
  , PublicKey (..)
  , ServiceName (..)
  , SessionId (..)
  , Signature (..)
  , UserName (..)
  , Version (..)
  ) where

import           Control.Monad            (unless, void, when)
import           Crypto.Error
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import           Crypto.Random
import qualified Data.Binary              as B
import qualified Data.Binary.Get          as B
import qualified Data.Binary.Put          as B
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as LBS
import           Data.Foldable
import qualified Data.List                as L
import           Data.Monoid              ((<>))
import           Data.Word

data Message
  = MsgDisconnect              Disconnect
  | MsgIgnore                  Ignore
  | MsgUnimplemented           Unimplemented
  | MsgDebug                   Debug
  | MsgServiceRequest          ServiceRequest
  | MsgServiceAccept           ServiceAccept
  | MsgKexInit                 KexInit
  | MsgNewKeys                 NewKeys
  | MsgKexEcdhInit             KexEcdhInit
  | MsgKexEcdhReply            KexEcdhReply
  | MsgUserAuthRequest         UserAuthRequest
  | MsgUserAuthFailure         UserAuthFailure
  | MsgUserAuthSuccess         UserAuthSuccess
  | MsgUserAuthBanner          UserAuthBanner
  | MsgUserAuthPublicKeyOk     UserAuthPublicKeyOk
  | MsgChannelOpen             ChannelOpen
  | MsgChannelOpenConfirmation ChannelOpenConfirmation
  | MsgChannelOpenFailure      ChannelOpenFailure
  | MsgChannelData             ChannelData
  | MsgChannelDataExtended     ChannelDataExtended
  | MsgChannelEof              ChannelEof
  | MsgChannelClose            ChannelClose
  | MsgChannelRequest          ChannelRequest
  | MsgChannelRequestSuccess   ChannelRequestSuccess
  | MsgChannelRequestFailure   ChannelRequestFailure
  deriving (Eq, Show)

data Disconnect
  = Disconnect
  { disconnectReasonCode  :: Word32
  , disconnectDescription :: BS.ByteString
  , disconnectLanguagtTag :: BS.ByteString
  }
  deriving (Eq, Show)

data Ignore
  = Ignore
  deriving (Eq, Show)

data Unimplemented
  = Unimplemented
  deriving (Eq, Show)

data Debug
  = Debug
  { debugAlwaysDisplay :: Bool
  , debugMessage       :: BS.ByteString
  , debugLanguageTag   :: BS.ByteString
  }
  deriving (Eq, Show)

data ServiceRequest
  = ServiceRequest ServiceName
  deriving (Eq, Show)

data ServiceAccept
  = ServiceAccept ServiceName
  deriving (Eq, Show)

data KexInit
  = KexInit
  { kexCookie                              :: Cookie
  , kexAlgorithms                          :: [BS.ByteString]
  , kexServerHostKeyAlgorithms             :: [BS.ByteString]
  , kexEncryptionAlgorithmsClientToServer  :: [BS.ByteString]
  , kexEncryptionAlgorithmsServerToClient  :: [BS.ByteString]
  , kexMacAlgorithmsClientToServer         :: [BS.ByteString]
  , kexMacAlgorithmsServerToClient         :: [BS.ByteString]
  , kexCompressionAlgorithmsClientToServer :: [BS.ByteString]
  , kexCompressionAlgorithmsServerToClient :: [BS.ByteString]
  , kexLanguagesClientToServer             :: [BS.ByteString]
  , kexLanguagesServerToClient             :: [BS.ByteString]
  , kexFirstPacketFollows                  :: Bool
  } deriving (Eq, Show)

data NewKeys
  = NewKeys
  deriving (Eq, Show)

data KexEcdhInit
  = KexEcdhInit
  { kexClientEphemeralKey :: Curve25519.PublicKey
  }
  deriving (Eq, Show)

data KexEcdhReply
  = KexEcdhReply
  { kexServerHostKey      :: PublicKey
  , kexServerEphemeralKey :: Curve25519.PublicKey
  , kexHashSignature      :: Signature
  }
  deriving (Eq, Show)

data UserAuthRequest
  = UserAuthRequest UserName ServiceName AuthMethod
  deriving (Eq, Show)

data UserAuthFailure
  = UserAuthFailure [AuthMethodName] Bool
  deriving (Eq, Show)

data UserAuthSuccess
  = UserAuthSuccess
  deriving (Eq, Show)

data UserAuthBanner
  = UserAuthBanner BS.ByteString BS.ByteString
  deriving (Eq, Show)

data UserAuthPublicKeyOk
  = UserAuthPublicKeyOk Algorithm PublicKey
  deriving (Eq, Show)

data ChannelOpen
  = ChannelOpen ChannelType ChannelId InitWindowSize MaxPacketSize
  deriving (Eq, Show)

data ChannelOpenConfirmation
  = ChannelOpenConfirmation ChannelId ChannelId InitWindowSize MaxPacketSize
  deriving (Eq, Show)

data ChannelOpenFailure
  = ChannelOpenFailure ChannelId ChannelOpenFailureReason
  deriving (Eq, Show)

data ChannelData
  = ChannelData ChannelId BS.ByteString
  deriving (Eq, Show)

data ChannelDataExtended
  = ChannelDataExtended ChannelId Word32 BS.ByteString
  deriving (Eq, Show)

data ChannelEof
  = ChannelEof ChannelId
  deriving (Eq, Show)

data ChannelClose
  = ChannelClose ChannelId
  deriving (Eq, Show)

data ChannelRequest
  = ChannelRequestPty
    { crChannelId     :: ChannelId
    , crWantReply     :: Bool
    , crTerminal      :: BS.ByteString
    , crWidthCols     :: Word32
    , crHeightRows    :: Word32
    , crWidthPixels   :: Word32
    , crHeightPixels  :: Word32
    , crTerminalModes :: BS.ByteString
    }
  | ChannelRequestShell
    { crChannelId :: ChannelId
    , crWantReply :: Bool
    }
  | ChannelRequestOther
    { crChannelId :: ChannelId
    , crOther     :: BS.ByteString
    }
  deriving (Eq, Show)

data ChannelRequestSuccess
  = ChannelRequestSuccess ChannelId
  deriving (Eq, Show)

data ChannelRequestFailure
  = ChannelRequestFailure ChannelId
  deriving (Eq, Show)

data ChannelOpenFailureReason
  = ChannelOpenFailureReason
  { reasonCode        :: Word32
  , reasonDescription :: BS.ByteString
  , reasonLanguageTag :: BS.ByteString
  }
  deriving (Eq, Show)

data AuthMethod
  = AuthNone
  | AuthHostBased
  | AuthPassword  Password
  | AuthPublicKey Algorithm PublicKey (Maybe Signature)
  deriving (Eq, Show)

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

newtype Cookie           = Cookie           BS.ByteString deriving (Eq, Ord, Show)

newCookie :: MonadRandom m => m Cookie
newCookie  = Cookie <$> getRandomBytes 16

nilCookie :: Cookie
nilCookie  = Cookie  $  BS.replicate 16 0

newtype Version          = Version          BS.ByteString deriving (Eq, Ord, Show)
newtype Algorithm        = Algorithm        BS.ByteString deriving (Eq, Ord, Show)
newtype Password         = Password         BS.ByteString deriving (Eq, Ord, Show)
newtype SessionId        = SessionId        BS.ByteString deriving (Eq, Ord, Show)
newtype UserName         = UserName         BS.ByteString deriving (Eq, Ord, Show)
newtype AuthMethodName   = AuthMethodName   BS.ByteString deriving (Eq, Ord, Show)
newtype ServiceName      = ServiceName      BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelType      = ChannelType      BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelId        = ChannelId        Word32        deriving (Eq, Ord, Show)
newtype InitWindowSize   = InitWindowSize   Word32        deriving (Eq, Ord, Show)
newtype MaxPacketSize    = MaxPacketSize    Word32        deriving (Eq, Ord, Show)

-------------------------------------------------------------------------------
-- Binary instances
-------------------------------------------------------------------------------

instance B.Binary Message where
  put = \case
    MsgDisconnect               x -> B.put x
    MsgIgnore                   x -> B.put x
    MsgUnimplemented            x -> B.put x
    MsgDebug                    x -> B.put x
    MsgServiceRequest           x -> B.put x
    MsgServiceAccept            x -> B.put x
    MsgKexInit                  x -> B.put x
    MsgNewKeys                  x -> B.put x
    MsgKexEcdhInit              x -> B.put x
    MsgKexEcdhReply             x -> B.put x
    MsgUserAuthRequest          x -> B.put x
    MsgUserAuthFailure          x -> B.put x
    MsgUserAuthSuccess          x -> B.put x
    MsgUserAuthBanner           x -> B.put x
    MsgUserAuthPublicKeyOk      x -> B.put x
    MsgChannelOpen              x -> B.put x
    MsgChannelOpenConfirmation  x -> B.put x
    MsgChannelOpenFailure       x -> B.put x
    MsgChannelData              x -> B.put x
    MsgChannelDataExtended      x -> B.put x
    MsgChannelEof               x -> B.put x
    MsgChannelClose             x -> B.put x
    MsgChannelRequest           x -> B.put x
    MsgChannelRequestSuccess    x -> B.put x
    MsgChannelRequestFailure    x -> B.put x

  get = B.lookAhead getByte >>= \case
    1   -> MsgDisconnect              <$> B.get
    2   -> MsgIgnore                  <$> B.get
    3   -> MsgUnimplemented           <$> B.get
    4   -> MsgDebug                   <$> B.get
    5   -> MsgServiceRequest          <$> B.get
    6   -> MsgServiceAccept           <$> B.get
    20  -> MsgKexInit                 <$> B.get
    21  -> MsgNewKeys                 <$> B.get
    30  -> MsgKexEcdhInit             <$> B.get
    31  -> MsgKexEcdhReply            <$> B.get
    50  -> MsgUserAuthRequest         <$> B.get
    51  -> MsgUserAuthFailure         <$> B.get
    52  -> MsgUserAuthSuccess         <$> B.get
    53  -> MsgUserAuthBanner          <$> B.get
    60  -> MsgUserAuthPublicKeyOk     <$> B.get
    90  -> MsgChannelOpen             <$> B.get
    91  -> MsgChannelOpenConfirmation <$> B.get
    92  -> MsgChannelOpenFailure      <$> B.get
    94  -> MsgChannelData             <$> B.get
    95  -> MsgChannelDataExtended     <$> B.get
    96  -> MsgChannelEof              <$> B.get
    97  -> MsgChannelClose            <$> B.get
    98  -> MsgChannelRequest          <$> B.get
    99  -> MsgChannelRequestSuccess   <$> B.get
    100 -> MsgChannelRequestFailure   <$> B.get
    x   -> fail ("UNKNOWN MESSAGE TYPE " ++ show x)

instance B.Binary Disconnect where
  put (Disconnect c d l) = mconcat
    [ putByte   1
    , putUint32 c
    , putString d
    , putString l
    ]
  get = do
    getMsgType 1
    Disconnect
      <$> getUint32
      <*> getString
      <*> getString

instance B.Binary Ignore where
  put Ignore = B.putWord8 2
  get = do
    getMsgType 2
    pure Ignore

instance B.Binary Unimplemented where
  put Unimplemented = B.putWord8 3
  get = do
    getMsgType 3
    pure Unimplemented

instance B.Binary Debug where
  put (Debug ad msg lang) = mconcat
    [ putByte 4, putBool ad, putString msg, putString lang ]
  get = do
    getMsgType 4
    Debug <$> getBool <*> getString <*> getString

instance B.Binary ServiceRequest where
  put (ServiceRequest s) =
    putByte 5 <> B.put s
  get = do
    getMsgType 5
    ServiceRequest <$> B.get

instance B.Binary ServiceAccept where
  put (ServiceAccept s) =
    putByte 6 <> B.put s
  get = do
    getMsgType 6
    ServiceAccept <$> B.get

instance B.Binary KexInit where
  put kex = mconcat
    [ putByte     20
    , B.put       (kexCookie                              kex)
    , putNameList (kexAlgorithms                          kex)
    , putNameList (kexServerHostKeyAlgorithms             kex)
    , putNameList (kexEncryptionAlgorithmsClientToServer  kex)
    , putNameList (kexEncryptionAlgorithmsServerToClient  kex)
    , putNameList (kexMacAlgorithmsClientToServer         kex)
    , putNameList (kexMacAlgorithmsServerToClient         kex)
    , putNameList (kexCompressionAlgorithmsClientToServer kex)
    , putNameList (kexCompressionAlgorithmsServerToClient kex)
    , putNameList (kexLanguagesClientToServer             kex)
    , putNameList (kexLanguagesServerToClient             kex)
    , putBool     (kexFirstPacketFollows                  kex)
    , putUint32   0 -- reserved for future extensions
    ]
  get = do
    getMsgType 20
    kex <- KexInit
      <$> B.get
      <*> getNameList <*> getNameList <*> getNameList <*> getNameList
      <*> getNameList <*> getNameList <*> getNameList <*> getNameList
      <*> getNameList <*> getNameList <*> getBool
    void getUint32 -- reserved for future extensions
    pure kex

instance B.Binary NewKeys where
  put NewKeys = B.putWord8 21
  get = do
    getMsgType 21
    pure NewKeys

instance B.Binary KexEcdhInit where
  put (KexEcdhInit ephemeralKey) = mconcat
    [ putByte 30
    , putCurve25519PK ephemeralKey
    ]
  get = do
    getMsgType 30
    KexEcdhInit
      <$> getCurve25519PK

instance B.Binary KexEcdhReply where
  put (KexEcdhReply hostKey ephemeralKey signature) = mconcat
    [ B.putWord8 31
    , B.put hostKey
    , putCurve25519PK ephemeralKey
    , B.put signature
    ]
  get = do
    getMsgType 31
    KexEcdhReply
      <$> B.get
      <*> getCurve25519PK
      <*> B.get

instance B.Binary UserAuthRequest where
  put (UserAuthRequest un sn am) = mconcat
    [ putByte  50, B.put un, B.put sn, B.put am ]
  get = do
    getMsgType 50
    UserAuthRequest <$> B.get <*> B.get <*> B.get

instance B.Binary UserAuthFailure where
  put (UserAuthFailure ms ps) = mconcat
    [ putByte 51, putNameList ((\(AuthMethodName x)->x) <$> ms), putBool ps ]
  get =  do
    getMsgType 51
    UserAuthFailure <$> (fmap AuthMethodName <$> getNameList) <*> getBool

instance B.Binary UserAuthSuccess where
  put UserAuthSuccess =
    putByte 52
  get = do
    getMsgType 52
    pure UserAuthSuccess

instance B.Binary UserAuthBanner where
  put (UserAuthBanner x y) = mconcat
    [ putByte 53, putString x, putString y ]
  get = do
    getMsgType 53
    UserAuthBanner <$> getString <*> getString

instance B.Binary UserAuthPublicKeyOk where
  put (UserAuthPublicKeyOk alg pk) =
    putByte  60 <> B.put alg <> B.put pk
  get = getMsgType 60 >> UserAuthPublicKeyOk <$> B.get <*> B.get

instance B.Binary ChannelOpen where
  put (ChannelOpen ct rid ws ps) =
    putByte 90 <> B.put ct <> B.put rid <> B.put ws <> B.put ps
  get = getMsgType 90 >> ChannelOpen <$> B.get <*> B.get <*> B.get  <*> B.get

instance B.Binary ChannelOpenConfirmation where
  put (ChannelOpenConfirmation (ChannelId a) (ChannelId b) (InitWindowSize c) (MaxPacketSize d)) =
    putByte 91 <> putUint32 a <> putUint32 b <> putUint32 c <> putUint32 d
  get = getMsgType 91 >> ChannelOpenConfirmation <$> B.get <*> B.get <*> B.get  <*> B.get

instance B.Binary ChannelOpenFailure where
  put (ChannelOpenFailure (ChannelId rid) (ChannelOpenFailureReason reason descr lang)) =
    putByte  92 <> putUint32 rid <> putUint32 reason <> putString descr <> putString lang
  get = getMsgType 92 >> ChannelOpenFailure  <$> B.get <*> B.get

instance B.Binary ChannelData where
  put (ChannelData (ChannelId lid) bs) =
    putByte  94 <> putUint32 lid <> putString bs
  get = getMsgType 94 >> ChannelData <$> B.get <*> getString

instance B.Binary ChannelDataExtended where
  put (ChannelDataExtended (ChannelId lid) x bs) =
    putByte  95 <> putUint32 lid <> putUint32 x <> putString bs
  get = getMsgType 95 >> ChannelDataExtended <$> B.get <*> getUint32 <*> getString

instance B.Binary ChannelEof where
  put (ChannelEof (ChannelId lid)) =
    putByte  96 <> putUint32 lid
  get = getMsgType 96 >> ChannelEof <$> B.get

instance B.Binary ChannelClose where
  put (ChannelClose (ChannelId lid)) =
    putByte  97 <> putUint32 lid
  get = getMsgType 97 >> ChannelClose <$> B.get

instance B.Binary ChannelRequest where
  put = \case
    ChannelRequestPty cid a b c d e f g -> mconcat
      [ putByte 98, B.put cid, putString "pty-req", putBool a, putString b, putUint32 c, putUint32 d, putUint32 e, putUint32 f, putString g]
    ChannelRequestShell cid wantReply -> mconcat
      [ putByte 98, B.put cid, putString "shell", putBool wantReply ]
    ChannelRequestOther cid other -> mconcat
      [ putByte 98, B.put cid, putString other ]
  get = getMsgType 98 >> B.get >>= \cid-> getString >>= \case
    "pty-req" -> ChannelRequestPty cid
      <$> getBool
      <*> getString
      <*> getUint32
      <*> getUint32
      <*> getUint32
      <*> getUint32
      <*> getString
    "shell" -> ChannelRequestShell cid <$> getBool
    other   -> ChannelRequestOther cid <$> pure other

instance B.Binary ChannelRequestSuccess where
  put (ChannelRequestSuccess (ChannelId lid)) =
    putByte 99 <> putUint32 lid
  get = getMsgType 99 >> ChannelRequestSuccess <$> B.get

instance B.Binary ChannelRequestFailure where
  put (ChannelRequestFailure (ChannelId lid)) =
    putByte 100 <> putUint32 lid
  get = getMsgType 100 >> ChannelRequestFailure   <$> B.get

instance B.Binary Cookie where
  put (Cookie s) = B.putByteString s
  get = Cookie <$> B.getByteString 16

instance B.Binary Algorithm where
  put (Algorithm s) = putString s
  get = Algorithm <$> getString

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

instance B.Binary Version where
  put (Version x) = B.putByteString x <> B.putWord16be 0x0d0a
  get = do
    magic <- B.getWord64be
    if magic /= 0x5353482d322e302d -- "SSH-2.0-"
      then stop
      else untilCRLF 0 [0x2d, 0x30, 0x2e, 0x32, 0x2d, 0x48, 0x53, 0x53]
    where
      stop = fail ""
      untilCRLF !i !xs
        = if i >= (255 :: Int)
          then stop
          else B.getWord8 >>= \case
            0x0d -> B.getWord8 >>= \case
              0x0a -> pure $ Version $ BS.pack (reverse xs)
              _    -> stop
            x -> untilCRLF (i+1) (x:xs)

instance B.Binary AuthMethod where
  put = \case
    AuthNone -> mconcat
      [ putString "none" ]
    AuthHostBased -> mconcat
      [ putString "hostbased" ]
    AuthPassword (Password pw) -> mconcat
      [ putString "password", putBool False, putString pw ]
    AuthPublicKey (Algorithm algo) pk msig -> mconcat $ case msig of
      Nothing  -> [ putString "publickey", putBool False, putString algo, B.put pk ]
      Just sig -> [ putString "publickey", putBool True,  putString algo, B.put pk, B.put sig ]

  get = getString >>= \case
    "none"      -> pure AuthNone
    "hostbased" -> pure AuthHostBased
    "password"  -> void getBool >> AuthPassword  <$> (Password <$> getString)
    "publickey" -> do
      signed <- getBool
      algo   <- Algorithm <$> getString
      key    <- B.get
      msig   <- if signed then Just <$> B.get else pure Nothing
      pure (AuthPublicKey algo key msig)
    other       -> fail $ "Unknown AuthMethod " ++ show other

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

  get = getFramed $ const $ getString >>= \case
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

  get = getFramed $ const $ getString >>= \case
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
    g ys = sum (BS.length <$> ys) + length ys - 1

getSize    :: B.Get Int
getSize     = fromIntegral <$> getUint32

--putSize    :: Int -> B.Put
--putSize     = putUint32 . fromIntegral

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

getCurve25519PK :: B.Get Curve25519.PublicKey
getCurve25519PK = getString >>= \s-> case Curve25519.publicKey s of
  CryptoPassed pk -> pure pk
  CryptoFailed e  -> fail (show e)

putCurve25519PK :: Curve25519.PublicKey -> B.Put
putCurve25519PK = putString . BS.pack . BA.unpack

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
    g yys@(y:_) | y > 128   = 0:yys
                | otherwise = yys

putFramed :: B.Put -> B.Put
putFramed b = B.putWord32be (fromIntegral $ LBS.length lbs) <> B.putLazyByteString lbs
  where
    lbs = B.runPut b

getFramed :: (Int -> B.Get a) -> B.Get a
getFramed f = do
  i <- getSize
  B.isolate i (f i)

getMsgType :: Word8 -> B.Get ()
getMsgType expected = do
  actual <- B.getWord8
  unless (actual == expected) $ fail $
    "Expected " ++ msgTypeName expected ++
    ", got "    ++ msgTypeName actual   ++ "."

msgTypeName :: Word8 -> String
msgTypeName   1 = "SSH_MSG_DISCONNECT"
msgTypeName  21 = "SSH_MSG_NEWKEYS"
msgTypeName   x = "SSH_MSG_" ++ show x
