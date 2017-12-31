{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Message
  ( Message (..)
  , Algorithm (..)
  , AuthMethod (..)
  , AuthMethodName (..)
  , ChannelId (..)
  , ChannelOpenFailureReason (..)
  , ChannelRequest (..)
  , ChannelType (..)
  , Cookie (), newCookie
  , DisconnectReason (..)
  , InitWindowSize (..)
  , KexInit (..)
  , KexEcdhInit (..)
  , KexEcdhReply (..)
  , MaxPacketSize (..)
  , NewKeys (..)
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
  = Disconnect              DisconnectReason BS.ByteString BS.ByteString
  | Ignore
  | Unimplemented
  | ServiceRequest          ServiceName
  | ServiceAccept           ServiceName
  | UserAuthRequest         UserName ServiceName AuthMethod
  | UserAuthFailure         [AuthMethodName] Bool
  | UserAuthSuccess
  | UserAuthBanner          BS.ByteString BS.ByteString
  | UserAuthPublicKeyOk     Algorithm PublicKey
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

newtype Cookie           = Cookie           BS.ByteString deriving (Eq, Ord, Show)

newCookie :: MonadRandom m => m Cookie
newCookie = Cookie <$> getRandomBytes 16

newtype Version          = Version          BS.ByteString deriving (Eq, Ord, Show)
newtype Algorithm        = Algorithm        BS.ByteString deriving (Eq, Ord, Show)
newtype Password         = Password         BS.ByteString deriving (Eq, Ord, Show)
newtype DisconnectReason = DisconnectReason Word32        deriving (Eq, Ord, Show)
newtype SessionId        = SessionId        BS.ByteString deriving (Eq, Ord, Show)
newtype UserName         = UserName         BS.ByteString deriving (Eq, Ord, Show)
newtype AuthMethodName   = AuthMethodName   BS.ByteString deriving (Eq, Ord, Show)
newtype ServiceName      = ServiceName      BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelType      = ChannelType      BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelId        = ChannelId        Word32        deriving (Eq, Ord, Show)
newtype InitWindowSize   = InitWindowSize   Word32        deriving (Eq, Ord, Show)
newtype MaxPacketSize    = MaxPacketSize    Word32        deriving (Eq, Ord, Show)

data NewKeys = NewKeys deriving (Eq, Ord, Show)

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
  } deriving (Eq, Ord, Show)

data KexEcdhInit
  = KexEcdhInit
  { kexClientEphemeralKey :: Curve25519.PublicKey
  } deriving (Eq, Show)

data KexEcdhReply
  = KexEcdhReply
  { kexServerHostKey      :: Ed25519.PublicKey
  , kexServerEphemeralKey :: Curve25519.PublicKey
  , kexHashSignature      :: Ed25519.Signature
  } deriving (Eq, Show)

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
    }
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

-------------------------------------------------------------------------------
-- Binary instances
-------------------------------------------------------------------------------

instance B.Binary Message where
  put = \case
    Disconnect r d l ->
      putByte   1 <> B.put r <> B.put d <> B.put l
    Ignore ->
      putByte   2
    Unimplemented ->
      putByte   3
    ServiceRequest sn ->
      putByte   5 <> B.put sn
    ServiceAccept sn ->
      putByte   6 <> B.put sn
    UserAuthRequest un sn am ->
      putByte  50 <> B.put un <> B.put sn <> B.put am
    UserAuthFailure ms ps ->
      putByte  51 <> putNameList ((\(AuthMethodName x)->x) <$> ms) <> putBool ps
    UserAuthSuccess ->
      putByte  52
    UserAuthBanner b l ->
      putByte  53 <> putString b <> putString l
    UserAuthPublicKeyOk alg pk ->
      putByte  60 <> B.put alg <> B.put pk
    ChannelOpen ct rid ws ps ->
      putByte  90 <> B.put ct <> B.put rid <> B.put ws <> B.put ps
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
      putByte  98 <> putUint32 lid <> B.put req
    ChannelRequestSuccess (ChannelId lid) ->
      putByte  99 <> putUint32 lid
    ChannelRequestFailure (ChannelId lid) ->
      putByte 100 <> putUint32 lid

  get = getByte >>= \case
    1   -> Disconnect              <$> B.get <*> getString <*> getString
    2   -> pure Ignore
    3   -> pure Unimplemented
    5   -> ServiceRequest          <$> B.get
    6   -> ServiceAccept           <$> B.get
    50  -> UserAuthRequest         <$> B.get <*> B.get <*> B.get
    51  -> UserAuthFailure         <$> (fmap AuthMethodName <$> getNameList) <*> getBool
    52  -> pure UserAuthSuccess
    53  -> UserAuthBanner          <$> getString    <*> getString
    60  -> UserAuthPublicKeyOk     <$> B.get <*> B.get
    90  -> ChannelOpen             <$> B.get <*> B.get <*> B.get  <*> B.get
    91  -> ChannelOpenConfirmation <$> B.get <*> B.get <*> B.get  <*> B.get
    92  -> ChannelOpenFailure      <$> B.get <*> B.get
    94  -> ChannelData             <$> B.get <*> getString
    95  -> ChannelDataExtended     <$> B.get <*> getUint32 <*> getString
    96  -> ChannelEof              <$> B.get
    97  -> ChannelClose            <$> B.get
    98  -> ChannelRequest          <$> B.get <*> B.get
    99  -> ChannelRequestSuccess   <$> B.get
    100 -> ChannelRequestFailure   <$> B.get
    x   -> fail ("UNKNOWN MESSAGE TYPE " ++ show x)

instance B.Binary NewKeys where
  put NewKeys = B.putWord8 21
  get = do
    getMsgType 21
    pure NewKeys

instance B.Binary Cookie where
  put (Cookie s) = B.putByteString s
  get = Cookie <$> B.getByteString 16

instance B.Binary Algorithm where
  put (Algorithm s) = putString s
  get = Algorithm <$> getString

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
        = if i >= 255
          then stop
          else B.getWord8 >>= \case
            0x0d -> B.getWord8 >>= \case
              0x0a -> pure $ Version $ BS.pack (reverse xs)
              _    -> stop
            x -> untilCRLF (i+1) (x:xs)

instance B.Binary ChannelRequest where
  put = \case
    ChannelRequestPTY a b c d e f g -> mconcat
      [ putString "pty-req", putBool a, putString b, putUint32 c, putUint32 d, putUint32 e, putUint32 f, putString g]
    ChannelRequestShell wantReply -> mconcat
      [ putString "shell", putBool wantReply ]
    ChannelRequestOther other -> mconcat
      [ putString other ]

  get = getString >>= \case
    "pty-req" -> ChannelRequestPTY
      <$> getBool
      <*> getString
      <*> getUint32
      <*> getUint32
      <*> getUint32
      <*> getUint32
      <*> getString
    "shell" -> ChannelRequestShell <$> getBool
    other -> pure (ChannelRequestOther other)

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

instance B.Binary KexInit where
  put kex = mconcat
    [ B.put       (kexCookie                              kex)
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
    kex <- KexInit
      <$> B.get
      <*> getNameList <*> getNameList <*> getNameList <*> getNameList
      <*> getNameList <*> getNameList <*> getNameList <*> getNameList
      <*> getNameList <*> getNameList <*> getBool
    void getUint32 -- reserved for future extensions
    pure kex

instance B.Binary KexEcdhInit where
  put = undefined
  get = do
    msg <- B.getWord8
    when (msg /= 30) (fail "expected SSH_MSG_KEX_ECDH_INIT")
    keySize <- B.getWord32be
    when (keySize /= 32) (fail "expected key size to be 32 bytes")
    bs <- B.getByteString 32
    case Curve25519.publicKey bs of
      CryptoPassed a -> pure (KexEcdhInit a)
      CryptoFailed e -> fail (show e)

instance B.Binary KexEcdhReply where
  put x = mconcat
    [ B.putWord8        31 -- message type
    , B.putWord32be     51 -- host key len
    , B.putWord32be     11 -- host key algorithm name len
    , B.putByteString   "ssh-ed25519"
    , B.putWord32be     32 -- host key data len
    , B.putByteString $ BS.pack $ BA.unpack (kexServerHostKey x)
    , B.putWord32be     32 -- ephemeral key len
    , B.putByteString $ BS.pack $ BA.unpack (kexServerEphemeralKey x)
    , B.putWord32be   $ 4 + 11 + 4 + fromIntegral signatureLen
    , B.putWord32be     11 -- algorithm name len
    , B.putByteString   "ssh-ed25519"
    , B.putWord32be   $ fromIntegral signatureLen
    , B.putByteString   signature
    ]
    where
      signature    = BS.pack $ BA.unpack (kexHashSignature x)
      signatureLen = BS.length signature
  get = undefined

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
msgTypeName 21 = "SSH_MSG_NEWKEYS"
msgTypeName  x = "SSH_MSG_" ++ show x
