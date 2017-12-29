{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Message
  ( Message (..), messageParser, messageBuilder
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
  , MethodName (..)
  , AuthenticationData (..)
  , PublicKey (..), publicKeyParser, publicKeyBuilder
  , Signature (..), signatureParser, signatureBuilder
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
import qualified Data.Binary.Get          as B
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Builder  as BS
import qualified Data.ByteString.Lazy     as LBS
import           Data.Foldable
import           Data.Int
import qualified Data.List                as L
import           Data.Monoid
import           Data.Word

data Message
  = Disconnect              DisconnectReason BS.ByteString BS.ByteString
  | Ignore
  | Unimplemented
  | ServiceRequest          ServiceName
  | ServiceAccept           ServiceName
  | UserAuthRequest         UserName ServiceName AuthenticationData
  | UserAuthFailure         [MethodName] Bool
  | UserAuthSuccess
  | UserAuthBanner          BS.ByteString BS.ByteString
  | UserAuthPublicKeyOk     PublicKey
  | ChannelOpen             ChannelType ChannelId InitWindowSize MaxPacketSize
  | ChannelOpenConfirmation ChannelId ChannelId InitWindowSize MaxPacketSize
  | ChannelOpenFailure      ChannelId ChannelOpenFailureReason BS.ByteString BS.ByteString
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

data AuthenticationData
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

newtype DisconnectReason = DisconnectReason Word32 deriving (Eq, Ord, Show)
newtype SessionId        = SessionId        BS.ByteString deriving (Eq, Ord, Show)
newtype UserName         = UserName         BS.ByteString deriving (Eq, Ord, Show)
newtype MethodName       = MethodName       { methodName :: BS.ByteString } deriving (Eq, Ord, Show)
newtype ServiceName      = ServiceName      BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelType      = ChannelType      BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelId        = ChannelId        Word32 deriving (Eq, Ord, Show)
newtype InitWindowSize   = InitWindowSize   Word32 deriving (Eq, Ord, Show)
newtype MaxPacketSize    = MaxPacketSize    Word32 deriving (Eq, Ord, Show)
newtype ChannelOpenFailureReason = ChannelOpenFailureReason Word32 deriving (Eq, Ord, Show)

nameListBuilder :: [BS.ByteString] -> BS.Builder
nameListBuilder xs =
  BS.word32BE (fromIntegral $ g xs)
  <> mconcat (BS.byteString <$> L.intersperse "," xs)
  where
    g [] = 0
    g xs = sum (BS.length <$> xs) + length xs - 1

nameListParser :: B.Get [BS.ByteString]
nameListParser = do
  len <- fromIntegral <$> B.getWord32be
  BS.split 0x2c <$> B.getByteString len

curve25519BlobBuilder :: Curve25519.PublicKey -> BS.Builder
curve25519BlobBuilder key =
  BS.word32BE 32 <> BS.byteString (BS.pack $ BA.unpack key)

curve25519DhSecretBuilder  :: Curve25519.DhSecret -> BS.Builder
curve25519DhSecretBuilder sec =
  bignum2bytes (BA.unpack sec)
  where
    -- FIXME: not constant time
    bignum2bytes xs = zs
      where
        prepend [] = []
        prepend (a:as)
          | a >= 128  = 0:a:as
          | otherwise = a:as
        ys = BS.pack $ prepend $ dropWhile (==0) xs
        zs = BS.word32BE (fromIntegral $ BS.length ys) <> BS.byteString ys

mpintLenBuilder :: Integer -> (Int, BS.Builder) -> (Int, BS.Builder)
mpingLenBuilder 0 x = x
mpintLenBuilder i (!len, !bld) = mpintLenBuilder q (len + 4, BS.word32BE (fromIntegral r) <> bld)
  where
    (q,r) = i `quotRem` 0x0100000000

messageParser :: B.Get Message
messageParser = B.getWord8 >>= \case
  1    -> Disconnect
      <$> (DisconnectReason <$> uint32)
      <*> string
      <*> string
  2   -> pure Ignore
  3   -> pure Unimplemented
  5   -> ServiceRequest        <$> serviceParser
  6   -> ServiceAccept         <$> serviceParser
  50  -> UserAuthRequest       <$> (UserName <$> string) <*> serviceParser <*> authMethodParser
  51  -> UserAuthFailure       <$> (fmap MethodName <$> nameListParser) <*> bool
  52  -> pure UserAuthSuccess
  53  -> UserAuthBanner        <$> string <*> string
  60  -> UserAuthPublicKeyOk   <$> publicKeyParser
  90  -> ChannelOpen
      <$> (ChannelType     <$> string)
      <*> (ChannelId       <$> uint32)
      <*> (InitWindowSize  <$> uint32)
      <*> (MaxPacketSize   <$> uint32)
  91  -> ChannelOpenConfirmation
      <$> (ChannelId       <$> uint32)
      <*> (ChannelId       <$> uint32)
      <*> (InitWindowSize  <$> uint32)
      <*> (MaxPacketSize   <$> uint32)
  92  -> ChannelOpenFailure    <$> (ChannelId <$> uint32) <*> (ChannelOpenFailureReason <$> uint32) <*> string <*> string
  94  -> ChannelData           <$> (ChannelId <$> uint32) <*> string
  95  -> ChannelDataExtended   <$> (ChannelId <$> uint32) <*> uint32 <*> string
  96  -> ChannelEof            <$> (ChannelId <$> uint32)
  97  -> ChannelClose          <$> (ChannelId <$> uint32)
  98  -> ChannelRequest        <$> (ChannelId <$> uint32) <*> channelRequestParser
  99  -> ChannelRequestSuccess <$> (ChannelId <$> uint32)
  100 -> ChannelRequestFailure <$> (ChannelId <$> uint32)
  x   -> fail ("UNKNOWN MESSAGE TYPE " ++ show x)
  where
    serviceParser = do
      len <- uint32
      ServiceName <$> B.getByteString (fromIntegral len)
    channelRequestParser = string >>= \case
      "pty-req" -> ChannelRequestPTY
        <$> bool
        <*> string
        <*> uint32
        <*> uint32
        <*> uint32
        <*> uint32
        <*> string
      "shell"   -> ChannelRequestShell <$> bool
      other     -> pure (ChannelRequestOther other)

    authMethodParser = string >>= \case
      "none"      -> pure AuthNone
      "hostbased" -> pure AuthHostBased
      "password"  -> void bool >> AuthPassword  <$> (Password <$> string)
      "publickey" -> do
        signed <- bool
        algo   <- Algorithm <$> string
        key    <- publicKeyParser
        msig   <- if signed then Just <$> signatureParser else pure Nothing
        pure (AuthPublicKey algo key msig)

    -- parser synomyns named as in the RFC
    bool    :: B.Get Bool
    bool     = byte >>= \case { 0 -> pure False; _ -> pure True; }
    byte    :: B.Get Word8
    byte     = B.getWord8
    uint32  :: B.Get Word32
    uint32   = B.getWord32be
    size    :: B.Get Int
    size     = fromIntegral <$> uint32
    string  :: B.Get BS.ByteString
    string   = uint32 >>= B.getByteString . fromIntegral
    -- Observing the encoded length is far cheaper than calculating the
    -- log2 of the resulting integer.
    sizedInteger :: B.Get (Int, Integer)
    sizedInteger  = do
      bs <- BS.dropWhile (==0) <$> string -- eventually remove leading 0 byte
      pure (BS.length bs * 8, foldl' (\i b-> i*256 + fromIntegral b) 0 $ BS.unpack bs)

messageBuilder :: Message -> BS.Builder
messageBuilder = \case
  Disconnect (DisconnectReason r) x y ->
    BS.word8   1 <> BS.word32BE r <> string x <> string y
  Ignore ->
    BS.word8   2
  Unimplemented ->
    BS.word8   3
  ServiceRequest (ServiceName sn) ->
    BS.word8   5 <> string sn
  ServiceAccept  (ServiceName sn) ->
    BS.word8   6 <> string sn
  UserAuthRequest (UserName un) (ServiceName sn) am ->
    BS.word8  50 <> string un <> string sn <> authMethodBuilder am
  UserAuthFailure methods partialSuccess ->
    BS.word8  51 <> nameListBuilder (methodName <$> methods) <> bool partialSuccess
  UserAuthSuccess ->
    BS.word8  52
  UserAuthBanner banner lang ->
    BS.word8  53 <> string banner <> string lang
  UserAuthPublicKeyOk pk ->
    BS.word8  60 <> publicKeyBuilder pk
  ChannelOpen (ChannelType a) (ChannelId b) (InitWindowSize c) (MaxPacketSize d) ->
    BS.word8  90 <> string a <> uint32 b <> uint32 c <> uint32 d
  ChannelOpenConfirmation (ChannelId a) (ChannelId b) (InitWindowSize c) (MaxPacketSize d) ->
    BS.word8  91 <> BS.word32BE a <> BS.word32BE b <> BS.word32BE c <> BS.word32BE d
  ChannelOpenFailure (ChannelId rid) (ChannelOpenFailureReason reason) x y ->
    BS.word8  92 <> uint32 rid <> uint32 reason <> string x <> string y
  ChannelData (ChannelId lid) s ->
    BS.word8  94 <> BS.word32BE lid <> BS.word32BE (fromIntegral $ BS.length s) <> BS.byteString s
  ChannelDataExtended (ChannelId lid) x s ->
    BS.word8  95 <> uint32 lid <> uint32 x <> string s
  ChannelEof   (ChannelId lid) ->
    BS.word8  96 <> uint32 lid
  ChannelClose (ChannelId lid) ->
    BS.word8  97 <> BS.word32BE lid
  ChannelRequest (ChannelId lid) req ->
    BS.word8  98 <> BS.word32BE lid <> channelRequestBuilder req
  ChannelRequestSuccess (ChannelId lid) ->
    BS.word8  99 <> BS.word32BE lid
  ChannelRequestFailure (ChannelId lid) ->
    BS.word8 100 <> BS.word32BE lid
  where
    string x = BS.word32BE (fromIntegral $ BS.length x) <> BS.byteString x
    bool   x = BS.word8 (if x then 0x01 else 0x00)
    uint32   = BS.word32BE

    channelRequestBuilder (ChannelRequestPTY a b c d e f g) = mconcat
      [ string "pty-req", bool a, string b, uint32 c, uint32 d, uint32 e, uint32 f, string g]
    channelRequestBuilder (ChannelRequestShell wantReply) = mconcat
      [ string "shell", bool wantReply ]
    channelRequestBuilder (ChannelRequestOther other) = mconcat
      [ string other ]

    authMethodBuilder AuthNone = mconcat
      [ string "none" ]
    authMethodBuilder AuthHostBased = mconcat
      [ string "hostbased" ]
    authMethodBuilder (AuthPassword (Password pw)) = mconcat
      [ string "password", bool False, string pw ]
    authMethodBuilder (AuthPublicKey (Algorithm algo) pk msig) = mconcat $ case msig of
      Nothing  -> [ string "publickey", bool False, string algo, publicKeyBuilder pk ]
      Just sig -> [ string "publickey", bool True,  string algo, publicKeyBuilder pk, signatureBuilder sig ]

publicKeyParser :: B.Get PublicKey
publicKeyParser = do
  keysize <- size
  B.isolate keysize $ string >>= \case
    "ssh-ed25519" ->
      Ed25519.publicKey <$> string >>= \case
        CryptoPassed k -> pure (PublicKeyEd25519 k)
        CryptoFailed e -> fail (show e)
    "ssh-rsa" -> do
      (_,n) <- sizedInteger
      (s,e) <- sizedInteger
      pure $ PublicKeyRSA $ RSA.PublicKey s n e
    other ->
      PublicKeyOther other <$> string
  where
    size    :: B.Get Int
    size     = fromIntegral <$> uint32
    uint32  :: B.Get Word32
    uint32   = B.getWord32be
    string  :: B.Get BS.ByteString
    string   = uint32 >>= B.getByteString . fromIntegral
    -- Observing the encoded length is far cheaper than calculating the
    -- log2 of the resulting integer.
    sizedInteger :: B.Get (Int, Integer)
    sizedInteger  = do
      bs <- BS.dropWhile (==0) <$> string -- eventually remove leading 0 byte
      pure (BS.length bs * 8, foldl' (\i b-> i*256 + fromIntegral b) 0 $ BS.unpack bs)

publicKeyBuilder :: PublicKey -> BS.Builder
publicKeyBuilder = \case
  PublicKeyEd25519    pk -> ed25519Builder    pk
  PublicKeyRSA        pk -> rsaBuilder        pk
  PublicKeyOther name pk -> otherBuilder name pk
  where
    uint32    = BS.word32BE
    string  x = BS.word32BE (fromIntegral $ BS.length x)  <> BS.byteString x
    integer x = BS.word32BE (fromIntegral $ BS.length bs) <> BS.byteString bs
      where
        bs = BS.pack $ g $ f x []
        f 0 acc = acc
        f i acc = let (q,r) = quotRem i 256
                  in  f q (fromIntegral r : acc)
        g []        = []
        g xxs@(x:_) | x > 128   = 0:xxs
                    | otherwise = xxs

    ed25519Builder :: Ed25519.PublicKey -> BS.Builder
    ed25519Builder key = mconcat
      [ BS.word32BE  51 -- total length is constant for ed25519
      , string       "ssh-ed25519"
      , string       (BS.pack $ BA.unpack key)
      ]

    rsaBuilder :: RSA.PublicKey -> BS.Builder
    rsaBuilder (RSA.PublicKey _ n e) = sized $ mconcat
      [ string "ssh-rsa"
      , integer n
      , integer e
      ]

    otherBuilder :: BS.ByteString -> BS.ByteString -> BS.Builder
    otherBuilder name pk = sized $ mconcat
      [ string name
      , string pk
      ]

signatureParser :: B.Get Signature
signatureParser = do
  sigsize <- size
  B.isolate sigsize $ string >>= \case
    "ssh-ed25519" ->
      Ed25519.signature <$> string >>= \case
        CryptoPassed s -> pure (SignatureEd25519 s)
        CryptoFailed e -> fail "56789"
    "ssh-rsa" ->
      SignatureRSA <$> string
    other ->
      SignatureOther other <$> string
  where
    size    :: B.Get Int
    size     = fromIntegral <$> uint32
    uint32  :: B.Get Word32
    uint32   = B.getWord32be
    string  :: B.Get BS.ByteString
    string   = uint32 >>= B.getByteString . fromIntegral

signatureBuilder :: Signature -> BS.Builder
signatureBuilder = sized . \case
  SignatureEd25519    sig -> string "ssh-ed25519" <> string (BS.pack $ BA.unpack sig)
  SignatureRSA        sig -> string "ssh-rsa"     <> string sig
  SignatureOther algo sig -> string algo          <> string sig
  where
    string x = BS.word32BE (fromIntegral $ BS.length x) <> BS.byteString x

verifyAuthSignature :: SessionId -> UserName -> ServiceName -> PublicKey -> Signature -> Bool
verifyAuthSignature
  (SessionId   sessionIdentifier)
  (UserName    userName)
  (ServiceName serviceName) publicKey signature = case (publicKey,signature) of
    (PublicKeyEd25519 k, SignatureEd25519 s) -> Ed25519.verify k signedData s
    (PublicKeyRSA     k, SignatureRSA     s) -> RSA.PKCS15.verify (Just Hash.SHA1) k signedData s
    _                                        -> False
  where
    signedData :: BS.ByteString
    signedData = LBS.toStrict $ BS.toLazyByteString $ mconcat
      [ string sessionIdentifier
      , byte   50
      , string userName
      , string serviceName
      , string "publickey"
      , bool   True
      , publicKeyBuilder publicKey
      ]

    byte     = BS.word8
    uint32   = BS.word32BE
    string x = BS.word32BE (fromIntegral $ BS.length x) <> BS.byteString x
    bool   x = BS.word8 (if x then 0x01 else 0x00)

sized :: BS.Builder -> BS.Builder
sized b = BS.word32BE (fromIntegral $ LBS.length lbs) <> BS.lazyByteString lbs
  where
    lbs = BS.toLazyByteString b
