{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH where

import           Control.Monad            (void, when)
import           Crypto.Error
import qualified Crypto.Error             as DH
import qualified Crypto.Hash              as Hash
import qualified Crypto.Hash.Algorithms   as Hash
import qualified Crypto.PubKey.Curve25519 as DH
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Data.Binary.Get          as B
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Builder  as BS
import qualified Data.ByteString.Lazy     as LBS
import           Data.Int
import qualified Data.List                as L
import           Data.Monoid
import           Data.Word
import           System.Exit

serverVersionString :: BS.ByteString
serverVersionString
  = "SSH-2.0-hssh_0.1"

data KexMsg
  = KexMsg
  { cookie                                  :: BS.ByteString
  , key_algorithms                          :: [BS.ByteString]
  , server_host_key_algorithms              :: [BS.ByteString]
  , encryption_algorithms_client_to_server  :: [BS.ByteString]
  , encryption_algorithms_server_to_client  :: [BS.ByteString]
  , mac_algorithms_client_to_server         :: [BS.ByteString]
  , mac_algorithms_server_to_client         :: [BS.ByteString]
  , compression_algorithms_client_to_server :: [BS.ByteString]
  , compression_algorithms_server_to_client :: [BS.ByteString]
  , languages_client_to_server              :: [BS.ByteString]
  , languages_server_to_client              :: [BS.ByteString]
  , first_kex_packet_follows                :: Bool
  } deriving (Eq, Ord, Show)

serverKexInit :: KexMsg
serverKexInit = KexMsg
  { cookie
  = "\155=\ACK\150\169p\164\v\t\245\223\224\EOT\233\200\SO"
  , key_algorithms
  = [ "curve25519-sha256@libssh.org" ]
  , server_host_key_algorithms
  = [ "ssh-ed25519" ]
  , encryption_algorithms_client_to_server
  = [ "chacha20-poly1305@openssh.com" ]
  , encryption_algorithms_server_to_client
  = [ "chacha20-poly1305@openssh.com" ]
  , mac_algorithms_client_to_server
  = [ "umac-64-etm@openssh.com" ]
  , mac_algorithms_server_to_client
  = [ "umac-64-etm@openssh.com" ]
  , compression_algorithms_client_to_server
  = [ "none" ]
  , compression_algorithms_server_to_client
  = [ "none" ]
  , languages_client_to_server
  = []
  , languages_server_to_client
  = []
  , first_kex_packet_follows
  = False
  }

versionParser :: B.Get BS.ByteString
versionParser = do
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
            0x0a -> pure $ BS.pack (reverse xs)
            _    -> stop
          x -> untilCRLF (i+1) (x:xs)

serverVersionBuilder :: BS.Builder
serverVersionBuilder =
  BS.byteString serverVersionString <> BS.int16BE 0x0d0a

kexInitParser :: B.Get KexMsg
kexInitParser = do
  void $ B.getWord8
  kex <- KexMsg
    <$> B.getByteString 16
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> nameList
    <*> ( B.getWord8 >>= \case { 0x00 -> pure False; _ -> pure True } )
  void $ B.getWord32be -- reserved for future extensions
  pure kex
  where
    nameList = do
      n <- fromIntegral . min maxPacketSize <$> B.getWord32be -- avoid undefined conversion
      BS.split 0x2c <$> B.getByteString n

kexInitBuilder :: KexMsg -> BS.Builder
kexInitBuilder msg = mconcat
  [ BS.byteString (cookie msg)
  , nameListBuilder (key_algorithms msg)
  , nameListBuilder (server_host_key_algorithms msg)
  , nameListBuilder (encryption_algorithms_client_to_server msg)
  , nameListBuilder (encryption_algorithms_server_to_client msg)
  , nameListBuilder (mac_algorithms_client_to_server msg)
  , nameListBuilder (mac_algorithms_server_to_client msg)
  , nameListBuilder (compression_algorithms_client_to_server msg)
  , nameListBuilder (compression_algorithms_server_to_client msg)
  , nameListBuilder (languages_client_to_server msg)
  , nameListBuilder (languages_server_to_client msg)
  , BS.word8 $ if first_kex_packet_follows msg then 0x01 else 0x00
  , BS.word32BE 0x00000000
  ]

data KexReply
  = KexReply
  { serverPublicHostKey      :: Ed25519.PublicKey
  , serverPublicEphemeralKey :: Curve25519.PublicKey
  , exchangeHashSignature    :: Ed25519.Signature
  } deriving (Show)

nameListBuilder :: [BS.ByteString] -> BS.Builder
nameListBuilder xs =
  BS.word32BE (fromIntegral $ g xs)
  <> mconcat (BS.byteString <$> L.intersperse "," xs)
  where
    g [] = 0
    g xs = sum (BS.length <$> xs) + length xs - 1

packetize :: BS.Builder -> BS.Builder
packetize payload = mconcat
  [ BS.word32BE $ fromIntegral packetLen
  , BS.word8    $ fromIntegral paddingLen
  , payload
  , padding
  ]
  where
    packetLen  = 1 + payloadLen + paddingLen
    payloadLen = fromIntegral $ LBS.length (BS.toLazyByteString payload)
    paddingLen = 16 - (4 + 1 + payloadLen) `mod` 8
    padding    = BS.byteString (BS.replicate paddingLen 0)

unpacketize :: B.Get a -> B.Get a
unpacketize parser = do
  packetLen <- fromIntegral . min maxPacketSize <$> B.getWord32be
  B.isolate packetLen $ do
    paddingLen <- fromIntegral <$> B.getWord8
    x <- parser
    B.skip paddingLen
    pure x

kexReplyBuilder :: KexReply -> BS.Builder
kexReplyBuilder reply = mconcat
  [ BS.word8        31 -- message type
  , BS.word32BE     51 -- host key len
  , BS.word32BE     11 -- host key algorithm name len
  , BS.byteString   "ssh-ed25519"
  , BS.word32BE     32 -- host key data len
  , BS.byteString $ BS.pack $ BA.unpack (serverPublicHostKey reply)
  , BS.word32BE     32 -- ephemeral key len
  , BS.byteString $ BS.pack $ BA.unpack (serverPublicEphemeralKey reply)
  , BS.word32BE   $ 4 + 11 + 4 + fromIntegral signatureLen
  , BS.word32BE     11 -- algorithm name len
  , BS.byteString   "ssh-ed25519"
  , BS.word32BE   $ fromIntegral signatureLen
  , BS.byteString   signature
  ]
  where
    signature    = BS.pack $ BA.unpack (exchangeHashSignature reply)
    signatureLen = BS.length signature

newKeysBuilder :: BS.Builder
newKeysBuilder = BS.word8 21

exchangeHash ::
  BS.ByteString ->         -- client version string
  BS.ByteString ->         -- server version string
  KexMsg ->                -- client kex msg
  KexMsg ->                -- server kex msg
  Ed25519.PublicKey ->     -- server host key
  Curve25519.PublicKey ->  -- client ephemeral key
  Curve25519.PublicKey ->  -- server ephemeral key
  Curve25519.DhSecret ->   -- dh secret
  Hash.Digest Hash.SHA256
exchangeHash vc vs ic is ks qc qs k
  = Hash.hash $ LBS.toStrict $ BS.toLazyByteString $ mconcat
  [ BS.word32BE                vcLen
  , BS.byteString              vc
  , BS.word32BE                vsLen
  , BS.byteString              vs
  , BS.word32BE                icLen
  , BS.word8                   20 -- SSH2_MSG_KEXINIT
  , kexInitBuilder             ic
  , BS.word32BE                isLen
  , BS.word8                   20 -- SSH2_MSG_KEXINIT
  , kexInitBuilder             is
  , ed25519PublicKeyBuilder    ks
  , curve25519BlobBuilder      qc
  , curve25519BlobBuilder      qs
  , curve25519DhSecretBuilder  k
  ] :: Hash.Digest Hash.SHA256
  where
    vcLen = fromIntegral $     BS.length vc
    vsLen = fromIntegral $     BS.length vs
    icLen = fromIntegral $ 1 + builderLength (kexInitBuilder ic)
    isLen = fromIntegral $ 1 + builderLength (kexInitBuilder is)

ed25519PublicKeyBuilder :: Ed25519.PublicKey -> BS.Builder
ed25519PublicKeyBuilder key = mconcat
  [ BS.word32BE     51 -- host key len
  , BS.word32BE     11 -- host key algorithm name len
  , BS.byteString   "ssh-ed25519"
  , BS.word32BE     32 -- host key data len
  , BS.byteString $ BS.pack $ BA.unpack key
  ]

curve25519BlobBuilder :: Curve25519.PublicKey -> BS.Builder
curve25519BlobBuilder key =
  BS.word32BE 32 <> BS.byteString (BS.pack $ BA.unpack key)

curve25519DhSecretBuilder  :: Curve25519.DhSecret -> BS.Builder
curve25519DhSecretBuilder sec = do
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

kexRequestParser :: B.Get DH.PublicKey
kexRequestParser = do
  msg <- B.getWord8
  when (msg /= 30) (fail "expected SSH_MSG_KEX_ECDH_INIT")
  keySize <- B.getWord32be
  when (keySize /= 32) (fail "expected key size to be 32 bytes")
  bs <- B.getByteString 32
  case DH.publicKey bs of
    DH.CryptoPassed a -> pure a
    DH.CryptoFailed e -> fail (show e)

mpintLenBuilder :: Integer -> (Int, BS.Builder) -> (Int, BS.Builder)
mpingLenBuilder 0 x = x
mpintLenBuilder i (!len, !bld) = mpintLenBuilder q (len + 4, BS.word32BE (fromIntegral r) <> bld)
  where
    (q,r) = i `quotRem` 0x0100000000

maxPacketSize :: Word32
maxPacketSize = 32767

builderLength :: BS.Builder -> Int64
builderLength =
  LBS.length . BS.toLazyByteString

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> BS.ByteString -> SessionId -> [Hash.Digest Hash.SHA256]
deriveKeys sec hash i (SessionId sess) =
  k1:(f [k1])
  where
    k1   = Hash.hashFinalize    $
      flip Hash.hashUpdate sess $
      flip Hash.hashUpdate i st
    f ks = kx:(f $ ks ++ [kx])
      where
        kx = Hash.hashFinalize (foldl Hash.hashUpdate st ks)
    st =
      flip Hash.hashUpdate hash $
      flip Hash.hashUpdate secmpint
      Hash.hashInit
    secmpint =
      LBS.toStrict $ BS.toLazyByteString $ curve25519DhSecretBuilder sec

data DisconnectReason
  = DisconnectReason Word32
  deriving (Eq, Ord, Show)

data AuthenticationData
  = None
  | HostBased
  | Password  BS.ByteString
  | PublicKey PublicKey (Maybe Signature)
  deriving (Eq, Show)

data PublicKey
  = PublicKeyEd25519 Ed25519.PublicKey
  | PublicKeyOther   BS.ByteString BS.ByteString
  deriving (Eq, Show)

data Signature
  = SignatureEd25519 Ed25519.Signature
  | SignatureOther   BS.ByteString BS.ByteString
  deriving (Eq, Show)

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
  deriving (Show)

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

newtype SessionId       = SessionId     BS.ByteString deriving (Eq, Ord, Show)
newtype UserName        = UserName      BS.ByteString deriving (Eq, Ord, Show)
newtype MethodName      = MethodName    { methodName :: BS.ByteString } deriving (Eq, Ord, Show)
newtype ServiceName     = ServiceName    BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelType     = ChannelType    BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelId       = ChannelId      Word32 deriving (Eq, Ord, Show)
newtype InitWindowSize  = InitWindowSize Word32 deriving (Eq, Ord, Show)
newtype MaxPacketSize   = MaxPacketSize  Word32 deriving (Eq, Ord, Show)

data ChannelOpenFailureReason
  = AdministrativelyProhibited
  | ConnectFailed
  | UnknownChannelType
  | ResourceShortage
  deriving (Eq, Ord, Show)

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
  90  -> ChannelOpen
      <$> (ChannelType     <$> string)
      <*> (ChannelId       <$> uint32)
      <*> (InitWindowSize  <$> uint32)
      <*> (MaxPacketSize   <$> uint32)
  94  -> ChannelData           <$> (ChannelId <$> uint32) <*> string
  95  -> ChannelDataExtended   <$> (ChannelId <$> uint32) <*> uint32 <*> string
  96  -> ChannelEof            <$> (ChannelId <$> uint32)
  97  -> ChannelClose          <$> (ChannelId <$> uint32)
  98  -> ChannelRequest        <$> (ChannelId <$> uint32) <*> channelRequestParser
  99  -> ChannelRequestSuccess <$> (ChannelId <$> uint32)
  100 -> ChannelRequestFailure <$> (ChannelId <$> uint32)
  -- 100 -> FAILURE

  x    -> fail ("UNKNOWN MESSAGE TYPE: " ++ show x)
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
      "none"      -> pure None
      "hostbased" -> pure HostBased
      "password"  -> void bool >> Password  <$> string
      "publickey" -> do
        signed <- bool
        algo   <- string
        case algo of
          "ssh-ed25519" -> do
            keysize <- fromIntegral <$> uint32
            key <- B.isolate keysize $ do
              keyalgo <- string
              when (keyalgo /= algo) (fail "KEY ALGORITHM NAME MISMATCH")
              Ed25519.publicKey <$> string >>= \case
                CryptoPassed k -> pure (PublicKeyEd25519 k)
                CryptoFailed e -> fail (show e)
            msig <- if not signed
              then pure Nothing
              else do
                sigsize <- fromIntegral <$> uint32
                B.isolate sigsize $ do
                  sigalgo <- string
                  when (sigalgo /= algo) (fail "SIGNATURE ALGORITHM NAME MISMATCH")
                  Ed25519.signature <$> string >>= \case
                    CryptoPassed s -> pure (Just (SignatureEd25519 s))
                    CryptoFailed e -> fail (show e)
            pure $ PublicKey key msig
          _ -> fail "FOOBAR"
    -- parser synomyns named as in the RFC
    uint8  = B.getWord8
    uint32 = B.getWord32be
    string = (fromIntegral <$> B.getWord32be) >>= B.getByteString
    bool   = B.getWord8 >>= \case { 0 -> pure False; _ -> pure True; }

messageBuilder :: Message -> BS.Builder
messageBuilder = \case
  ServiceRequest srv -> BS.word8 0x05 <> serviceBuilder srv
  ServiceAccept  srv -> BS.word8 0x06 <> serviceBuilder srv
  UserAuthFailure methods partialSuccess ->
    BS.word8 51 <> nameListBuilder (methodName <$> methods) <> bool partialSuccess
  UserAuthSuccess ->
    BS.word8 52
  UserAuthBanner banner lang ->
    BS.word8 53 <> string banner <> string lang
  UserAuthPublicKeyOk pk ->
    BS.word8 60 <> publicKey pk
  ChannelOpenConfirmation (ChannelId a) (ChannelId b) (InitWindowSize c) (MaxPacketSize d) ->
    BS.word8 91 <> BS.word32BE a <> BS.word32BE b <> BS.word32BE d <> BS.word32BE d
  ChannelData (ChannelId lid) s ->
    BS.word8 94 <> BS.word32BE lid <> BS.word32BE (fromIntegral $ BS.length s) <> BS.byteString s
  ChannelClose (ChannelId lid) ->
    BS.word8  97 <> BS.word32BE lid
  ChannelRequestSuccess (ChannelId lid) -> BS.word8  99 <> BS.word32BE lid
  ChannelRequestFailure (ChannelId lid) -> BS.word8 100 <> BS.word32BE lid
  otherwise          -> error (show otherwise)
  where
    serviceBuilder (ServiceName bs) = BS.word32BE (fromIntegral $ BS.length bs) <> BS.byteString bs
    string x = BS.word32BE (fromIntegral $ BS.length x) <> BS.byteString x
    bool   x = BS.word8 (if x then 0x01 else 0x00)
    uint32 x = BS.word32BE
    publicKey (PublicKeyEd25519 pk) = string "ssh-ed25519" <> ed25519PublicKeyBuilder pk
    publicKey _                     = error "ABCDEF"

verifyAuthSignature :: SessionId -> UserName -> ServiceName -> PublicKey -> Signature -> Bool
verifyAuthSignature
  (SessionId   sessionIdentifier)
  (UserName    userName)
  (ServiceName serviceName) publicKey signature = case (publicKey,signature) of
    (PublicKeyEd25519 k, SignatureEd25519 s) -> Ed25519.verify k signedData s
    _                                        -> False
  where
    signedData :: BS.ByteString
    signedData = LBS.toStrict $ BS.toLazyByteString $ mconcat
      [ string    sessionIdentifier
      , byte      50
      , string    userName
      , string    serviceName
      , string    "publickey"
      , bool      True
      , pk        publicKey
      ]

    byte     = BS.word8
    uint32   = BS.word32BE
    string x = BS.word32BE (fromIntegral $ BS.length x) <> BS.byteString x
    bool   x = BS.word8 (if x then 0x01 else 0x00)
    pk       = \case
      PublicKeyEd25519 x -> string "ssh-ed25519" <> ed25519PublicKeyBuilder x
      other              -> error "ABCDEF"
