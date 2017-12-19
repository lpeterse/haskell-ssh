{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH where

import           Control.Monad            (void, when)
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
  , f (key_algorithms msg)
  , f (server_host_key_algorithms msg)
  , f (encryption_algorithms_client_to_server msg)
  , f (encryption_algorithms_server_to_client msg)
  , f (mac_algorithms_client_to_server msg)
  , f (mac_algorithms_server_to_client msg)
  , f (compression_algorithms_client_to_server msg)
  , f (compression_algorithms_server_to_client msg)
  , f (languages_client_to_server msg)
  , f (languages_server_to_client msg)
  , BS.word8 $ if first_kex_packet_follows msg then 0x01 else 0x00
  , BS.word32BE 0x00000000
  ]
  where
    f xs = BS.word32BE (fromIntegral $ g xs)
        <> mconcat (BS.byteString <$> L.intersperse "," xs)
    g [] = 0
    g xs = sum (BS.length <$> xs) + length xs - 1

data KexReply
  = KexReply
  { serverPublicHostKey      :: Ed25519.PublicKey
  , serverPublicEphemeralKey :: Curve25519.PublicKey
  , exchangeHashSignature    :: Ed25519.Signature
  } deriving (Show)

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

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> BS.ByteString -> Hash.Digest Hash.SHA256 -> [Hash.Digest Hash.SHA256]
deriveKeys sec hash i sess =
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

newtype UserName   = UserName   BS.ByteString deriving (Eq, Ord, Show)
newtype MethodName = MethodName BS.ByteString deriving (Eq, Ord, Show)

data Message
  = ServiceRequest ServiceName
  | ServiceAccept  ServiceName
  | UserAuthRequest UserName ServiceName MethodName
  | UserAuthFailure
  | UserAuthSuccess
  | ChannelOpen    BS.ByteString Word32 Word32 Word32
  | ChannelOpenConfirmation Word32 Word32 Word32 Word32
  | ChannelRequest Word32 ChannelRequest
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
  | ChannelRequestOther
    { crother           :: BS.ByteString
    } deriving (Eq, Ord, Show)

data ServiceName
  = ServiceUserAuth
  | ServiceConnection
  deriving (Eq, Ord, Show)

messageParser :: B.Get Message
messageParser = B.getWord8 >>= \case
  0x05 -> ServiceRequest        <$> serviceParser
  0x06 -> ServiceAccept         <$> serviceParser
  0x32 -> UserAuthRequest       <$> (UserName <$> bs) <*> serviceParser <*> (MethodName <$> bs)
  90   -> channelOpenParser
  98   -> ChannelRequest        <$> B.getWord32be <*> channelRequestParser
  -- 99  -> SUCESS
  -- 100 -> FAILURE

  _    -> fail "UNKNOWN MESSAGE TYPE"
  where
    serviceParser = do
      len <- B.getWord32be
      B.getByteString (fromIntegral len) >>= \case
        "ssh-userauth"   -> pure ServiceUserAuth
        "ssh-connection" -> pure ServiceConnection
        _                -> fail "UNKNOWN SERVICE REQUEST"
    channelOpenParser =
      ChannelOpen <$> bs <*> B.getWord32be <*> B.getWord32be <*> B.getWord32be
    channelRequestParser = bs >>= \case
      "pty-req" -> ChannelRequestPTY
        <$> ( B.getWord8 >>= \case { 0x00 -> pure False; _ -> pure True } )
        <*> bs
        <*> B.getWord32be
        <*> B.getWord32be
        <*> B.getWord32be
        <*> B.getWord32be
        <*> bs
      other     -> pure (ChannelRequestOther other)

    bs = do
      len <- B.getWord32be
      B.getByteString (fromIntegral len)

messageBuilder :: Message -> BS.Builder
messageBuilder = \case
  ServiceRequest srv -> BS.word8 0x05 <> serviceBuilder srv
  ServiceAccept  srv -> BS.word8 0x06 <> serviceBuilder srv
  UserAuthSuccess    -> BS.word8 0x34
  ChannelOpenConfirmation a b c d ->
    BS.word8 91 <> BS.word32BE a <> BS.word32BE b <> BS.word32BE d <> BS.word32BE d
  otherwise          -> error (show otherwise)
  where
    serviceBuilder ServiceUserAuth   = BS.word32BE 12 <> BS.byteString "ssh-userauth"
    serviceBuilder ServiceConnection = BS.word32BE 14 <> BS.byteString "ssh-connection"
