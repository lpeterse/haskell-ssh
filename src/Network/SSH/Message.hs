{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE LambdaCase         #-}
{-# LANGUAGE OverloadedStrings  #-}
module Network.SSH.Message
  ( -- * Message
    Message (..)
    -- ** Disconnect (1)
  , Disconnect (..)
  , DisconnectReason (..)
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
  , ChannelOpenFailureReason (..)
    -- ** ChannelWindowAdjust (93)
  , ChannelWindowAdjust (..)
    -- ** ChannelData (94)
  , ChannelData (..)
    -- ** ChannelExtendedData (95)
  , ChannelExtendedData (..)
    -- ** ChannelEof (96)
  , ChannelEof (..)
    -- ** ChannelClose (97)
  , ChannelClose (..)
    -- ** ChannelRequest (98)
  , ChannelRequest (..)
  , ChannelRequestRequest (..)
    -- ** ChannelSuccess (99)
  , ChannelSuccess (..)
    -- ** ChannelFailure (100)
  , ChannelFailure (..)

    -- * verifyAuthSignature
  , verifyAuthSignature

    -- * Misc
  , Algorithm (..)
  , AuthMethod (..)
  , AuthMethodName (..)
  , ChannelId (..)
  , ChannelPacketSize (..)
  , ChannelType (..)
  , ChannelWindowSize (..)
  , Cookie (), newCookie, nilCookie
  , Password (..)
  , PtySettings (..)
  , PublicKey (..)
  , ServiceName (..)
  , SessionId (..)
  , Signature (..)
  , UserName (..)
  , Version (..)
  ) where

import           Control.Exception
import           Control.Monad            (unless, void)
import           Crypto.Error
import qualified Crypto.Hash.Algorithms   as Hash
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA.PKCS15
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
import           Data.Typeable
import           Data.Word
import           System.Exit

import           Network.SSH.Encoding
import           Network.SSH.Key

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
  | MsgChannelWindowAdjust     ChannelWindowAdjust
  | MsgChannelData             ChannelData
  | MsgChannelExtendedData     ChannelExtendedData
  | MsgChannelEof              ChannelEof
  | MsgChannelClose            ChannelClose
  | MsgChannelRequest          ChannelRequest
  | MsgChannelSuccess          ChannelSuccess
  | MsgChannelFailure          ChannelFailure
  | MsgUnknown                 Word8
  deriving (Eq, Show)

data Disconnect
  = Disconnect
  { disconnectReason      :: DisconnectReason
  , disconnectDescription :: BS.ByteString
  , disconnectLanguageTag :: BS.ByteString
  }
  deriving (Eq, Show, Typeable)

data DisconnectReason
    = DisconnectHostNotAllowedToConnect
    | DisconnectProtocolError
    | DisconnectKeyExchangeFailed
    | DisconnectReserved
    | DisconnectMacError
    | DisconnectCompressionError
    | DisconnectServiceNotAvailable
    | DisconnectProtocolVersionNotSupported
    | DisconnectHostKeyNotVerifiable
    | DisconnectConnectionLost
    | DisconnectByApplication
    | DisconnectTooManyConnection
    | DisconnectAuthCancelledByUser
    | DisconnectNoMoreAuthMethodsAvailable
    | DisconnectIllegalUsername
    deriving (Eq, Show, Typeable)

instance Exception Disconnect

data Ignore
  = Ignore
  deriving (Eq, Show)

data Unimplemented
  = Unimplemented -- TODO: has Word32 payload
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
  = ChannelOpen ChannelType ChannelId ChannelWindowSize ChannelPacketSize
  deriving (Eq, Show)

data ChannelOpenConfirmation
  = ChannelOpenConfirmation ChannelId ChannelId ChannelWindowSize ChannelPacketSize
  deriving (Eq, Show)

data ChannelOpenFailure
  = ChannelOpenFailure ChannelId ChannelOpenFailureReason BS.ByteString BS.ByteString
  deriving (Eq, Show)

data ChannelOpenFailureReason
  = ChannelOpenAdministrativelyProhibited
  | ChannelOpenConnectFailed
  | ChannelOpenUnknownChannelType
  | ChannelOpenResourceShortage
  deriving (Eq, Show)

data ChannelWindowAdjust
  = ChannelWindowAdjust ChannelId ChannelWindowSize
  deriving (Eq, Show)

data ChannelData
  = ChannelData ChannelId BS.ByteString
  deriving (Eq, Show)

data ChannelExtendedData
  = ChannelExtendedData ChannelId Word32 BS.ByteString
  deriving (Eq, Show)

data ChannelEof
  = ChannelEof ChannelId
  deriving (Eq, Show)

data ChannelClose
  = ChannelClose ChannelId
  deriving (Eq, Show)

data ChannelRequest
    = ChannelRequest ChannelId ChannelRequestRequest
    deriving (Eq, Show)

data ChannelRequestRequest
  = ChannelRequestPty
    { crWantReply   :: Bool
    , crPtySettings :: PtySettings
    }
  | ChannelRequestShell
    { crWantReply     :: Bool
    }
  | ChannelRequestExec
    { crWantReply :: Bool
    , crCommand   :: BS.ByteString
    }
  | ChannelRequestExitStatus
    { crExitStatus    :: ExitCode
    }
  | ChannelRequestExitSignal
    { crSignalName   :: BS.ByteString
    , crCodeDumped   :: Bool
    , crErrorMessage :: BS.ByteString
    , crLanguageTag  :: BS.ByteString
    }
  | ChannelRequestEnv
    { crWantReply     :: Bool
    , crVariableName  :: BS.ByteString
    , crVariableValue :: BS.ByteString
    }
  | ChannelRequestOther
    { crOther     :: BS.ByteString
    }
  deriving (Eq, Show)

data ChannelSuccess
  = ChannelSuccess ChannelId
  deriving (Eq, Show)

data ChannelFailure
  = ChannelFailure ChannelId
  deriving (Eq, Show)

data AuthMethod
  = AuthNone
  | AuthHostBased
  | AuthPassword  Password
  | AuthPublicKey Algorithm PublicKey (Maybe Signature)
  deriving (Eq, Show)

data Signature
  = SignatureEd25519 Ed25519.Signature
  | SignatureRSA     BS.ByteString
  | SignatureOther   BS.ByteString BS.ByteString
  deriving (Eq, Show)

data PtySettings
  = PtySettings
  { ptyEnv          :: BS.ByteString
  , ptyWidthCols    :: Word32
  , ptyHeightRows   :: Word32
  , ptyWidthPixels  :: Word32
  , ptyHeightPixels :: Word32
  , ptyModes        :: BS.ByteString
  } deriving (Eq, Show)

newtype Cookie           = Cookie           BS.ByteString deriving (Eq, Ord, Show)

newCookie :: MonadRandom m => m Cookie
newCookie  = Cookie <$> getRandomBytes 16

nilCookie :: Cookie
nilCookie  = Cookie  $  BS.replicate 16 0

newtype Version           = Version           BS.ByteString deriving (Eq, Ord, Show)
newtype Algorithm         = Algorithm         BS.ByteString deriving (Eq, Ord, Show)
newtype Password          = Password          BS.ByteString deriving (Eq, Ord, Show)
newtype SessionId         = SessionId         BS.ByteString deriving (Eq, Ord, Show)
newtype UserName          = UserName          BS.ByteString deriving (Eq, Ord, Show)
newtype AuthMethodName    = AuthMethodName    BS.ByteString deriving (Eq, Ord, Show)
newtype ServiceName       = ServiceName       BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelType       = ChannelType       BS.ByteString deriving (Eq, Ord, Show)
newtype ChannelId         = ChannelId         Word32        deriving (Eq, Ord, Show)
newtype ChannelWindowSize = ChannelWindowSize Word32        deriving (Eq, Ord, Show)
newtype ChannelPacketSize = ChannelPacketSize Word32        deriving (Eq, Ord, Show)

-------------------------------------------------------------------------------
-- Encoding instances
-------------------------------------------------------------------------------

instance Encodable Message where
    len = \case
        MsgDisconnect               x -> len x
        MsgIgnore                   x -> len x
        MsgUnimplemented            x -> len x
        MsgDebug                    x -> len x
        MsgServiceRequest           x -> len x
        MsgServiceAccept            x -> len x
        MsgKexInit                  x -> len x
        MsgNewKeys                  x -> len x
        MsgKexEcdhInit              x -> len x
        MsgKexEcdhReply             x -> len x
        MsgUserAuthRequest          x -> len x
        MsgUserAuthFailure          x -> len x
        MsgUserAuthSuccess          x -> len x
        MsgUserAuthBanner           x -> len x
        MsgUserAuthPublicKeyOk      x -> len x
        MsgChannelOpen              x -> len x
        MsgChannelOpenConfirmation  x -> len x
        MsgChannelOpenFailure       x -> len x
        MsgChannelWindowAdjust      x -> len x
        MsgChannelData              x -> len x
        MsgChannelExtendedData      x -> len x
        MsgChannelEof               x -> len x
        MsgChannelClose             x -> len x
        MsgChannelRequest           x -> len x
        MsgChannelSuccess           x -> len x
        MsgChannelFailure           x -> len x
        MsgUnknown                  _ -> lenWord8
    put = \case
        MsgDisconnect               x -> put x
        MsgIgnore                   x -> put x
        MsgUnimplemented            x -> put x
        MsgDebug                    x -> put x
        MsgServiceRequest           x -> put x
        MsgServiceAccept            x -> put x
        MsgKexInit                  x -> put x
        MsgNewKeys                  x -> put x
        MsgKexEcdhInit              x -> put x
        MsgKexEcdhReply             x -> put x
        MsgUserAuthRequest          x -> put x
        MsgUserAuthFailure          x -> put x
        MsgUserAuthSuccess          x -> put x
        MsgUserAuthBanner           x -> put x
        MsgUserAuthPublicKeyOk      x -> put x
        MsgChannelOpen              x -> put x
        MsgChannelOpenConfirmation  x -> put x
        MsgChannelOpenFailure       x -> put x
        MsgChannelWindowAdjust      x -> put x
        MsgChannelData              x -> put x
        MsgChannelExtendedData      x -> put x
        MsgChannelEof               x -> put x
        MsgChannelClose             x -> put x
        MsgChannelRequest           x -> put x
        MsgChannelSuccess           x -> put x
        MsgChannelFailure           x -> put x
        MsgUnknown                  x -> putWord8 x
    get =
        MsgDisconnect              get <|>
        MsgIgnore                  get <|>
        MsgUnimplemented           get <|>
        MsgDebug                   get <|>
        MsgServiceRequest          get <|>
        MsgServiceAccept           get <|>
        MsgKexInit                 get <|>
        MsgNewKeys                 get <|>
        MsgKexEcdhInit             get <|>
        MsgKexEcdhReply            get <|>
        MsgUserAuthRequest         get <|>
        MsgUserAuthFailure         get <|>
        MsgUserAuthSuccess         get <|>
        MsgUserAuthBanner          get <|>
        MsgUserAuthPublicKeyOk     get <|>
        MsgChannelOpen             get <|>
        MsgChannelOpenConfirmation get <|>
        MsgChannelOpenFailure      get <|>
        MsgChannelWindowAdjust     get <|>
        MsgChannelData             get <|>
        MsgChannelExtendedData     get <|>
        MsgChannelEof              get <|>
        MsgChannelClose            get <|>
        MsgChannelRequest          get <|>
        MsgChannelSuccess          get <|>
        MsgChannelFailure          get <|>
        MsgUnknown                 getWord8

instance Encodable Disconnect where
    len (Disconnect r d l) =
        lenWord8 + len r + lenString d + lenString l
    put (Disconnect r d l) = do
        putWord8 1
        putWord32 $ case r of
            DisconnectHostNotAllowedToConnect     -> 1
            DisconnectProtocolError               -> 2
            DisconnectKeyExchangeFailed           -> 3
            DisconnectReserved                    -> 4
            DisconnectMacError                    -> 5
            DisconnectCompressionError            -> 6
            DisconnectServiceNotAvailable         -> 7
            DisconnectProtocolVersionNotSupported -> 8
            DisconnectHostKeyNotVerifiable        -> 9
            DisconnectConnectionLost              -> 10
            DisconnectByApplication               -> 11
            DisconnectTooManyConnection           -> 12
            DisconnectAuthCancelledByUser         -> 13
            DisconnectNoMoreAuthMethodsAvailable  -> 14
            DisconnectIllegalUsername             -> 15
        putString d
        putString l
    get = do
        BA.byte 1
        reason <- getWord32 >>= \case
            1  -> pure DisconnectHostNotAllowedToConnect
            2  -> pure DisconnectProtocolError
            3  -> pure DisconnectKeyExchangeFailed
            4  -> pure DisconnectReserved
            5  -> pure DisconnectMacError
            6  -> pure DisconnectCompressionError
            7  -> pure DisconnectServiceNotAvailable
            8  -> pure DisconnectProtocolVersionNotSupported
            9  -> pure DisconnectHostKeyNotVerifiable
            10 -> pure DisconnectConnectionLost
            11 -> pure DisconnectByApplication
            12 -> pure DisconnectTooManyConnection
            13 -> pure DisconnectAuthCancelledByUser
            14 -> pure DisconnectNoMoreAuthMethodsAvailable
            15 -> pure DisconnectIllegalUsername
            _  -> fail ""
        Disconnect reason <*> getString <*> getString

instance B.Binary Ignore where
    len _ = 1
    put _ = putWord8 2
    get   = BA.byte 2 >> pure Ignore

instance B.Binary Unimplemented where
    len _ = lenWord8 + lenWord32
    put (Unimplemented w) = putWord8 3 >> putWord32 w
    get = BA.byte 3 >> Unimplemented <$> getWord32

instance B.Binary Debug where
    len (Debug ad msg lang) = lenWord8 + lenBool + lenString msg + lenString lang
    put (Debug ad msg lang) = putWord8 4 >> putBool ad >> putString msg >> putString lang
    get = BA.byte 4 >> Debug <$> getBool <*> getString <*> getString

instance B.Binary ServiceRequest where
    len (ServiceRequest name) = lenWord8 + len name
    put (ServiceRequest name) = putWord8 5 >> put name
    get = BA.byte 5 >> ServiceRequest <$> get

instance B.Binary ServiceAccept where
    len (ServiceAccept name) = lenWord8 + len name
    put (ServiceAccept s) = putWord8 6 >> put name
    get = BA.byte 6 >> ServiceAccept <$> B.get

instance B.Binary KexInit where
    len kex = lenWord8
        + len (kexCookie                              kex)
        + len (kexCookie                              kex)
        + len (kexAlgorithms                          kex)
        + len (kexServerHostKeyAlgorithms             kex)
        + len (kexEncryptionAlgorithmsClientToServer  kex)
        + len (kexEncryptionAlgorithmsServerToClient  kex)
        + len (kexMacAlgorithmsClientToServer         kex)
        + len (kexMacAlgorithmsServerToClient         kex)
        + len (kexCompressionAlgorithmsClientToServer kex)
        + len (kexCompressionAlgorithmsServerToClient kex)
        + len (kexLanguagesClientToServer             kex)
        + len (kexLanguagesServerToClient             kex)
        + len (kexFirstPacketFollows                  kex)
        + lenWord32
    put kex = do
        putWord8     20
        put         (kexCookie                              kex)
        putNameList (kexAlgorithms                          kex)
        putNameList (kexServerHostKeyAlgorithms             kex)
        putNameList (kexEncryptionAlgorithmsClientToServer  kex)
        putNameList (kexEncryptionAlgorithmsServerToClient  kex)
        putNameList (kexMacAlgorithmsClientToServer         kex)
        putNameList (kexMacAlgorithmsServerToClient         kex)
        putNameList (kexCompressionAlgorithmsClientToServer kex)
        putNameList (kexCompressionAlgorithmsServerToClient kex)
        putNameList (kexLanguagesClientToServer             kex)
        putNameList (kexLanguagesServerToClient             kex)
        putBool     (kexFirstPacketFollows                  kex)
        putWord32 0 -- reserved for future extensions
    get = do
        BA.byte 20
        kex <- KexInit <$> B.get
            <*> getNameList <*> getNameList <*> getNameList <*> getNameList
            <*> getNameList <*> getNameList <*> getNameList <*> getNameList
            <*> getNameList <*> getNameList <*> getBool
        getWord32 -- reserved for future extensions
        pure kex

instance B.Binary NewKeys where
    len _ = lenWord8
    put _ = putWord8 21
    get   = BA.byte 21 >> pure NewKeys

instance B.Binary KexEcdhInit where
    len (KexEcdhInit key) = lenWord8 + lenCurve25519PK
    put (KexEcdhInit key) = putWord8 30 >> putCurve25519PK key
    get = BA.byte 30 >> KexEcdhInit <$> getCurve25519PK

instance B.Binary KexEcdhReply where
    len (KexEcdhReply hkey ekey sig) =
        lenWord8 + len hkey + len ekey + len sig
    put (KexEcdhReply hkey ekey sig) = do
        putWord8 31
        put hkey
        put ekey
        put sig
    get = do
        BA.byte 31
        KexEcdhReply
            <$> get
            <*> get
            <*> get

instance B.Binary UserAuthRequest where
    len (UserAuthRequest un sn am) = lenWord8 + len un + len sn + len am
    put (UserAuthRequest un sn am) = putWord8 50 >> put un >> put sn >> put an
    get = BA.byte 50 >> UserAuthRequest <$> B.get <*> B.get <*> B.get

instance B.Binary UserAuthFailure where
    len (UserAuthFailure ms ps) = lenWord8 + undefined
    put (UserAuthFailure ms ps) = do
        putWord8 51
        putNameList ((\(AuthMethodName x)->x) <$> ms)
        putBool ps
    get =  do
        BA.byte 51
        UserAuthFailure <$> (fmap AuthMethodName <$> getNameList) <*> getBool

instance B.Binary UserAuthSuccess where
    len _ = lenWord8
    put _ = putWord8 52
    get   = BA.byte 52 >> pure UserAuthSuccess

instance B.Binary UserAuthBanner where
    len (UserAuthBanner x y) = lenWord8 + lenString x + lenString y
    put (UserAuthBanner x y) = putWord8 53 >> putString x >> putString y
    get = BA.byte 53 >> UserAuthBanner <$> getString <*> getString

instance B.Binary UserAuthPublicKeyOk where
    len (UserAuthPublicKeyOk alg pk) = lenWord8 + len alg + len pk
    put (UserAuthPublicKeyOk alg pk) = putWord8 60 >> put alg >> put pk
    get = BA.byte 60 >> UserAuthPublicKeyOk <$> get <*> get

instance B.Binary ChannelOpen where
    len (ChannelOpen ct rid ws ps) = lenWord8 + len ct + len rid + len ws + len ps
    put (ChannelOpen ct rid ws ps) = putWord8 90 + put ct + put rid + put ws + put ps
    get = BA.byte 90 >> ChannelOpen <$> get <*> get <*> get  <*> get

instance B.Binary ChannelOpenConfirmation where
    len (ChannelOpenConfirmation a b c d) = lenWord8 + len a + len b + len c + len d
    put (ChannelOpenConfirmation a b c d) = putWord8 91 >> put a >> put b >> put c >> put d
    get = BA.byte 91 >> ChannelOpenConfirmation <$> get <*> get <*> get  <*> get

instance B.Binary ChannelOpenFailure where
    len (ChannelOpenFailure rid reason descr lang) =
        lenWord8 + len rid + lenString reason + lenString desc + lenString lang
    put (ChannelOpenFailure rid reason descr lang) = do
        putWord8 92
        put rid
        putWord32 $ case reason of
            ChannelOpenAdministrativelyProhibited -> 1
            ChannelOpenConnectFailed              -> 2
            ChannelOpenUnknownChannelType         -> 3
            ChannelOpenResourceShortage           -> 4
        putString descr
        putString lang
    get = do
        BA.byte 92
        rid <- get
        reason <- getUint32 >>= \case
            1 -> pure ChannelOpenAdministrativelyProhibited
            2 -> pure ChannelOpenConnectFailed
            3 -> pure ChannelOpenUnknownChannelType
            4 -> pure ChannelOpenResourceShortage
            _ -> fail ""
        ChannelOpenFailure rid reason <$> getString <*> getString

instance B.Binary ChannelWindowAdjust where
    len (ChannelWindowAdjust cid ws) = lenWord8 + len cid + len ws
    put (ChannelWindowAdjust channelId windowSize) = putWord8 93 >> put cid <> put ws
    get = BA.byte 93 >> ChannelWindowAdjust <$> get <*> get

instance B.Binary ChannelData where
    len (ChannelData cid ba) = lenWord8 + len cid + lenString ba
    put (ChannelData cid ba) = putWord8 94 >> put cid >> putString ba
    get = BA.byte 94 >> ChannelData <$> get <*> getString

instance B.Binary ChannelExtendedData where
    len (ChannelData cid _ ba) = lenWord8 + len cid + lenWord32 + lenString ba
    put (ChannelData cid x ba) = putWord8 95 >> put cid >> putWord32 >> putString ba
    get = BA.byte 95 >> ChannelExtendedData <$> get <*> getString

instance B.Binary ChannelEof where
    len (ChannelEof cid) = lenWord8 + len cid
    put (ChannelEof cid) = putWord8 96 >> put cid
    get = BA.byte 96 >> ChannelEof <$> get

instance B.Binary ChannelClose where
    len (ChannelClose cid) = lenWord8 + len cid
    put (ChannelClose cid) = putWord8 97 >> put cid
    get = BA.byte 97 >> ChannelClose <$> get

instance B.Binary ChannelRequest where
    len (ChannelRequest cid req) = lenWord8 + len cid + len req
    put (ChannelRequest cid req) = putWord8 98 >> put cid >> put req
    get = BA.byte 98 >> ChannelRequest <$> get

instance Encoding ChannelRequestRequest where
    len = \case
        ChannelRequestEnv wantReply name value ->
            lenString "env" + lenBool + lenString name + lenString value
        ChannelRequestPty wantReply ts ->
            lenString "pty-req" + lenBool + len ts
        ChannelRequestShell wantReply ->
            lenString "shell" + lenBool
        ChannelRequestExec wantReply command ->
            lenString "exec" + lenBool + lenString command
        ChannelRequestExitStatus status ->
            lenString "exit-status" + lenBool + lenWord32
        ChannelRequestExitSignal signame _ errmsg lang ->
            lenString "exit-signal" + lenBool + lenString signame +
            lenBool + lenString errmsg + lenString lang
        ChannelRequestOther other ->
            lenString other
    put = \case
        ChannelRequestEnv wantReply name value ->
            putString "env" >> putBool wantReply >> putString name >> putString value
        ChannelRequestPty wantReply ts ->
            putString "pty-req" >> putBool wantReply >> put ts
        ChannelRequestShell wantReply ->
            putString "shell" >> putBool wantReply
        ChannelRequestExec wantReply command ->
            putString "exec" >> putBool wantReply >> putString command
        ChannelRequestExitStatus status ->
            putString "exit-status" >> putBool False >> put status
        ChannelRequestExitSignal signame coredump errmsg lang ->
            putString "exit-signal" >> putBool False >> putString signame >>
            putBool coredump >> putString errmsg >> putString lang
        ChannelRequestOther other -> mconcat
            putString other
    get = getString >>= \case
        "env" ->
            ChannelRequestEnv <$> getBool <*> getString <*> getString
        "pty-req" ->
            ChannelRequestPty <$> getBool <*> B.get
        "shell" ->
            ChannelRequestShell <$> getBool
        "exec" ->
            ChannelRequestExec <$> getBool <*> getString
        "exit-status" ->
            getFalse >> ChannelRequestExitStatus <$> get
        "exit-signal" ->
            getFalse >> ChannelRequestExitSignal <$> getString <*> getBool <*> getString <*> getString
        other ->
            pure (ChannelRequestOther other)

instance B.Binary ChannelSuccess where
    len (ChannelSuccess cid) = lenWord8 + len cid
    put (ChannelSuccess cid) = putWord8 99 >> put cid
    get = BA.byte 99 >> ChannelSuccess <$> get

instance B.Binary ChannelFailure where
    len (ChannelFailure cid) = lenWord8 + len cid
    put (ChannelFailure cid) = putWord8 100 >> put cid
    get = BA.byte 100 >> ChannelFailure <$> get

instance B.Binary Cookie where
    len _ = 16
    put (Cookie s) = BA.putBytes 16
    get = Cookie <$> BA.take 16

instance B.Binary Algorithm where
    put (Algorithm s) = putString s
    get = Algorithm <$> getString

instance B.Binary ChannelId where
    len (ChannelId x) = len x
    put (ChannelId x) = put x
    get = ChannelId <$> get

instance B.Binary ChannelWindowSize where
    len (ChannelWindowSize x) = lenWord32 x
    put (ChannelWindowSize x) = putWord32 x
    get = ChannelWindowSize <$> getWord32

instance B.Binary ChannelPacketSize where
    len (ChannelPacketSize x) = lenWord32 x
    put (ChannelPacketSize x) = putWord32 x
    get = ChannelPacketSize <$> getWord32

instance B.Binary ChannelType where
    len (ChannelType x) = lenString x
    put (ChannelType x) = putString x
    get = ChannelType <$> getString

instance B.Binary SessionId where
    len (SessionId x) = lenString x
    put (SessionId x) = putString x
    get = SessionId <$> getString

instance B.Binary ServiceName where
    len (ServiceName x) = lenString x
    put (ServiceName x) = putString x
    get = ServiceName <$> getString

instance B.Binary UserName where
    len (UserName x) = lenString x
    put (UserName x) = putString x
    get = UserName <$> getString

instance B.Binary Version where
    len (Version x) = fromIntegral (BA.length x) + 2
    put (Version x) = BA.putBytes x >> putWord8 0x0d >> putWord8 >> 0x0a
    put (Version x) = B.putByteString x <> B.putWord16be 0x0d0a
    get = do
      mapM_ BA.byte magic
      untilCRLF 0 (reverse magic)
      where
        magic :: Word8
        magic  = [0x53,0x53,0x48,0x2d,0x32,0x2e,0x30,0x2d]
        untilCRLF !i !xs
            | i >= (255 :: Int) = fail ""
            | otherwise = B.getWord8 >>= \case
                0x0d -> BA.byte 0x0a >>= pure (Version $ BS.pack $ reverse xs)
                x    -> untilCRLF (i+1) (x:xs)

instance B.Binary AuthMethod where
    len = \case
        AuthNone ->
            lenString "none"
        AuthHostBased ->
            lenString "hostbased"
        AuthPassword (Password pw) ->
            lenString "password" + lenBool + lenString pw
        AuthPublicKey (Algorithm algo) pk msig ->
            lenString "publickey" + lenBool + lenString algo + len pk + maybe 0 len sig
    put = \case
        AuthNone ->
            putString "none"
        AuthHostBased -> mconcat
            putString "hostbased"
        AuthPassword (Password pw) ->
            putString "password" >> putBool False >> putString pw
        AuthPublicKey (Algorithm algo) pk msig ->
            putString "publickey" >> case msig of
                Nothing -> putBool False >> putString algo >> put pk
                Just sig -> putBool True >> putString algo >> put pk >> put sig
    get = getString >>= \case
        "none" ->
            pure AuthNone
        "hostbased" ->
            pure AuthHostBased
        "password" ->
            void getBool >> AuthPassword  <$> (Password <$> getString)
        "publickey" -> do
            signed <- getBool
            algo   <- Algorithm <$> getString
            key    <- get
            msig   <- if signed then Just <$> get else pure Nothing
            pure (AuthPublicKey algo key msig)
        other       -> fail $ "Unknown AuthMethod " ++ show other

instance B.Binary PublicKey where
    len = \case
        PublicKeyEd25519 key ->
            lenWord32 + lenString "ssh-ed25519" + lenString key
        PublicKeyRSA ->
            undefined
    put k = putWord32 (len k) >> case k of
        PublicKeyEd25519 key ->
            putString "ssh-ed25519" >> putString key
        PublicKeyRSA (RSA.PublicKey _ n e) ->
            putString "ssh-rsa" >> putInteger n >> putInteger e
    get = getWord32 >> getString >>= \case
        "ssh-ed25519" ->
            Ed25519.publicKey <$> getString >>= \case
                CryptoPassed k -> pure (PublicKeyEd25519 k)
                CryptoFailed _ -> fail ""
        "ssh-rsa" -> do
            (n,_) <- getIntegerAndSize
            (e,s) <- getIntegerAndSize
            pure $ PublicKeyRSA $ RSA.PublicKey s n e
        other -> fail $ "Unknown pubkey algorithm " ++ show other

instance B.Binary Signature where
    len = \case
        SignatureEd25519    sig -> lenWord32 + lenString "ssh-ed25519" <> lenString sig
        SignatureRSA        sig -> lenWord32 + lenString "ssh-rsa"     <> lenString sig
        SignatureOther algo sig -> lenWord32 + lenString algo          <> lenString sig
    put s = putWord32 (len s)  >> case s of
        SignatureEd25519    sig -> putString "ssh-ed25519" <> putString sig
        SignatureRSA        sig -> putString "ssh-rsa"     <> putString sig
        SignatureOther algo sig -> putString algo          <> putString sig
    get = getWord32 >> getString >>= \case
        "ssh-ed25519" ->
            Ed25519.signature <$> getString >>= \case
                CryptoPassed s -> pure (SignatureEd25519 s)
                CryptoFailed _ -> fail ""
        "ssh-rsa" ->
            SignatureRSA <$> getString
        other ->
            SignatureOther other <$> getString

instance B.Binary PtySettings where
    len (PtySettings env __ __ __ __ modes) =
        lenString env + lenWord32 + lenWord32 + lenWord32 + lenWord32 + lenString modes
    put (PtySettings env wc hc wp hp modes) =
        putString env >> putWord32 wc >> putWord32 hc >> putWord32 wp >> putWord32 hp >> putString modes
    get =
        PtySettings <$> getString <*> getWord32 <*> getWord32 <*> getWord32 <*> getWord32 <*> getString

-------------------------------------------------------------------------------
-- Util functions
-------------------------------------------------------------------------------

getNameList :: (BA.ByteArray ba, BA.ByteArray name) => BA.Parser ba [name]
getNameList = do
    len <- fromIntegral <$> getWord32be
    BS.split 0x2c <$> B.getByteString len

putNameList :: [BS.ByteString] -> B.Put
putNameList xs =
    B.putWord32be (fromIntegral $ g xs)
    <> mconcat (B.putByteString <$> L.intersperse "," xs)
    where
        g [] = 0
        g ys = sum (BS.length <$> ys) + length ys - 1

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
