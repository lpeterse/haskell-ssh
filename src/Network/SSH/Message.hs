{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ExistentialQuantification  #-}
module Network.SSH.Message
  ( -- * Message
    Message (..)
  , ToMessage (..)
  , MessageStream (..)
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
    -- ** KexNewKeys (21)
  , KexNewKeys (..)
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
  , ChannelRequestEnv (..)
  , ChannelRequestPty (..)
  , ChannelRequestWindowChange (..)
  , ChannelRequestShell (..)
  , ChannelRequestExec (..)
  , ChannelRequestSignal (..)
  , ChannelRequestExitStatus (..)
  , ChannelRequestExitSignal (..)
    -- ** ChannelSuccess (99)
  , ChannelSuccess (..)
    -- ** ChannelFailure (100)
  , ChannelFailure (..)

    -- * Misc
  , Algorithm (..)
  , AuthMethod (..)
  , AuthMethodName (..)
  , ChannelId (..)
  , ChannelMaxPacketSize
  , ChannelType (..)
  , ChannelWindowSize
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

import           Control.Applicative
import           Control.Exception
import           Control.Monad            (void)
import           Crypto.Error
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import           Crypto.Random
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import           Data.Foldable
import qualified Data.List                as L
import           Data.Typeable
import           Data.Word
import           System.Exit

import           Network.SSH.Encoding
import           Network.SSH.Key

class MessageStream a where
    sendMessage :: forall msg. Encoding msg => a -> msg -> IO ()
    receiveMessage :: forall msg. Encoding msg => a -> IO msg

class ToMessage a where
    toMessage :: a -> Message

instance ToMessage Message where
    toMessage = id

instance ToMessage Disconnect where
    toMessage = MsgDisconnect

instance ToMessage Ignore where
    toMessage = MsgIgnore

instance ToMessage Debug where
    toMessage = MsgDebug

instance ToMessage Unimplemented where
    toMessage = MsgUnimplemented

instance ToMessage ServiceRequest where
    toMessage = MsgServiceRequest

instance ToMessage ServiceAccept where
    toMessage = MsgServiceAccept

instance ToMessage KexInit where
    toMessage = MsgKexInit

instance ToMessage KexNewKeys where
    toMessage = MsgKexNewKeys

instance ToMessage KexEcdhInit where
    toMessage = MsgKexEcdhInit

instance ToMessage KexEcdhReply where
    toMessage = MsgKexEcdhReply

instance ToMessage UserAuthRequest where
    toMessage = MsgUserAuthRequest

instance ToMessage UserAuthFailure where
    toMessage = MsgUserAuthFailure

instance ToMessage UserAuthSuccess where
    toMessage = MsgUserAuthSuccess

instance ToMessage UserAuthBanner where
    toMessage = MsgUserAuthBanner

instance ToMessage UserAuthPublicKeyOk where
    toMessage = MsgUserAuthPublicKeyOk

instance ToMessage ChannelOpen where
    toMessage = MsgChannelOpen

instance ToMessage ChannelOpenConfirmation where
    toMessage = MsgChannelOpenConfirmation

instance ToMessage ChannelOpenFailure where
    toMessage = MsgChannelOpenFailure

instance ToMessage ChannelWindowAdjust where
    toMessage = MsgChannelWindowAdjust

instance ToMessage ChannelData where
    toMessage = MsgChannelData

instance ToMessage ChannelExtendedData where
    toMessage = MsgChannelExtendedData

instance ToMessage ChannelEof where
    toMessage = MsgChannelEof

instance ToMessage ChannelRequest where
    toMessage = MsgChannelRequest

instance ToMessage ChannelSuccess where
    toMessage = MsgChannelSuccess

instance ToMessage ChannelFailure where
    toMessage = MsgChannelFailure

data Message
    = MsgDisconnect              Disconnect
    | MsgIgnore                  Ignore
    | MsgUnimplemented           Unimplemented
    | MsgDebug                   Debug
    | MsgServiceRequest          ServiceRequest
    | MsgServiceAccept           ServiceAccept
    | MsgKexInit                 KexInit
    | MsgKexNewKeys              KexNewKeys
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
    | DisconnectOtherReason Word32
    deriving (Eq, Show, Typeable)

instance Exception Disconnect

data Ignore
    = Ignore
    deriving (Eq, Show)

data Unimplemented
    = Unimplemented Word32
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

data KexNewKeys
    = KexNewKeys
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
    = ChannelOpen ChannelType ChannelId ChannelWindowSize ChannelMaxPacketSize
    deriving (Eq, Show)

data ChannelOpenConfirmation
    = ChannelOpenConfirmation ChannelId ChannelId ChannelWindowSize ChannelMaxPacketSize
    deriving (Eq, Show)

data ChannelOpenFailure
    = ChannelOpenFailure ChannelId ChannelOpenFailureReason BS.ByteString BS.ByteString
    deriving (Eq, Show)

data ChannelOpenFailureReason
    = ChannelOpenAdministrativelyProhibited
    | ChannelOpenConnectFailed
    | ChannelOpenUnknownChannelType
    | ChannelOpenResourceShortage
    | ChannelOpenOtherFailure Word32
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
    = ChannelRequest
    { crChannel       :: ChannelId
    , crType          :: BS.ByteString
    , crWantReply     :: Bool
    , crData          :: BS.ByteString
    } deriving (Eq, Show)

data ChannelRequestEnv
    = ChannelRequestEnv
    { crVariableName  :: BS.ByteString
    , crVariableValue :: BS.ByteString
    } deriving (Eq, Show)

data ChannelRequestPty
    = ChannelRequestPty
    { crPtySettings   :: PtySettings
    } deriving (Eq, Show)

data ChannelRequestWindowChange
    = ChannelRequestWindowChange
    { crWidth         :: Word32
    , crHeight        :: Word32
    , crWidthPixels   :: Word32
    , crHeightPixels  :: Word32
    } deriving (Eq, Show)

data ChannelRequestShell
    = ChannelRequestShell
    deriving (Eq, Show)

data ChannelRequestExec
    = ChannelRequestExec
    { crCommand       :: BS.ByteString
    } deriving (Eq, Show)

data ChannelRequestSignal
    = ChannelRequestSignal
    { crSignal        :: BS.ByteString
    } deriving (Eq, Show)

data ChannelRequestExitStatus
    = ChannelRequestExitStatus
    { crExitStatus    :: ExitCode
    } deriving (Eq, Show)

data ChannelRequestExitSignal
    = ChannelRequestExitSignal
    { crSignalName    :: BS.ByteString
    , crCodeDumped    :: Bool
    , crErrorMessage  :: BS.ByteString
    , crLanguageTag   :: BS.ByteString
    } deriving (Eq, Show)

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
    | AuthOther BS.ByteString
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

newtype Cookie            = Cookie            BS.ByteString deriving (Eq, Ord, Show)

newCookie :: MonadRandom m => m Cookie
newCookie  = Cookie <$> getRandomBytes 16

nilCookie :: Cookie
nilCookie  = Cookie  $  BS.replicate 16 0

type ChannelWindowSize = Word32
type ChannelMaxPacketSize = Word32

newtype Version           = Version           BS.ByteString
    deriving (Eq, Ord, Show, Semigroup, Monoid, BA.ByteArrayAccess, BA.ByteArray)
newtype Algorithm         = Algorithm         BS.ByteString
    deriving (Eq, Ord, Show, Semigroup, Monoid, BA.ByteArrayAccess, BA.ByteArray)
newtype Password          = Password          BS.ByteString
    deriving (Eq, Ord, Show, Semigroup, Monoid, BA.ByteArrayAccess, BA.ByteArray)
newtype SessionId         = SessionId         BS.ByteString
    deriving (Eq, Ord, Show, Semigroup, Monoid, BA.ByteArrayAccess, BA.ByteArray)
newtype UserName          = UserName          BS.ByteString
    deriving (Eq, Ord, Show, Semigroup, Monoid, BA.ByteArrayAccess, BA.ByteArray)
newtype AuthMethodName    = AuthMethodName    BS.ByteString
    deriving (Eq, Ord, Show, Semigroup, Monoid, BA.ByteArrayAccess, BA.ByteArray)
newtype ServiceName       = ServiceName       BS.ByteString
    deriving (Eq, Ord, Show, Semigroup, Monoid, BA.ByteArrayAccess, BA.ByteArray)
newtype ChannelType       = ChannelType       BS.ByteString
    deriving (Eq, Ord, Show, Semigroup, Monoid, BA.ByteArrayAccess, BA.ByteArray)
newtype ChannelId         = ChannelId         Word32
    deriving (Eq, Ord, Show)

-------------------------------------------------------------------------------
-- Encoding instances
-------------------------------------------------------------------------------

instance Encoding Message where
    len = \case
        MsgDisconnect               x -> len x
        MsgIgnore                   x -> len x
        MsgUnimplemented            x -> len x
        MsgDebug                    x -> len x
        MsgServiceRequest           x -> len x
        MsgServiceAccept            x -> len x
        MsgKexInit                  x -> len x
        MsgKexNewKeys               x -> len x
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
        MsgKexNewKeys               x -> put x
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
        MsgDisconnect              <$> get <|>
        MsgIgnore                  <$> get <|>
        MsgUnimplemented           <$> get <|>
        MsgDebug                   <$> get <|>
        MsgServiceRequest          <$> get <|>
        MsgServiceAccept           <$> get <|>
        MsgKexInit                 <$> get <|>
        MsgKexNewKeys              <$> get <|>
        MsgKexEcdhInit             <$> get <|>
        MsgKexEcdhReply            <$> get <|>
        MsgUserAuthRequest         <$> get <|>
        MsgUserAuthFailure         <$> get <|>
        MsgUserAuthSuccess         <$> get <|>
        MsgUserAuthBanner          <$> get <|>
        MsgUserAuthPublicKeyOk     <$> get <|>
        MsgChannelOpen             <$> get <|>
        MsgChannelOpenConfirmation <$> get <|>
        MsgChannelOpenFailure      <$> get <|>
        MsgChannelWindowAdjust     <$> get <|>
        MsgChannelData             <$> get <|>
        MsgChannelExtendedData     <$> get <|>
        MsgChannelEof              <$> get <|>
        MsgChannelClose            <$> get <|>
        MsgChannelRequest          <$> get <|>
        MsgChannelSuccess          <$> get <|>
        MsgChannelFailure          <$> get <|> (MsgUnknown <$> getWord8)

instance Encoding Disconnect where
    len (Disconnect r d l) =
        lenWord8 + len r + lenString d + lenString l
    put (Disconnect r d l) = do
        putWord8 1
        put r
        putString d
        putString l
    get = do
        expectWord8 1
        Disconnect <$> get <*> getString <*> getString

instance Encoding DisconnectReason where
    len _ = lenWord32
    put r = putWord32 $ case r of
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
        DisconnectOtherReason n               -> n
    get = (<$> getWord32) $ \case
        1  -> DisconnectHostNotAllowedToConnect
        2  -> DisconnectProtocolError
        3  -> DisconnectKeyExchangeFailed
        4  -> DisconnectReserved
        5  -> DisconnectMacError
        6  -> DisconnectCompressionError
        7  -> DisconnectServiceNotAvailable
        8  -> DisconnectProtocolVersionNotSupported
        9  -> DisconnectHostKeyNotVerifiable
        10 -> DisconnectConnectionLost
        11 -> DisconnectByApplication
        12 -> DisconnectTooManyConnection
        13 -> DisconnectAuthCancelledByUser
        14 -> DisconnectNoMoreAuthMethodsAvailable
        15 -> DisconnectIllegalUsername
        r  -> DisconnectOtherReason r

instance Encoding Ignore where
    len _ = 1
    put _ = putWord8 2
    get   = expectWord8 2 >> pure Ignore

instance Encoding Unimplemented where
    len _ = lenWord8 + lenWord32
    put (Unimplemented w) = putWord8 3 >> putWord32 w
    get = expectWord8 3 >> Unimplemented <$> getWord32

instance Encoding Debug where
    len (Debug _ msg lang) = lenWord8 + lenBool + lenString msg + lenString lang
    put (Debug ad msg lang) = putWord8 4 >> putBool ad >> putString msg >> putString lang
    get = expectWord8 4 >> Debug <$> getBool <*> getString <*> getString

instance Encoding ServiceRequest where
    len (ServiceRequest name) = lenWord8 + len name
    put (ServiceRequest name) = putWord8 5 >> put name
    get = expectWord8 5 >> ServiceRequest <$> get

instance Encoding ServiceAccept where
    len (ServiceAccept name) = lenWord8 + len name
    put (ServiceAccept name) = putWord8 6 >> put name
    get = expectWord8 6 >> ServiceAccept <$> get

instance Encoding KexInit where
    len kex = lenWord8
        + len         (kexCookie                              kex)
        + lenNameList (kexAlgorithms                          kex)
        + lenNameList (kexServerHostKeyAlgorithms             kex)
        + lenNameList (kexEncryptionAlgorithmsClientToServer  kex)
        + lenNameList (kexEncryptionAlgorithmsServerToClient  kex)
        + lenNameList (kexMacAlgorithmsClientToServer         kex)
        + lenNameList (kexMacAlgorithmsServerToClient         kex)
        + lenNameList (kexCompressionAlgorithmsClientToServer kex)
        + lenNameList (kexCompressionAlgorithmsServerToClient kex)
        + lenNameList (kexLanguagesClientToServer             kex)
        + lenNameList (kexLanguagesServerToClient             kex)
        + lenBool
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
        expectWord8 20
        kex <- KexInit <$> get
            <*> getNameList <*> getNameList <*> getNameList <*> getNameList
            <*> getNameList <*> getNameList <*> getNameList <*> getNameList
            <*> getNameList <*> getNameList <*> getBool
        void getWord32 -- reserved for future extensions
        pure kex

instance Encoding KexNewKeys where
    len _ = lenWord8
    put _ = putWord8 21
    get   = expectWord8 21 >> pure KexNewKeys

instance Encoding KexEcdhInit where
    len (KexEcdhInit key) = lenWord8 + len key
    put (KexEcdhInit key) = putWord8 30 >> put key
    get = expectWord8 30 >> KexEcdhInit <$> get

instance Encoding KexEcdhReply where
    len (KexEcdhReply hkey ekey sig) =
        lenWord8 + len hkey + len ekey + len sig
    put (KexEcdhReply hkey ekey sig) = putWord8 31 >> put hkey >> put ekey >> put sig
    get = expectWord8 31 >> KexEcdhReply <$> get <*> get <*> get

instance Encoding UserAuthRequest where
    len (UserAuthRequest un sn am) = lenWord8 + len un + len sn + len am
    put (UserAuthRequest un sn am) = putWord8 50 >> put un >> put sn >> put am
    get = expectWord8 50 >> UserAuthRequest <$> get <*> get <*> get

instance Encoding UserAuthFailure where
    len (UserAuthFailure ms _) = lenWord8 + lenNameList ms + lenBool
    put (UserAuthFailure ms ps) = do
        putWord8 51
        putNameList ((\(AuthMethodName x)->x) <$> ms)
        putBool ps
    get =  do
        expectWord8 51
        UserAuthFailure <$> (fmap AuthMethodName <$> getNameList) <*> getBool

instance Encoding UserAuthSuccess where
    len UserAuthSuccess = lenWord8
    put UserAuthSuccess = putWord8 52
    get = expectWord8 52 >> pure UserAuthSuccess

instance Encoding UserAuthBanner where
    len (UserAuthBanner x y) = lenWord8 + lenString x + lenString y
    put (UserAuthBanner x y) = putWord8 53 >> putString x >> putString y
    get = expectWord8 53 >> UserAuthBanner <$> getString <*> getString

instance Encoding UserAuthPublicKeyOk where
    len (UserAuthPublicKeyOk alg pk) = lenWord8 + len alg + len pk
    put (UserAuthPublicKeyOk alg pk) = putWord8 60 >> put alg >> put pk
    get = expectWord8 60 >> UserAuthPublicKeyOk <$> get <*> get

instance Encoding ChannelOpen where
    len (ChannelOpen ct cid _ _) = lenWord8 + len ct + len cid + lenWord32 + lenWord32
    put (ChannelOpen ct cid ws ps) = do
        putWord8 90
        put ct
        put cid
        putWord32 ws
        putWord32 ps
    get = do
        expectWord8 90
        ChannelOpen
            <$> get
            <*> get
            <*> getWord32
            <*> getWord32

instance Encoding ChannelOpenConfirmation where
    len (ChannelOpenConfirmation a b _ _) = lenWord8 + len a + len b + lenWord32 + lenWord32
    put (ChannelOpenConfirmation a b ws ps) = do
        putWord8 91
        put a
        put b
        putWord32 ws
        putWord32 ps
    get = do
        expectWord8 91
        ChannelOpenConfirmation
            <$> get
            <*> get
            <*> getWord32
            <*> getWord32

instance Encoding ChannelOpenFailure where
    len (ChannelOpenFailure cid reason descr lang) =
        lenWord8 + len cid + len reason + lenString descr + lenString lang
    put (ChannelOpenFailure cid reason descr lang) = do
        putWord8 92
        put cid
        put reason
        putString descr
        putString lang
    get = do
        expectWord8 92
        ChannelOpenFailure <$> get <*> get <*> getString <*> getString

instance Encoding ChannelOpenFailureReason where
    len _ = lenWord32
    put r = putWord32 $ case r of
        ChannelOpenAdministrativelyProhibited -> 1
        ChannelOpenConnectFailed              -> 2
        ChannelOpenUnknownChannelType         -> 3
        ChannelOpenResourceShortage           -> 4
        ChannelOpenOtherFailure w32           -> w32
    get = (<$> getWord32) $ \case
        1   -> ChannelOpenAdministrativelyProhibited
        2   -> ChannelOpenConnectFailed
        3   -> ChannelOpenUnknownChannelType
        4   -> ChannelOpenResourceShortage
        w32 -> ChannelOpenOtherFailure w32

instance Encoding ChannelWindowAdjust where
    len (ChannelWindowAdjust cid _) = lenWord8 + len cid + lenWord32
    put (ChannelWindowAdjust cid ws) = putWord8 93 >> put cid >> putWord32 ws
    get = expectWord8 93 >> ChannelWindowAdjust <$> get <*> getWord32

instance Encoding ChannelData where
    len (ChannelData cid ba) = lenWord8 + len cid + lenString ba
    put (ChannelData cid ba) = putWord8 94 >> put cid >> putString ba
    get = expectWord8 94 >> ChannelData <$> get <*> getString

instance Encoding ChannelExtendedData where
    len (ChannelExtendedData cid _ ba) = lenWord8 + len cid + lenWord32 + lenString ba
    put (ChannelExtendedData cid x ba) = putWord8 95 >> put cid >> putWord32 x >> putString ba
    get = expectWord8 95 >> ChannelExtendedData <$> get <*> getWord32 <*> getString

instance Encoding ChannelEof where
    len (ChannelEof cid) = lenWord8 + len cid
    put (ChannelEof cid) = putWord8 96 >> put cid
    get = expectWord8 96 >> ChannelEof <$> get

instance Encoding ChannelClose where
    len (ChannelClose cid) = lenWord8 + len cid
    put (ChannelClose cid) = putWord8 97 >> put cid
    get = expectWord8 97 >> ChannelClose <$> get

instance Encoding ChannelRequest where
    len (ChannelRequest cid typ _     dat) = lenWord8 + len cid + lenString typ + lenBool + lenByteString dat
    put (ChannelRequest cid typ reply dat) = putWord8 98 >> put cid >> putString typ >> putBool reply >> putByteString dat
    get = expectWord8 98 >> ChannelRequest <$> get <*> getString <*> getBool <*> getRemainingByteString

instance Encoding ChannelRequestEnv where
    len (ChannelRequestEnv name value) = lenString name + lenString value
    put (ChannelRequestEnv name value) = putString name >> putString value
    get = ChannelRequestEnv <$> getString <*> getString

instance Encoding ChannelRequestPty where
    len (ChannelRequestPty settings) = len settings
    put (ChannelRequestPty settings) = put settings
    get = ChannelRequestPty <$> get

instance Encoding ChannelRequestWindowChange where
    len _ = 4 * lenWord32
    put (ChannelRequestWindowChange x0 x1 x2 x3) = putWord32 x0 >> putWord32 x1 >> putWord32 x2 >> putWord32 x3
    get = ChannelRequestWindowChange <$> getWord32 <*> getWord32 <*> getWord32 <*> getWord32

instance Encoding ChannelRequestShell where
    len _ = 0
    put _ = pure ()
    get   = pure ChannelRequestShell

instance Encoding ChannelRequestExec where
    len (ChannelRequestExec command) = lenString command
    put (ChannelRequestExec command) = putString command
    get = ChannelRequestExec <$> getString

instance Encoding ChannelRequestSignal where
    len (ChannelRequestSignal signame) = lenString signame
    put (ChannelRequestSignal signame) = putString signame
    get = ChannelRequestSignal <$> getString

instance Encoding ChannelRequestExitStatus where
    len (ChannelRequestExitStatus code) = len code
    put (ChannelRequestExitStatus code) = put code
    get = ChannelRequestExitStatus <$> get

instance Encoding ChannelRequestExitSignal where
    len (ChannelRequestExitSignal signame core msg lang) = lenString signame + lenBool + lenString msg + lenString lang
    put (ChannelRequestExitSignal signame core msg lang) = putString signame >> putBool core >> putString msg >> putString lang
    get = ChannelRequestExitSignal <$> getString <*> getBool <*> getString <*> getString

instance Encoding ChannelSuccess where
    len (ChannelSuccess cid) = lenWord8 + len cid
    put (ChannelSuccess cid) = putWord8 99 >> put cid
    get = expectWord8 99 >> (ChannelSuccess <$> get)

instance Encoding ChannelFailure where
    len (ChannelFailure cid) = lenWord8 + len cid
    put (ChannelFailure cid) = putWord8 100 >> put cid
    get = expectWord8 100 >> (ChannelFailure <$> get)

instance Encoding Cookie where
    len _ = 16
    put (Cookie s) = putBytes s
    get = Cookie <$> getBytes 16

instance Encoding Algorithm where
    len (Algorithm s) = lenString s
    put (Algorithm s) = putString s
    get = Algorithm <$> getString

instance Encoding ChannelId where
    len (ChannelId _) = lenWord32
    put (ChannelId x) = putWord32 x
    get = ChannelId <$> getWord32

instance Encoding ChannelType where
    len (ChannelType x) = lenString x
    put (ChannelType x) = putString x
    get = ChannelType <$> getString

instance Encoding SessionId where
    len (SessionId x) = lenString x
    put (SessionId x) = putString x
    get = SessionId <$> getString

instance Encoding ServiceName where
    len (ServiceName x) = lenString x
    put (ServiceName x) = putString x
    get = ServiceName <$> getString

instance Encoding UserName where
    len (UserName x) = lenString x
    put (UserName x) = putString x
    get = UserName <$> getString

instance Encoding Version where
    len (Version x) =
        lenBytes x + 2
    put (Version x) = do
        putBytes x
        putWord8 0x0d
        putWord8 0x0a
    get = do
      mapM_ expectWord8 magic
      untilCRLF 0 (reverse magic)
      where
        magic :: [Word8]
        magic  = [0x53,0x53,0x48,0x2d,0x32,0x2e,0x30,0x2d]
        untilCRLF !i !xs
            | i >= (246 :: Int) = fail ""
            | otherwise = getWord8 >>= \case
                0x0d -> getWord8 >>= \case
                    0x0a -> pure (Version $ BS.pack $ reverse xs)
                    _ -> fail ""
                x -> untilCRLF (i+1) (x:xs)

instance Encoding AuthMethod where
    len = \case
        AuthNone ->
            lenString ("none" :: BS.ByteString)
        AuthHostBased ->
            lenString ("hostbased" :: BS.ByteString)
        AuthPassword (Password pw) ->
            lenString ("password" :: BS.ByteString) + lenBool + lenString pw
        AuthPublicKey (Algorithm algo) pk msig ->
            lenString ("publickey" :: BS.ByteString) + lenBool + lenString algo + len pk + maybe 0 len msig
        AuthOther other ->
            lenString other
    put = \case
        AuthNone ->
            putString ("none" :: BS.ByteString)
        AuthHostBased ->
            putString ("hostbased" :: BS.ByteString)
        AuthPassword (Password pw) ->
            putString ("password" :: BS.ByteString) >> putBool False >> putString pw
        AuthPublicKey (Algorithm algo) pk msig ->
            putString ("publickey" :: BS.ByteString) >> case msig of
                Nothing -> putBool False >> putString algo >> put pk
                Just sig -> putBool True >> putString algo >> put pk >> put sig
        AuthOther other ->
            putString other
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
        other -> pure (AuthOther other)

instance Encoding PublicKey where
    len = \case
        PublicKeyEd25519 key ->
            lenWord32 + lenString ("ssh-ed25519" :: BS.ByteString) + len key
        PublicKeyRSA key ->
            lenWord32 + lenString ("ssh-rsa" :: BS.ByteString) + len key
        PublicKeyOther other ->
            lenWord32 + lenString other
    put k = putWord32 (len k - lenWord32) >> case k of
        PublicKeyEd25519 key ->
            putString ("ssh-ed25519" :: BS.ByteString) >> put key
        PublicKeyRSA key ->
            putString ("ssh-rsa" :: BS.ByteString) >> put key
        PublicKeyOther other ->
            putString other
    get = getFramed $ getString >>= \case
        "ssh-ed25519" -> PublicKeyEd25519 <$> get
        "ssh-rsa"     -> PublicKeyRSA <$> get
        other         -> PublicKeyOther <$> pure other

instance Encoding Signature where
    len = \case
        SignatureEd25519    sig -> lenWord32 + lenString ("ssh-ed25519" :: BS.ByteString) + len       sig
        SignatureRSA        sig -> lenWord32 + lenString ("ssh-rsa"     :: BS.ByteString) + lenString sig -- FIXME
        SignatureOther algo sig -> lenWord32 + lenString algo          + lenString sig -- FIXME
    put s = putWord32 (len s - lenWord32) >> case s of
        SignatureEd25519    sig -> putString ("ssh-ed25519" :: BS.ByteString) >> put       sig
        SignatureRSA        sig -> putString ("ssh-rsa"     :: BS.ByteString) >> putString sig -- FIXME
        SignatureOther algo sig -> putString algo                             >> putString sig -- FIXME
    get = getFramed $ getString >>= \case
        "ssh-ed25519" -> SignatureEd25519 <$> get
        "ssh-rsa"     -> SignatureRSA <$> getString --FIXME
        other         -> SignatureOther other <$> getString

instance Encoding PtySettings where
    len (PtySettings env _ _ _ _ modes) =
        lenString env + lenWord32 + lenWord32 + lenWord32 + lenWord32 + lenString modes
    put (PtySettings env wc hc wp hp modes) =
        putString env >> putWord32 wc >> putWord32 hc >> putWord32 wp >> putWord32 hp >> putString modes
    get =
        PtySettings <$> getString <*> getWord32 <*> getWord32 <*> getWord32 <*> getWord32 <*> getString

-------------------------------------------------------------------------------
-- Util functions
-------------------------------------------------------------------------------

lenNameList :: (BA.ByteArray name) => [name] -> Word32
lenNameList xs = lenWord32 + fromIntegral (g xs)
    where
        g [] = 0
        g ys = sum (BA.length <$> ys) + length ys - 1

putNameList :: (BA.ByteArray name) => [name] -> Put
putNameList xs = do
    putWord32 $ fromIntegral $ g xs
    mapM_ putBytes $ L.intersperse (BA.singleton 0x2c) xs
    where
        g [] = 0
        g ys = sum (BA.length <$> ys) + length ys - 1

getNameList :: (BA.ByteArray name) => Get [name]
getNameList = do
    s <- getString :: Get BS.ByteString
    pure $ BA.convert <$> BS.split 0x2c s

instance Encoding Curve25519.PublicKey where
    len = lenString
    put = putString
    get = getString >>= \s-> case Curve25519.publicKey (s :: BA.Bytes) of
        CryptoPassed k -> pure k
        CryptoFailed _ -> fail ""

instance Encoding Ed25519.PublicKey where
    len = lenString
    put = putString
    get = getString >>= \s-> case Ed25519.publicKey (s :: BA.Bytes) of
        CryptoPassed k -> pure k
        CryptoFailed _ -> fail ""

instance Encoding Ed25519.Signature where
    len = lenString
    put = putString
    get = getString >>= \s-> case Ed25519.signature (s :: BA.Bytes) of
        CryptoPassed k -> pure k
        CryptoFailed _ -> fail ""

instance Encoding RSA.PublicKey where
    len x = lenBytes (runPut $ put x :: BS.ByteString)
    put (RSA.PublicKey _ n e) = do
        putInteger n
        putInteger e
        where
          putInteger :: Integer -> Put
          putInteger x = putString bs
              where
                  bs      = BA.pack $ g $ f x [] :: BS.ByteString
                  f 0 acc = acc
                  f i acc = let (q,r) = quotRem i 256
                            in  f q (fromIntegral r : acc)
                  g []        = []
                  g yys@(y:_) | y > 128   = 0:yys
                              | otherwise = yys
    get = do
        (n,_) <- getIntegerAndSize
        (e,s) <- getIntegerAndSize
        pure $ RSA.PublicKey s n e
        where
            -- Observing the encoded length is far cheaper than calculating the
            -- log2 of the resulting integer.
            getIntegerAndSize :: Get (Integer, Int)
            getIntegerAndSize = do
              ws <- dropWhile (== 0) . (BA.unpack :: BS.ByteString -> [Word8]) <$> getString -- eventually remove leading 0 byte
              pure (foldl' (\acc w8-> acc * 256 + fromIntegral w8) 0 ws, length ws * 8)
