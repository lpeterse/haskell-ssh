{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ExistentialQuantification  #-}
module Network.SSH.Message
  ( -- * Message
    Message (..)
  , MessageStream (..)
    -- ** Disconnected (1)
  , Disconnected (..)
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
  , ChannelOpenType (..)
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
  , AuthMethod (..)
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
import           Control.Monad            (void)
import           Crypto.Error
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import           Crypto.Random
import qualified Data.ByteArray           as BA
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Short    as SBS
import           Data.Foldable
import           Data.Typeable
import           Data.Word
import           System.Exit

import qualified Network.SSH.Builder as B
import           Network.SSH.Exception
import           Network.SSH.Encoding
import           Network.SSH.Key
import           Network.SSH.Name

class MessageStream a where
    sendMessage :: forall msg. Encoding msg => a -> msg -> IO ()
    receiveMessage :: forall msg. Encoding msg => a -> IO msg

data Message
    = MsgDisconnect              Disconnected
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

data Disconnected
    = Disconnected
    { disconnectedReason      :: DisconnectReason
    , disconnectedDescription :: SBS.ShortByteString
    , disconnectedLanguageTag :: SBS.ShortByteString
    }
    deriving (Eq, Show, Typeable)

data Ignore
    = Ignore
    deriving (Eq, Show)

data Unimplemented
    = Unimplemented Word32
    deriving (Eq, Show)

data Debug
    = Debug
    { debugAlwaysDisplay :: Bool
    , debugMessage       :: SBS.ShortByteString
    , debugLanguageTag   :: SBS.ShortByteString
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
    , kexKexAlgorithms                       :: [Name]
    , kexServerHostKeyAlgorithms             :: [Name]
    , kexEncryptionAlgorithmsClientToServer  :: [Name]
    , kexEncryptionAlgorithmsServerToClient  :: [Name]
    , kexMacAlgorithmsClientToServer         :: [Name]
    , kexMacAlgorithmsServerToClient         :: [Name]
    , kexCompressionAlgorithmsClientToServer :: [Name]
    , kexCompressionAlgorithmsServerToClient :: [Name]
    , kexLanguagesClientToServer             :: [Name]
    , kexLanguagesServerToClient             :: [Name]
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
    = UserAuthFailure [Name] Bool
    deriving (Eq, Show)

data UserAuthSuccess
    = UserAuthSuccess
    deriving (Eq, Show)

data UserAuthBanner
    = UserAuthBanner SBS.ShortByteString SBS.ShortByteString
    deriving (Eq, Show)

data UserAuthPublicKeyOk
    = UserAuthPublicKeyOk PublicKey
    deriving (Eq, Show)

data ChannelOpen
    = ChannelOpen ChannelId ChannelWindowSize ChannelMaxPacketSize ChannelOpenType
    deriving (Eq, Show)

data ChannelOpenType
    = ChannelOpenSession
    | ChannelOpenDirectTcpIp
    { coDestinationAddress :: SBS.ShortByteString
    , coDestinationPort    :: Word32
    , coSourceAddress      :: SBS.ShortByteString
    , coSourcePort         :: Word32
    }
    | ChannelOpenOther ChannelType
    deriving (Eq, Show)

data ChannelOpenConfirmation
    = ChannelOpenConfirmation ChannelId ChannelId ChannelWindowSize ChannelMaxPacketSize
    deriving (Eq, Show)

data ChannelOpenFailure
    = ChannelOpenFailure ChannelId ChannelOpenFailureReason SBS.ShortByteString SBS.ShortByteString
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
    = ChannelData ChannelId SBS.ShortByteString
    deriving (Eq, Show)

data ChannelExtendedData
    = ChannelExtendedData ChannelId Word32 SBS.ShortByteString
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
    , crType          :: SBS.ShortByteString
    , crWantReply     :: Bool
    , crData          :: BS.ByteString
    } deriving (Eq, Show)

data ChannelRequestEnv
    = ChannelRequestEnv
    { crVariableName  :: SBS.ShortByteString
    , crVariableValue :: SBS.ShortByteString
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
    { crCommand       :: SBS.ShortByteString
    } deriving (Eq, Show)

data ChannelRequestSignal
    = ChannelRequestSignal
    { crSignal        :: SBS.ShortByteString
    } deriving (Eq, Show)

data ChannelRequestExitStatus
    = ChannelRequestExitStatus
    { crExitStatus    :: ExitCode
    } deriving (Eq, Show)

data ChannelRequestExitSignal
    = ChannelRequestExitSignal
    { crSignalName    :: SBS.ShortByteString
    , crCodeDumped    :: Bool
    , crErrorMessage  :: SBS.ShortByteString
    , crLanguageTag   :: SBS.ShortByteString
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
    | AuthPublicKey PublicKey (Maybe Signature)
    | AuthOther     Name
    deriving (Eq, Show)

instance HasName AuthMethod where
    name AuthNone         = Name "none"
    name AuthHostBased    = Name "hostbased"
    name AuthPassword {}  = Name "password"
    name AuthPublicKey {} = Name "publickey"
    name (AuthOther n)    = n

data Signature
    = SignatureEd25519 Ed25519.Signature
    | SignatureRSA     BS.ByteString
    | SignatureOther   Name
    deriving (Eq, Show)

instance HasName Signature where
    name SignatureEd25519 {} = Name "ssh-ed25519"
    name SignatureRSA {}     = Name "ssh-rsa"
    name (SignatureOther n)  = n

data PtySettings
    = PtySettings
    { ptyEnv          :: SBS.ShortByteString
    , ptyWidthCols    :: Word32
    , ptyHeightRows   :: Word32
    , ptyWidthPixels  :: Word32
    , ptyHeightPixels :: Word32
    , ptyModes        :: SBS.ShortByteString
    } deriving (Eq, Show)


type ChannelWindowSize = Word32
type ChannelMaxPacketSize = Word32

newtype Cookie            = Cookie            SBS.ShortByteString
    deriving (Eq, Ord, Show)
newtype Version           = Version           SBS.ShortByteString
    deriving (Eq, Ord, Show)
newtype Password          = Password          SBS.ShortByteString
    deriving (Eq, Ord, Show)
newtype SessionId         = SessionId         SBS.ShortByteString
    deriving (Eq, Ord, Show)
newtype UserName          = UserName          SBS.ShortByteString
    deriving (Eq, Ord, Show)
newtype ServiceName       = ServiceName       SBS.ShortByteString
    deriving (Eq, Ord, Show)
newtype ChannelType       = ChannelType       SBS.ShortByteString
    deriving (Eq, Ord, Show)
newtype ChannelId         = ChannelId         Word32
    deriving (Eq, Ord, Show)

newCookie :: MonadRandom m => m Cookie
newCookie  = Cookie . SBS.toShort <$> getRandomBytes 16

nilCookie :: Cookie
nilCookie  = Cookie $ SBS.toShort $ BS.replicate 16 0

-------------------------------------------------------------------------------
-- Encoding instances
-------------------------------------------------------------------------------

instance Encoding Message where
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

instance Encoding Disconnected where
    put (Disconnected r d l) =
        putWord8 1 <>
        put r <>
        putShortString d <>
        putShortString l
    get = do
        expectWord8 1
        Disconnected <$> get <*> getShortString <*> getShortString

instance Encoding DisconnectReason where
    put r = B.word32BE $ case r of
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
    put _ = putWord8 2
    get   = expectWord8 2 >> pure Ignore

instance Encoding Unimplemented where
    put (Unimplemented w) = putWord8 3 <> B.word32BE w
    get = expectWord8 3 >> Unimplemented <$> getWord32

instance Encoding Debug where
    put (Debug ad msg lang) = putWord8 4 <> putBool ad <> putShortString msg <> putShortString lang
    get = expectWord8 4 >> Debug <$> getBool <*> getShortString <*> getShortString

instance Encoding ServiceRequest where
    put (ServiceRequest name) = putWord8 5 <> put name
    get = expectWord8 5 >> ServiceRequest <$> get

instance Encoding ServiceAccept where
    put (ServiceAccept name) = putWord8 6 <> put name
    get = expectWord8 6 >> ServiceAccept <$> get

instance Encoding KexInit where
    put kex =
        putWord8     20 <>
        put         (kexCookie                              kex) <>
        putNameList (kexKexAlgorithms                       kex) <>
        putNameList (kexServerHostKeyAlgorithms             kex) <>
        putNameList (kexEncryptionAlgorithmsClientToServer  kex) <>
        putNameList (kexEncryptionAlgorithmsServerToClient  kex) <>
        putNameList (kexMacAlgorithmsClientToServer         kex) <>
        putNameList (kexMacAlgorithmsServerToClient         kex) <>
        putNameList (kexCompressionAlgorithmsClientToServer kex) <>
        putNameList (kexCompressionAlgorithmsServerToClient kex) <>
        putNameList (kexLanguagesClientToServer             kex) <>
        putNameList (kexLanguagesServerToClient             kex) <>
        putBool     (kexFirstPacketFollows                  kex) <>
        B.word32BE 0 -- reserved for future extensions
    get = do
        expectWord8 20
        kex <- KexInit <$> get
            <*> getNameList <*> getNameList <*> getNameList <*> getNameList
            <*> getNameList <*> getNameList <*> getNameList <*> getNameList
            <*> getNameList <*> getNameList <*> getBool
        void getWord32 -- reserved for future extensions
        pure kex

instance Encoding KexNewKeys where
    put _ = putWord8 21
    get   = expectWord8 21 >> pure KexNewKeys

instance Encoding KexEcdhInit where
    put (KexEcdhInit key) = putWord8 30 <> put key
    get = expectWord8 30 >> KexEcdhInit <$> get

instance Encoding KexEcdhReply where
    put (KexEcdhReply hkey ekey sig) = putWord8 31 <> put hkey <> put ekey <> put sig
    get = expectWord8 31 >> KexEcdhReply <$> get <*> get <*> get

instance Encoding UserAuthRequest where
    put (UserAuthRequest un sn am) = putWord8 50 <> put un <> put sn <> put am
    get = expectWord8 50 >> UserAuthRequest <$> get <*> get <*> get

instance Encoding UserAuthFailure where
    put (UserAuthFailure ms ps) =
        putWord8 51 <>
        putNameList ms <>
        putBool ps
    get =  do
        expectWord8 51
        UserAuthFailure <$> getNameList <*> getBool

instance Encoding UserAuthSuccess where
    put UserAuthSuccess = putWord8 52
    get = expectWord8 52 >> pure UserAuthSuccess

instance Encoding UserAuthBanner where
    put (UserAuthBanner x y) = putWord8 53 <> putShortString x <> putShortString y
    get = expectWord8 53 >> UserAuthBanner <$> getShortString <*> getShortString

instance Encoding UserAuthPublicKeyOk where
    put (UserAuthPublicKeyOk pk) = putWord8 60 <> putName (name pk) <> put pk
    get = expectWord8 60 >> getName >> UserAuthPublicKeyOk <$> get

instance Encoding ChannelOpen where
    put (ChannelOpen rc rw rp ct) =
        putWord8 90 <>
        (case ct of
            ChannelOpenSession {} -> put (ChannelType "session")
            ChannelOpenDirectTcpIp {} -> put (ChannelType "direct-tcpip")
            ChannelOpenOther t -> put t ) <>
        put rc <>
        B.word32BE rw <>
        B.word32BE rp <>
        case ct of
            ChannelOpenSession {} -> mempty
            ChannelOpenDirectTcpIp da dp sa sp ->
                putShortString da <>
                B.word32BE dp <>
                putShortString sa <>
                B.word32BE sp
            ChannelOpenOther {} -> mempty
    get = do
        expectWord8 90
        ct <- get
        rc <- get
        rw <- getWord32
        rp <- getWord32
        ChannelOpen rc rw rp <$> case ct of
            ChannelType "session" ->
                pure ChannelOpenSession
            ChannelType "direct-tcpip" ->
                ChannelOpenDirectTcpIp
                    <$> getShortString
                    <*> getWord32
                    <*> getShortString
                    <*> getWord32
            other ->
                pure $ ChannelOpenOther other

instance Encoding ChannelOpenConfirmation where
    put (ChannelOpenConfirmation a b ws ps) =
        putWord8 91 <>
        put a <>
        put b <>
        B.word32BE ws <>
        B.word32BE ps
    get = do
        expectWord8 91
        ChannelOpenConfirmation
            <$> get
            <*> get
            <*> getWord32
            <*> getWord32

instance Encoding ChannelOpenFailure where
    put (ChannelOpenFailure cid reason descr lang) =
        putWord8 92 <>
        put cid <>
        put reason <>
        putShortString descr <>
        putShortString lang
    get = do
        expectWord8 92
        ChannelOpenFailure <$> get <*> get <*> getShortString <*> getShortString

instance Encoding ChannelOpenFailureReason where
    put r = B.word32BE $ case r of
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
    put (ChannelWindowAdjust cid ws) = putWord8 93 <> put cid <> B.word32BE ws
    get = expectWord8 93 >> ChannelWindowAdjust <$> get <*> getWord32

instance Encoding ChannelData where
    put (ChannelData cid ba) = putWord8 94 <> put cid <> putShortString ba
    get = expectWord8 94 >> ChannelData <$> get <*> getShortString

instance Encoding ChannelExtendedData where
    put (ChannelExtendedData cid x ba) = putWord8 95 <> put cid <> B.word32BE x <> putShortString ba
    get = expectWord8 95 >> ChannelExtendedData <$> get <*> getWord32 <*> getShortString

instance Encoding ChannelEof where
    put (ChannelEof cid) = putWord8 96 <> put cid
    get = expectWord8 96 >> ChannelEof <$> get

instance Encoding ChannelClose where
    put (ChannelClose cid) = putWord8 97 <> put cid
    get = expectWord8 97 >> ChannelClose <$> get

instance Encoding ChannelRequest where
    put (ChannelRequest cid typ reply dat) = putWord8 98 <> put cid <> putShortString typ <> putBool reply <> putByteString dat
    get = expectWord8 98 >> ChannelRequest <$> get <*> getShortString <*> getBool <*> getRemainingByteString

instance Encoding ChannelRequestEnv where
    put (ChannelRequestEnv name value) = putShortString name <> putShortString value
    get = ChannelRequestEnv <$> getShortString <*> getShortString

instance Encoding ChannelRequestPty where
    put (ChannelRequestPty settings) = put settings
    get = ChannelRequestPty <$> get

instance Encoding ChannelRequestWindowChange where
    put (ChannelRequestWindowChange x0 x1 x2 x3) = B.word32BE x0 <> B.word32BE x1 <> B.word32BE x2 <> B.word32BE x3
    get = ChannelRequestWindowChange <$> getWord32 <*> getWord32 <*> getWord32 <*> getWord32

instance Encoding ChannelRequestShell where
    put _ = mempty
    get   = pure ChannelRequestShell

instance Encoding ChannelRequestExec where
    put (ChannelRequestExec command) = putShortString command
    get = ChannelRequestExec <$> getShortString

instance Encoding ChannelRequestSignal where
    put (ChannelRequestSignal signame) = putShortString signame
    get = ChannelRequestSignal <$> getShortString

instance Encoding ChannelRequestExitStatus where
    put (ChannelRequestExitStatus code) = putExitCode code
    get = ChannelRequestExitStatus <$> getExitCode

instance Encoding ChannelRequestExitSignal where
    put (ChannelRequestExitSignal signame core msg lang) = putShortString signame <> putBool core <> putShortString msg <> putShortString lang
    get = ChannelRequestExitSignal <$> getShortString <*> getBool <*> getShortString <*> getShortString

instance Encoding ChannelSuccess where
    put (ChannelSuccess cid) = putWord8 99 <> put cid
    get = expectWord8 99 >> (ChannelSuccess <$> get)

instance Encoding ChannelFailure where
    put (ChannelFailure cid) = putWord8 100 <> put cid
    get = expectWord8 100 >> (ChannelFailure <$> get)

instance Encoding Cookie where
    put (Cookie s) = B.shortByteString s
    get = Cookie . SBS.toShort <$> getBytes 16

instance Encoding ChannelId where
    put (ChannelId x) = B.word32BE x
    get = ChannelId <$> getWord32

instance Encoding ChannelType where
    put (ChannelType x) = putShortString x
    get = ChannelType <$> getShortString

instance Encoding SessionId where
    put (SessionId x) = putShortString x
    get = SessionId <$> getShortString

instance Encoding ServiceName where
    put (ServiceName x) = putShortString x
    get = ServiceName <$> getShortString

instance Encoding UserName where
    put (UserName x) = putShortString x
    get = UserName <$> getShortString

instance Encoding Version where
    put (Version x) =
        B.shortByteString x <>
        putWord8 0x0d <>
        putWord8 0x0a
    get = do
      mapM_ expectWord8 magic
      untilCRLF 0 (reverse magic)
      where
        magic :: [Word8]
        magic  = [0x53,0x53,0x48,0x2d,0x32,0x2e,0x30,0x2d]
        untilCRLF !i !xs
            | i >= (246 :: Int) = fail mempty
            | otherwise = getWord8 >>= \case
                0x0d -> getWord8 >>= \case
                    0x0a -> pure (Version $ SBS.toShort $ BS.pack $ reverse xs)
                    _ -> fail mempty
                x -> untilCRLF (i+1) (x:xs)

instance Encoding AuthMethod where
    put m = putName (name m) <> case m of
        AuthNone -> mempty
        AuthHostBased -> mempty
        AuthPassword (Password pw) ->
            putBool False <> putShortString pw
        AuthPublicKey pk msig -> case msig of
            Nothing  -> putBool False <> putName (name pk) <> put pk
            Just sig -> putBool True <> putName (name pk) <> put pk <> put sig
        AuthOther {} -> mempty
    get = getName >>= \case
        Name "none" ->
            pure AuthNone
        Name "hostbased" ->
            pure AuthHostBased
        Name "password" ->
            void getBool >> AuthPassword  <$> (Password <$> getShortString)
        Name "publickey" -> do
            signed <- getBool
            void getShortString -- is redundant, ignore!
            key    <- get
            msig   <- if signed then Just <$> get else pure Nothing
            pure (AuthPublicKey key msig)
        other -> pure (AuthOther other)

instance Encoding PublicKey where
    put k = B.word32BE (len k - 4) <> putName (name k) <> case k of
        PublicKeyEd25519 key -> put key
        PublicKeyRSA     key -> putRsaPublicKey key
        PublicKeyOther other -> mempty
        where
            len = fromIntegral . B.length . put -- FIXME
    get = getFramed $ getName >>= \case
        Name "ssh-ed25519" -> PublicKeyEd25519 <$> get
        Name "ssh-rsa"     -> PublicKeyRSA <$> getRsaPublicKey
        other              -> PublicKeyOther <$> pure other

instance Encoding Signature where
    put s = B.word32BE (len s - 4) <> putName (name s) <> case s of
        SignatureEd25519    sig -> put       sig
        SignatureRSA        sig -> putString sig -- FIXME
        SignatureOther {}       -> mempty
        where
            len = fromIntegral . B.length . put -- FIXME
    get = getFramed $ getName >>= \case
        Name "ssh-ed25519" -> SignatureEd25519 <$> get
        Name "ssh-rsa"     -> SignatureRSA <$> getString --FIXME
        other              -> SignatureOther <$> pure other

instance Encoding PtySettings where
    put (PtySettings env wc hc wp hp modes) =
        putShortString env <> B.word32BE wc <> B.word32BE hc <> B.word32BE wp <> B.word32BE hp <> putShortString modes
    get =
        PtySettings <$> getShortString <*> getWord32 <*> getWord32 <*> getWord32 <*> getWord32 <*> getShortString

-------------------------------------------------------------------------------
-- Util functions
-------------------------------------------------------------------------------

putNameList :: (B.Builder b) => [Name] -> b
putNameList xs = B.word32BE (fromIntegral $ g xs) <> h xs
    where
        g [] = 0
        g ys = sum ((\(Name y) -> SBS.length y) <$> ys) + length ys - 1
        h [] = mempty
        h [Name y] = B.shortByteString y
        h (Name y:ys) = B.shortByteString y <> B.word8 0x2c <> h ys

getNameList :: Get [Name]
getNameList = do
    s <- getString :: Get BS.ByteString
    pure $ Name . SBS.toShort <$> BS.split 0x2c s

instance Encoding Curve25519.PublicKey where
    put = putString
    get = getString >>= \s-> case Curve25519.publicKey (s :: BA.Bytes) of
        CryptoPassed k -> pure k
        CryptoFailed _ -> fail ""

instance Encoding Ed25519.PublicKey where
    put = putString
    get = getString >>= \s-> case Ed25519.publicKey (s :: BA.Bytes) of
        CryptoPassed k -> pure k
        CryptoFailed _ -> fail ""

instance Encoding Ed25519.Signature where
    put = putString
    get = getString >>= \s-> case Ed25519.signature (s :: BA.Bytes) of
        CryptoPassed k -> pure k
        CryptoFailed _ -> fail ""

putRsaPublicKey :: B.Builder b => RSA.PublicKey -> b
putRsaPublicKey (RSA.PublicKey _ n e) =
    putInteger n <>
    putInteger e
    where
        putInteger x = putString bs
            where
                bs      = BA.pack $ g $ f x [] :: BS.ByteString
                f 0 acc = acc
                f i acc = let (q,r) = quotRem i 256
                        in  f q (fromIntegral r : acc)
                g []        = []
                g yys@(y:_) | y > 128   = 0:yys
                            | otherwise = yys

getRsaPublicKey :: Get RSA.PublicKey
getRsaPublicKey = do
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
