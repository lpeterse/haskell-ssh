{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE StandaloneDeriving         #-}

import           Crypto.Error
import qualified Crypto.PubKey.Curve25519 as Curve25519
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.Binary              as B
import qualified Data.Binary.Get          as B
import qualified Data.Binary.Put          as B
import qualified Data.ByteString          as BS

import           Test.Tasty
import           Test.Tasty.QuickCheck    as QC

import           Network.SSH.Message

main :: IO ()
main = defaultMain $ testGroup "Network.SSH.Message"
  [ testGroup "put . get == id"
    [ QC.testProperty ":: Disconnect"              (parserIdentity :: Disconnect              -> Property)
    , QC.testProperty ":: Ignore"                  (parserIdentity :: Ignore                  -> Property)
    , QC.testProperty ":: Unimplemented"           (parserIdentity :: Unimplemented           -> Property)
    , QC.testProperty ":: Debug"                   (parserIdentity :: Debug                   -> Property)
    , QC.testProperty ":: ServiceRequest"          (parserIdentity :: ServiceRequest          -> Property)
    , QC.testProperty ":: ServiceAccept"           (parserIdentity :: ServiceAccept           -> Property)
    , QC.testProperty ":: KexInit"                 (parserIdentity :: KexInit                 -> Property)
    , QC.testProperty ":: NewKeys"                 (parserIdentity :: NewKeys                 -> Property)
    , QC.testProperty ":: KexEcdhInit"             (parserIdentity :: KexEcdhInit             -> Property)
    , QC.testProperty ":: KexEcdhReply"            (parserIdentity :: KexEcdhReply            -> Property)
    , QC.testProperty ":: UserAuthRequest"         (parserIdentity :: UserAuthRequest         -> Property)
    , QC.testProperty ":: UserAuthFailure"         (parserIdentity :: UserAuthFailure         -> Property)
    , QC.testProperty ":: UserAuthSuccess"         (parserIdentity :: UserAuthSuccess         -> Property)
    , QC.testProperty ":: UserAuthBanner"          (parserIdentity :: UserAuthBanner          -> Property)
    , QC.testProperty ":: UserAuthPublicKeyOk"     (parserIdentity :: UserAuthPublicKeyOk     -> Property)
    , QC.testProperty ":: ChannelOpen"             (parserIdentity :: ChannelOpen             -> Property)
    , QC.testProperty ":: ChannelOpenConfirmation" (parserIdentity :: ChannelOpenConfirmation -> Property)
    , QC.testProperty ":: ChannelOpenFailure"      (parserIdentity :: ChannelOpenFailure      -> Property)
    , QC.testProperty ":: ChannelData"             (parserIdentity :: ChannelData             -> Property)
    , QC.testProperty ":: ChannelDataExtended"     (parserIdentity :: ChannelDataExtended     -> Property)
    , QC.testProperty ":: ChannelEof"              (parserIdentity :: ChannelEof              -> Property)
    , QC.testProperty ":: ChannelClose"            (parserIdentity :: ChannelClose            -> Property)
    , QC.testProperty ":: ChannelRequest"          (parserIdentity :: ChannelRequest          -> Property)
    , QC.testProperty ":: ChannelRequestSuccess"   (parserIdentity :: ChannelRequestSuccess   -> Property)
    , QC.testProperty ":: ChannelRequestFailure"   (parserIdentity :: ChannelRequestFailure   -> Property)

    , QC.testProperty ":: Version"                 (parserIdentity :: Version                 -> Property)
    , QC.testProperty ":: PublicKey"               (parserIdentity :: PublicKey               -> Property)
    , QC.testProperty ":: Signature"               (parserIdentity :: Signature               -> Property)
    , QC.testProperty ":: Message"                 (parserIdentity :: Message                 -> Property)
    ]
  ]
  where
    parserIdentity :: (B.Binary a, Eq a, Show a) => a -> Property
    parserIdentity x = x === B.runGet B.get (B.runPut $ B.put x)

instance Arbitrary BS.ByteString where
  arbitrary = pure mempty

instance Arbitrary Message where
  arbitrary = oneof
    [ MsgDisconnect              <$> arbitrary
    , MsgIgnore                  <$> arbitrary
    , MsgUnimplemented           <$> arbitrary
    , MsgDebug                   <$> arbitrary
    , MsgServiceRequest          <$> arbitrary
    , MsgServiceAccept           <$> arbitrary
    , MsgKexInit                 <$> arbitrary
    , MsgNewKeys                 <$> arbitrary
    , MsgKexEcdhInit             <$> arbitrary
    , MsgKexEcdhReply            <$> arbitrary
    , MsgUserAuthRequest         <$> arbitrary
    , MsgUserAuthFailure         <$> arbitrary
    , MsgUserAuthSuccess         <$> arbitrary
    , MsgUserAuthBanner          <$> arbitrary
    , MsgUserAuthPublicKeyOk     <$> arbitrary
    , MsgChannelOpen             <$> arbitrary
    , MsgChannelOpenConfirmation <$> arbitrary
    , MsgChannelOpenFailure      <$> arbitrary
    , MsgChannelData             <$> arbitrary
    , MsgChannelDataExtended     <$> arbitrary
    , MsgChannelEof              <$> arbitrary
    , MsgChannelClose            <$> arbitrary
    , MsgChannelRequest          <$> arbitrary
    , MsgChannelRequestSuccess   <$> arbitrary
    , MsgChannelRequestFailure   <$> arbitrary
    , MsgUnknown                 <$> elements [ 128, 255 ]
                                 <*> elements [ "", "unknown message payload" ]
    ]

instance Arbitrary Disconnect where
  arbitrary = Disconnect <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary Ignore where
  arbitrary = pure Ignore

instance Arbitrary Unimplemented where
  arbitrary = pure Unimplemented

instance Arbitrary Debug where
  arbitrary = Debug
    <$> arbitrary
    <*> elements [ "", "debug message", "debug message containing\n linefeeds\n\r" ]
    <*> elements [ "", "de_DE", "en_US" ]

instance Arbitrary ServiceRequest where
  arbitrary = ServiceRequest <$> arbitrary

instance Arbitrary ServiceAccept where
  arbitrary = ServiceAccept <$> arbitrary

instance Arbitrary KexInit where
  arbitrary = KexInit <$> arbitrary <*> nameList  <*> nameList  <*> nameList
                      <*> nameList  <*> nameList  <*> nameList  <*> nameList
                      <*> nameList  <*> nameList  <*> nameList  <*> arbitrary
    where
      nameList = elements [ [], ["abc"], ["abc","def"] ]

instance Arbitrary NewKeys where
  arbitrary = pure NewKeys

instance Arbitrary KexEcdhInit where
  arbitrary = KexEcdhInit <$> arbitrary

instance Arbitrary KexEcdhReply where
  arbitrary = KexEcdhReply <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary UserAuthRequest where
  arbitrary = UserAuthRequest <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary UserAuthFailure where
  arbitrary = UserAuthFailure <$> arbitrary <*> arbitrary

instance Arbitrary UserAuthSuccess where
  arbitrary = pure UserAuthSuccess

instance Arbitrary UserAuthBanner where
  arbitrary = UserAuthBanner <$> arbitrary <*> arbitrary

instance Arbitrary UserAuthPublicKeyOk where
  arbitrary = UserAuthPublicKeyOk <$> arbitrary <*> arbitrary

instance Arbitrary ChannelOpen where
  arbitrary = ChannelOpen <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ChannelOpenConfirmation where
  arbitrary = ChannelOpenConfirmation <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ChannelOpenFailure where
  arbitrary = ChannelOpenFailure <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ChannelData where
  arbitrary = ChannelData <$> arbitrary <*> arbitrary

instance Arbitrary ChannelDataExtended where
  arbitrary = ChannelDataExtended <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ChannelEof where
  arbitrary = ChannelEof <$> arbitrary

instance Arbitrary ChannelClose where
  arbitrary = ChannelClose <$> arbitrary

instance Arbitrary ChannelRequest where
  arbitrary = oneof
    [ ChannelRequestPty   <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    , ChannelRequestShell <$> arbitrary <*> arbitrary
    , ChannelRequestOther <$> arbitrary <*> arbitrary
    ]

instance Arbitrary ChannelRequestSuccess where
  arbitrary = ChannelRequestSuccess <$> arbitrary

instance Arbitrary ChannelRequestFailure where
  arbitrary = ChannelRequestFailure <$> arbitrary

instance Arbitrary Version where
  arbitrary = elements
    [ Version "SSH-2.0-OpenSSH_4.3"
    , Version "SSH-2.0-hssh_0.1"
    ]

deriving instance Arbitrary MaxPacketSize
deriving instance Arbitrary InitWindowSize
deriving instance Arbitrary ChannelId
deriving instance Arbitrary ChannelType

instance Arbitrary Cookie where
  arbitrary = pure nilCookie

instance Arbitrary Password where
  arbitrary = elements $ fmap Password
    [ "1234567890"
    ]

instance Arbitrary Algorithm where
  arbitrary = elements $ fmap Algorithm
    [ "ssh-ed25519"
    , "ssh-rsa"
    ]

instance Arbitrary UserName where
  arbitrary = elements $ fmap UserName
    [ "franz"
    , "franz-nord"
    ]

instance Arbitrary ServiceName where
  arbitrary = elements $ fmap ServiceName
    [ "ssh-connection"
    ]

instance Arbitrary AuthMethodName where
  arbitrary = elements $ fmap AuthMethodName
    [ "none"
    , "hostbased"
    , "password"
    , "publickey"
    ]

instance Arbitrary AuthMethod where
  arbitrary = oneof
    [ pure AuthNone
    , pure AuthHostBased
    , AuthPassword  <$> arbitrary
    , AuthPublicKey <$> arbitrary <*> arbitrary <*> arbitrary
    ]

instance Arbitrary PublicKey where
  arbitrary = oneof
    [ PublicKeyEd25519           <$> x1
    , PublicKeyRSA               <$> x2
    , PublicKeyOther "ssh-other" <$> x3
    ]
    where
      x1 = pure $ case Ed25519.publicKey ("$\149\229m\164\ETB\GSA\ESC\185ThTc8\212\219\158\249\CAN\202\245\133\140a\bZQ\v\234\247x" :: BS.ByteString) of
        CryptoPassed pk -> pk
        CryptoFailed _  -> undefined
      x2 = pure $ RSA.PublicKey 24 65537 2834792
      x3 = pure "PUBLIC_KEY_OTHER"

instance Arbitrary Signature where
  arbitrary = oneof
    [ SignatureEd25519           <$> x1
    , SignatureRSA               <$> x2
    , SignatureOther "ssh-other" <$> x3
    ]
    where
      x1 = pure $ case Ed25519.signature ("\169\150V0\235\151\ENQ\149w\DC1\172wKV]W|\b\ETB\f@\158\178\254\158\168\v>\180&\164D\DELF\204\133p\186\195(\169\177\144\168\STX\DC2\153!B\252\154o\251\230\154\164T\223\243\148'i\a\EOT" :: BS.ByteString) of
        CryptoPassed sig -> sig
        CryptoFailed _   -> undefined
      x2 = pure "SIGNATURE_RSA"
      x3 = pure "SIGNATURE_OTHER"

instance Arbitrary Curve25519.PublicKey where
  arbitrary = pure $ case Curve25519.publicKey ("\179g~\181\170\169\154\205\211\ft\162\&0@0dO\FS\DLEA\166@[r\150t~W\221cOF" :: BS.ByteString) of
    CryptoPassed pk -> pk
    CryptoFailed _  -> undefined
