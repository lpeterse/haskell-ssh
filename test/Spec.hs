{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE StandaloneDeriving         #-}
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519   as Ed25519
import qualified Crypto.PubKey.RSA       as RSA
import qualified Data.Binary.Get         as B
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Builder as BS

import           Test.Tasty
import           Test.Tasty.QuickCheck   as QC

import           Network.SSH.Message

main :: IO ()
main = defaultMain $ testGroup "Network.SSH.Message"
  [ QC.testProperty "id == getPublicKey . putPublicKey" $ \x->
      x === B.runGet getPublicKey (BS.toLazyByteString $ putPublicKey x)
  , QC.testProperty "id == getSignature . putSignature" $ \x->
      x === B.runGet getSignature (BS.toLazyByteString $ putSignature x)
  , QC.testProperty "id == getMessage   . putMessage" $ \x->
      x === B.runGet getMessage   (BS.toLazyByteString $ putMessage x)
  ]

instance Arbitrary BS.ByteString where
  arbitrary = pure mempty

instance Arbitrary Message where
  arbitrary = oneof
    [ Disconnect              <$> arbitrary <*> arbitrary <*> arbitrary
    , pure Ignore
    , pure Unimplemented
    , ServiceRequest          <$> arbitrary
    , ServiceAccept           <$> arbitrary
    , UserAuthRequest         <$> arbitrary <*> arbitrary <*> arbitrary
    , UserAuthFailure         <$> arbitrary <*> arbitrary
    , pure UserAuthSuccess
    , UserAuthBanner          <$> arbitrary <*> arbitrary
    , UserAuthPublicKeyOk     <$> arbitrary
    , ChannelOpen             <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    , ChannelOpenConfirmation <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    , ChannelOpenFailure      <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    , ChannelRequest          <$> arbitrary <*> arbitrary
    , ChannelRequestSuccess   <$> arbitrary
    , ChannelRequestFailure   <$> arbitrary
    , ChannelData             <$> arbitrary <*> arbitrary
    , ChannelDataExtended     <$> arbitrary <*> arbitrary <*> arbitrary
    , ChannelEof              <$> arbitrary
    , ChannelClose            <$> arbitrary
    ]

instance Arbitrary ChannelRequest where
  arbitrary = oneof
    [ ChannelRequestPTY   <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    , ChannelRequestShell <$> arbitrary
    , ChannelRequestOther <$> arbitrary
    ]

instance Arbitrary DisconnectReason where
  arbitrary = DisconnectReason <$> arbitrary

deriving instance Arbitrary MaxPacketSize
deriving instance Arbitrary InitWindowSize
deriving instance Arbitrary ChannelId
deriving instance Arbitrary ChannelType
deriving instance Arbitrary ChannelOpenFailureReason

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

instance Arbitrary MethodName where
  arbitrary = elements $ fmap MethodName
    [ "none"
    , "hostbased"
    , "password"
    , "publickey"
    ]

instance Arbitrary AuthenticationData where
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
