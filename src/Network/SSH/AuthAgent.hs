module Network.SSH.AuthAgent where

import qualified Data.ByteArray as BA
import qualified Crypto.PubKey.Ed25519  as Ed25519

import Network.SSH.Message
import Network.SSH.Key

data AuthAgent
    = AuthAgent
    { authKeyPair :: KeyPair
    }

fromKeyPair :: KeyPair -> AuthAgent
fromKeyPair = AuthAgent

getPublicKeys :: AuthAgent -> IO [PublicKey]
getPublicKeys agent = case authKeyPair agent of
    KeyPairEd25519 pk sk -> pure [PublicKeyEd25519 pk]

signHash :: BA.ByteArrayAccess ba => AuthAgent -> PublicKey -> ba -> IO (Maybe Signature)
signHash agent pk0 hash = case authKeyPair agent of
    KeyPairEd25519 pk sk
        | pk0 == PublicKeyEd25519 pk -> pure $ Just $ SignatureEd25519 $ Ed25519.sign sk pk hash
        | otherwise                  -> pure Nothing
