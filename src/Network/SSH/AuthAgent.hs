module Network.SSH.AuthAgent where

import qualified Data.ByteArray as BA
import qualified Crypto.PubKey.Ed25519  as Ed25519

import Network.SSH.Message
import Network.SSH.Key

-- | An `AuthAgent` is something that is capable of cryptographic signing
--   using a public key algorithm like Ed25519 or RSA.
--
--   Currently, `KeyPair` is the only instance, but the method
--   signatures have been designed with other mechanisms like HSM's
--   or agent-forwarding in mind.
class AuthAgent agent where
    -- | Get a list of public keys for which the agent holds the corresponding
    --   private keys.
    --
    --   The list contents may change when called subsequently.
    getPublicKeys :: agent -> IO [PublicKey]
    -- | Sign the given hash with the requested public key.
    --
    --   The signature may be denied in case the key is no longer available.
    --   This method shall not throw exceptions, but rather return `Nothing` if possible.
    getSignature :: BA.ByteArrayAccess hash => agent -> PublicKey -> hash -> IO (Maybe Signature)

instance AuthAgent KeyPair where
    getPublicKeys kp = case kp of
        KeyPairEd25519 pk _ -> pure [PublicKeyEd25519 pk]

    getSignature kp pk0 hash = case kp of
        KeyPairEd25519 pk sk
            | pk0 == PublicKeyEd25519 pk -> pure $ Just $ SignatureEd25519 $ Ed25519.sign sk pk hash
            | otherwise                  -> pure Nothing
