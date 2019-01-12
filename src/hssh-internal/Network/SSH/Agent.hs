module Network.SSH.Agent where

import           Control.Exception
import           Control.Monad
import qualified Crypto.PubKey.Ed25519            as Ed25519
import qualified Data.ByteArray                   as BA
import qualified Data.ByteString                  as BS
import qualified Data.ByteString.Char8            as BS8
import           Data.Maybe
import           Data.Word
import           Data.Default
import           System.Environment
import qualified System.Socket                    as S
import qualified System.Socket.Family.Unix        as S
import qualified System.Socket.Type.Stream        as S
import qualified System.Socket.Protocol.Default   as S

import           Network.SSH.Constants
import           Network.SSH.Key
import           Network.SSH.Stream
import           Network.SSH.Encoding
import           Network.SSH.Builder (word32BE)
import           Network.SSH.Message

type AgentSocket = S.Socket S.Unix S.Stream S.Default

newtype SignFlags = SignFlags Word32
    deriving (Eq, Ord, Show)

instance Default SignFlags where
    def = SignFlags 0

newtype Comment = Comment BS.ByteString
    deriving (Eq, Ord, Show)

-- | An `Agent` is something that is capable of cryptographic signing
--   using a public key algorithm like Ed25519 or RSA.
--
--   Currently, `KeyPair` is the only instance, but the method
--   signatures have been designed with other mechanisms like HSM's
--   or agent-forwarding in mind.
class Agent agent where
    -- | Get a list of public keys for which the agent holds the corresponding
    --   private keys.
    --
    --   The list contents may change when called subsequently.
    getIdentities :: agent -> IO [(PublicKey, Comment)]
    -- | Sign the given digest with the requested public key.
    --
    --   The signature may be denied in case the key is no longer available.
    --   This method shall not throw exceptions, but rather return `Nothing` if possible.
    signDigest :: BA.ByteArrayAccess digest => agent -> PublicKey -> digest -> SignFlags -> IO (Maybe Signature)

instance Agent KeyPair where
    getIdentities kp = case kp of
        KeyPairEd25519 pk _ -> pure [(PublicKeyEd25519 pk, Comment "")]

    signDigest kp pk0 digest _ = case kp of
        KeyPairEd25519 pk sk
            | pk0 == PublicKeyEd25519 pk -> pure $ Just $ SignatureEd25519 $ Ed25519.sign sk pk digest
            | otherwise                  -> pure Nothing

---------------------------------------------------------------------------------------------------
-- LOCAL AGENT
---------------------------------------------------------------------------------------------------

data LocalAgent = LocalAgent

instance Agent LocalAgent where
    getIdentities _ = runWithAgentSocket getIdentitiesLocal
    signDigest _ pk bytes flags = runWithAgentSocket $ \s ->
        signDigestLocal s pk bytes flags

runWithAgentSocket :: Default a => (AgentSocket -> IO a) -> IO a
runWithAgentSocket run = handleExceptions $ lookupEnv "SSH_AUTH_SOCK" >>= \case
    Nothing -> pure def
    Just p  -> case S.socketAddressUnixPath (BS8.pack p) of
        Nothing -> pure def
        Just a  -> bracket S.socket S.close $ \s -> do
            S.connect s a
            run s
    where
        handleExceptions = handle $ \e -> do
            let _ = e :: S.SocketException
            pure def

getResponse :: AgentSocket -> BS.ByteString -> IO BS.ByteString
getResponse s msg = do
    sendAll s $ runPut $ word32BE (fromIntegral $ BS.length msg)
    sendAll s msg
    header <- receiveAll s 4
    responseLen <- runGetter header getWord32
    -- Just in case we get off sync or the auth agent
    -- is malicious.
    when (responseLen > maxPacketLength)
        $ throwIO S.eConnectionReset
    receiveAll s (fromIntegral responseLen)

getIdentitiesLocal :: AgentSocket -> IO [(PublicKey, Comment)]
getIdentitiesLocal s = do
    response  <- getResponse s request
    pure $ fromMaybe mempty $ runGetter response do
        void getWord8
        n <- getWord32
        forM [1 .. n] $ const do
            pubkey <- getPublicKey
            comment <- Comment <$> getString
            pure (pubkey, comment)
    where
        request = runPut $ putWord8 11

signDigestLocal :: BA.ByteArrayAccess digest =>
    AgentSocket -> PublicKey -> digest -> SignFlags -> IO (Maybe Signature)
signDigestLocal s pk bytes (SignFlags flags) = do
    response <- getResponse s request
    pure $ runGetter response do
        getWord8 >>= \case
            14 -> getSignature
            _  -> fail mempty
    where
        request = runPut $
            putWord8 13 <>
            putPublicKey pk <>
            putString bytes <>
            word32BE flags
