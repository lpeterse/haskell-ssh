{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
module Network.SSH.Server.Transport.KeyExchange
  ( KexStep (..)
  , performInitialKeyExchange
  , newKexInit
  , deriveKeys
  ) where

import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TVar
import           Control.Exception            (throwIO)
import           Control.Monad                (void)
import           Control.Monad.STM            (atomically)
import qualified Crypto.Hash                  as Hash
import qualified Crypto.PubKey.Curve25519     as Curve25519
import qualified Crypto.PubKey.Ed25519        as Ed25519
import qualified Data.ByteArray               as BA
import           Data.List
import qualified Data.List.NonEmpty           as NEL
import           System.Clock

import           Network.SSH.Algorithms
import           Network.SSH.Encoding
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport

data KexStep
    = KexStart
    | KexProcessInit KexInit
    | KexProcessEcdhInit KexEcdhInit

performInitialKeyExchange ::
    Config identity -> Transport -> (Message -> IO ()) -> Version -> Version
    -> IO (Either Disconnect (SessionId, KexStep -> IO ()))
performInitialKeyExchange config transport enqueueMessage clientVersion serverVersion = do
    msid <- newEmptyMVar
    handler <- newKexStepHandler config transport clientVersion serverVersion enqueueMessage msid
    handler KexStart
    receiveMessage transport >>= \case
        Left d -> do
            onReceive config (MsgDisconnect d)
            pure (Left d)
        Right cki -> do
            onReceive config (MsgKexInit cki)
            handler (KexProcessInit cki)
            receiveMessage transport >>= \case
                Left d -> do
                    onReceive config (MsgDisconnect d)
                    pure (Left d)
                Right cei -> do
                    onReceive config (MsgKexEcdhInit cei)
                    handler (KexProcessEcdhInit cei)
                    session <- readMVar msid
                    pure $ Right (session, handler)

newKexStepHandler :: Config identity -> Transport -> Version -> Version
                  -> (Message -> IO ()) -> MVar SessionId -> IO (KexStep -> IO ())
newKexStepHandler config transport clientVersion serverVersion sendMsg msid = do
    continuation <- newEmptyMVar

    let noKexInProgress = \case
            KexStart -> do
                ski <- newKexInit config
                sendMsg (MsgKexInit ski)
                updateRekeyTracking transport
                void $ swapMVar continuation (waitingForKexInit ski)
            KexProcessInit cki -> do
                ski <- newKexInit config
                sendMsg (MsgKexInit ski)
                void $ swapMVar continuation (waitingForKexEcdhInit ski cki)
            KexProcessEcdhInit {} ->
                throwIO $ Disconnect DisconnectProtocolError "unexpected KexEcdhInit" mempty

        waitingForKexInit ski = \case
            KexStart -> do
                pure () -- already in progress
            KexProcessInit cki ->
                void $ swapMVar continuation (waitingForKexEcdhInit ski cki)
            KexProcessEcdhInit {} ->
                throwIO $ Disconnect DisconnectProtocolError "unexpected KexEcdhInit" mempty

        waitingForKexEcdhInit ski cki = \case
            KexStart -> do
                pure () -- already in progress
            KexProcessInit {} ->
                throwIO $ Disconnect DisconnectProtocolError "unexpected KexInit" mempty
            KexProcessEcdhInit (KexEcdhInit clientEphemeralPublicKey) -> do
                completeEcdhExchange ski cki clientEphemeralPublicKey
                void $ swapMVar continuation noKexInProgress

    putMVar continuation noKexInProgress
    pure $ \step-> do
            handle <- readMVar continuation
            handle step
        where
            completeEcdhExchange ski cki clientEphemeralPublicKey = do
                kexAlgorithm   <- commonKexAlgorithm   ski cki
                encAlgorithmCS <- commonEncAlgorithmCS ski cki
                encAlgorithmSC <- commonEncAlgorithmSC ski cki

                -- TODO: Dispatch here when implementing support for more algorithms.
                case (kexAlgorithm, encAlgorithmCS, encAlgorithmSC) of
                    (Curve25519Sha256AtLibsshDotOrg, Chacha20Poly1305AtOpensshDotCom, Chacha20Poly1305AtOpensshDotCom) ->
                        completeCurve25519KeyExchange ski cki clientEphemeralPublicKey

            completeCurve25519KeyExchange ski cki clientEphemeralPublicKey = do
                -- Generate a Curve25519 keypair for elliptic curve Diffie-Hellman key exchange.
                serverEphemeralSecretKey <- Curve25519.generateSecretKey
                serverEphemeralPublicKey <- pure $ Curve25519.toPublic serverEphemeralSecretKey

                KeyPairEd25519 pubKey secKey <- do
                    let isEd25519 KeyPairEd25519 {} = True
                        -- TODO: Required when more algorithms are implemented.
                        -- isEd25519 _                 = False
                    case NEL.filter isEd25519 (hostKeys config) of
                        (x:_) -> pure x
                        _     -> undefined -- impossible

                let secret = Curve25519.dh
                        clientEphemeralPublicKey
                        serverEphemeralSecretKey

                let hash = exchangeHash
                        clientVersion
                        serverVersion
                        cki
                        ski
                        (PublicKeyEd25519 pubKey)
                        clientEphemeralPublicKey
                        serverEphemeralPublicKey
                        secret

                -- The reply is shall be sent with the old encryption context.
                -- This is the case as long as the KexNewKeys message has not
                -- been transmitted.
                sendMsg $ MsgKexEcdhReply KexEcdhReply {
                            kexServerHostKey      = PublicKeyEd25519 pubKey
                        ,   kexServerEphemeralKey = serverEphemeralPublicKey
                        ,   kexHashSignature      = SignatureEd25519 $ Ed25519.sign
                                                        secKey
                                                        pubKey
                                                        hash
                        }

                session <- tryReadMVar msid >>= \case
                    Just s -> pure s
                    Nothing -> do
                        let s = SessionId $ BA.convert hash
                        putMVar msid s
                        pure s

                setChaCha20Poly1305Context transport Server $ deriveKeys secret hash session

                -- The encryption context shall be switched no earlier than
                -- before the new keys message has been transmitted.
                -- It's the sender's thread responsibility to switch the context.
                sendMsg (MsgKexNewKeys KexNewKeys)

commonKexAlgorithm :: KexInit -> KexInit -> IO KeyExchangeAlgorithm
commonKexAlgorithm ski cki = case kexAlgorithms cki `intersect` kexAlgorithms ski of
    ("curve25519-sha256@libssh.org":_) -> pure Curve25519Sha256AtLibsshDotOrg
    _ -> throwIO (Disconnect DisconnectKeyExchangeFailed "no common kex algorithm" mempty)

commonEncAlgorithmCS :: KexInit -> KexInit -> IO EncryptionAlgorithm
commonEncAlgorithmCS ski cki = case kexEncryptionAlgorithmsClientToServer cki `intersect` kexEncryptionAlgorithmsClientToServer ski of
    ("chacha20-poly1305@openssh.com":_) -> pure Chacha20Poly1305AtOpensshDotCom
    _ -> throwIO (Disconnect DisconnectKeyExchangeFailed "no common encryption algorithm (client to server)" mempty)

commonEncAlgorithmSC :: KexInit -> KexInit -> IO EncryptionAlgorithm
commonEncAlgorithmSC ski cki = case kexEncryptionAlgorithmsServerToClient cki `intersect` kexEncryptionAlgorithmsServerToClient ski of
    ("chacha20-poly1305@openssh.com":_) -> pure Chacha20Poly1305AtOpensshDotCom
    _ -> throwIO (Disconnect DisconnectKeyExchangeFailed "no common encryption algorithm (server to client)" mempty)

newKexInit :: Config identity -> IO KexInit
newKexInit config = do
    cookie <- newCookie
    pure KexInit
        {   kexCookie                              = cookie
        ,   kexAlgorithms                          = NEL.toList $ fmap f (keyExchangeAlgorithms config)
        ,   kexServerHostKeyAlgorithms             = NEL.toList $ NEL.nub $ fmap g (hostKeys config)
        ,   kexEncryptionAlgorithmsClientToServer  = NEL.toList $ fmap h (encryptionAlgorithms config)
        ,   kexEncryptionAlgorithmsServerToClient  = NEL.toList $ fmap h (encryptionAlgorithms config)
        ,   kexMacAlgorithmsClientToServer         = []
        ,   kexMacAlgorithmsServerToClient         = []
        ,   kexCompressionAlgorithmsClientToServer = ["none"]
        ,   kexCompressionAlgorithmsServerToClient = ["none"]
        ,   kexLanguagesClientToServer             = []
        ,   kexLanguagesServerToClient             = []
        ,   kexFirstPacketFollows                  = False
        }
    where
        f Curve25519Sha256AtLibsshDotOrg  = "curve25519-sha256@libssh.org"
        g KeyPairEd25519 {}               = "ssh-ed25519"
        h Chacha20Poly1305AtOpensshDotCom = "chacha20-poly1305@openssh.com"

exchangeHash ::
    Version ->               -- client version string
    Version ->               -- server version string
    KexInit ->               -- client kex init msg
    KexInit ->               -- server kex init msg
    PublicKey ->             -- server host key
    Curve25519.PublicKey ->  -- client ephemeral key
    Curve25519.PublicKey ->  -- server ephemeral key
    Curve25519.DhSecret ->   -- dh secret
    Hash.Digest Hash.SHA256
exchangeHash (Version vc) (Version vs) ic is ks qc qs k
    = Hash.hash $ runPut $ do
        putString vc
        putString vs
        putWord32 (len ic)
        put       ic
        putWord32 (len is)
        put       is
        put       ks
        put       qc
        put       qs
        putAsMPInt k

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> SessionId -> KeyStreams
deriveKeys secret hash (SessionId sess) = KeyStreams $ \i -> BA.convert <$> (k1 i) : f [k1 i]
    where
    k1 i = Hash.hashFinalize $
        flip Hash.hashUpdate sess $
        Hash.hashUpdate st i :: Hash.Digest Hash.SHA256
    f ks = kx : f (ks ++ [kx])
        where
        kx = Hash.hashFinalize (foldl Hash.hashUpdate st ks)
    st =
        flip Hash.hashUpdate hash $
        Hash.hashUpdate Hash.hashInit (runPut $ putAsMPInt secret)
