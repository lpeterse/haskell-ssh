{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Network.SSH.Server.UserAuth where

import           Control.Exception            ( throwIO )
import           Control.Concurrent           ( threadDelay )
import qualified Control.Concurrent.Async     as Async
import qualified Crypto.Hash.Algorithms       as Hash
import qualified Crypto.PubKey.Ed25519        as Ed25519
import qualified Crypto.PubKey.RSA.PKCS15     as RSA.PKCS15
import qualified Data.ByteString              as BS
import           Data.Default

import           Network.SSH.Duration
import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Address
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Name

-- | Configuration for the user authentication layer.
--
-- After a successful key exchange the client will usually
-- request the @user-auth@ service to authenticate against.
-- In this implementation, the @user-auth@ service is the
-- only service available after key exchange and the client
-- must request the connection layer through the authentication
-- layer. Except for transport messages, all other message types
-- will result in a disconnect as long as user authentication
-- is in progress (looking at you, libssh ;-)
data UserAuthConfig state user
    = UserAuthConfig
    {   onAuthRequest :: state -> Address -> UserName -> ServiceName -> PublicKey -> IO (Maybe user)
        -- ^ This handler will be called for each authentication attempt.
        --
        --  (1) The client might try several methods and keys: Just return `Nothing`
        --   for every request that is not sufficient to determine the user's
        --   identity.
        --
        --   (2) When access shall be granted, return `Just`. The `user` may
        --   contain whatever is desired; it may be just the `UserName`.
        --
        --   (3) When the client uses public key authentication, the transport layer
        --   has already determined that the client is in posession of the
        --   corresponding private key (by requesting and validating a signature).
        --
        --   (4) The default rejects all authentication attempts unconditionally.
    , userAuthTimeout :: Duration
        -- ^ Timeout for user authentication in seconds (default is 60 seconds).
        --
        --   (1) A @SSH_DISCONNECT_BY_APPLICATION@ will be sent to the client
        --   when the timeout occurs before successful authentication.
    , userAuthMaxAttempts :: Int
        -- ^ A limit for the number of failed attempts per connection (default is 20).
        --
        --   (1) A @SSH_DISCONNECT_BY_APPLICATION@ will be sent to the client
        --   when limit has been exceeded.
    }

instance Default (UserAuthConfig state user) where
    def = UserAuthConfig
        { onAuthRequest       = \_ _ _ _ _-> pure Nothing
        , userAuthTimeout     = seconds 60
        , userAuthMaxAttempts = 20
        }

withAuthentication ::
    forall stream state user a. (MessageStream stream) =>
    UserAuthConfig state user -> stream -> state -> SourceAddress -> SessionId ->
    (ServiceName -> Maybe (user -> IO a)) -> IO a
withAuthentication config stream state addr session serviceHandler = do
    ServiceRequest srv <- receiveMessage stream
    case srv of
        Name "ssh-userauth" -> do
            sendMessage stream (ServiceAccept srv)
            Async.race timeout (authenticate maxAttempts) >>= \case
                Left () -> throwIO exceptionAuthenticationTimeout
                Right (s,i) -> case serviceHandler s of
                    Just h  -> sendSuccess >> h i
                    Nothing -> throwIO exceptionServiceNotAvailable
        _ -> throwIO exceptionServiceNotAvailable
    where
        maxAttempts = userAuthMaxAttempts config
        timeout     = threadDelay $ fromIntegral (asMicroSeconds $ userAuthTimeout config)

        sendSupportedAuthMethods =
            sendMessage stream $ UserAuthFailure [Name "publickey"] False
        sendPublicKeyIsOk pk =
            sendMessage stream $ UserAuthPublicKeyOk pk
        sendSuccess =
            sendMessage stream UserAuthSuccess

        authenticate limit
            | limit <= 0 = throwIO exceptionAuthenticationLimitExceeded
            | otherwise  = do
                UserAuthRequest user service method <- receiveMessage stream
                case method of
                    AuthPublicKey pk msig -> case msig of
                        Just sig
                            | signatureValid session user service pk sig -> do
                                onAuthRequest config state addr user service pk >>= \case
                                    Just st -> pure (service, st)
                                    Nothing -> do
                                        sendSupportedAuthMethods
                                        authenticate (limit - 1)
                            | otherwise -> do
                                sendSupportedAuthMethods
                                authenticate (limit - 1)
                        Nothing -> do
                            sendPublicKeyIsOk pk
                            authenticate (limit - 1)
                    _ -> do
                        sendSupportedAuthMethods
                        authenticate (limit - 1)

signatureValid :: SessionId -> UserName -> ServiceName -> PublicKey -> Signature -> Bool
signatureValid sessionIdentifier userName serviceName publicKey signature =
    case (publicKey,signature) of
        (PublicKeyEd25519 k, SignatureEd25519 s) -> Ed25519.verify k signedData s
        (PublicKeyRSA     k, SignatureRSA     s) -> RSA.PKCS15.verify (Just Hash.SHA1) k signedData s
        _                                        -> False
    where
        signedData :: BS.ByteString
        signedData = runPut $
            put           sessionIdentifier <>
            putWord8      50 <> -- SSH_MSG_USERAUTH_REQUEST
            putName       userName <>
            putName       serviceName <>
            putName       (Name "publickey") <>
            putWord8      1 <>  -- TRUE
            putName       (name publicKey) <>
            putPublicKey  publicKey
