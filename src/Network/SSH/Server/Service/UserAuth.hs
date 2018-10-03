{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
module Network.SSH.Server.Service.UserAuth where

import           Control.Exception (throwIO)
import qualified Crypto.PubKey.Ed25519        as Ed25519
import qualified Data.ByteString              as BS

import           Network.SSH.Encoding
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Server.Config

withAuthentication :: forall identity stream a. (MessageStream stream) => Config identity -> stream -> SessionId -> (ServiceName -> Maybe (identity -> IO ())) -> IO ()
withAuthentication config transport session serviceHandler = do
    ServiceRequest srv <- receiveMessage transport
    case srv of
        ServiceName "ssh-userauth" -> do
            sendMessage transport (ServiceAccept srv)
            authenticate
        _ -> exceptionServiceNotAvailable
    where
        exception code msg = throwIO $ Disconnect code msg mempty
        exceptionServiceNotAvailable = exception DisconnectServiceNotAvailable mempty

        sendSupportedAuthMethods =
            sendMessage transport $ UserAuthFailure [AuthMethodName "publickey"] False
        sendPublicKeyIsOk algo pk =
            sendMessage transport $ UserAuthPublicKeyOk algo pk
        sendSuccess =
            sendMessage transport UserAuthSuccess

        authenticate = do
            UserAuthRequest user service method <- receiveMessage transport
            case method of
                AuthPublicKey algo pk msig -> case msig of
                    Just sig
                        | verifyAuthSignature session user service algo pk sig -> do
                            onAuthRequest config user service pk >>= \case
                                Just idnt -> case serviceHandler service of
                                    Just h  -> sendSuccess >> h idnt
                                    Nothing -> exceptionServiceNotAvailable
                                Nothing -> do
                                    sendSupportedAuthMethods
                                    authenticate
                        | otherwise -> do
                            sendSupportedAuthMethods
                            authenticate
                    Nothing -> do
                        sendPublicKeyIsOk algo pk
                        authenticate
                _ -> do
                    sendSupportedAuthMethods
                    authenticate

verifyAuthSignature :: SessionId -> UserName -> ServiceName -> Algorithm -> PublicKey -> Signature -> Bool
verifyAuthSignature sessionIdentifier userName serviceName algorithm publicKey signature =
    case (publicKey,signature) of
        (PublicKeyEd25519 k, SignatureEd25519 s) -> Ed25519.verify k signedData s
        -- TODO: Implement RSA
        -- (PublicKeyRSA     k, SignatureRSA     s) -> RSA.PKCS15.verify (Just Hash.SHA1) k signedData s
        _                                        -> False
    where
        signedData :: BS.ByteString
        signedData = runPut $ do
            put           sessionIdentifier
            putWord8      50
            put           userName
            put           serviceName
            putString     ("publickey" :: BS.ByteString)
            putWord8      1
            put           algorithm
            put           publicKey
