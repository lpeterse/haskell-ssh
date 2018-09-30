{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
module Network.SSH.Server.Service.UserAuth where

import           Control.Exception (throwIO)
import qualified Crypto.Hash.Algorithms       as Hash
import qualified Crypto.PubKey.Ed25519        as Ed25519
import qualified Crypto.PubKey.RSA.PKCS15     as RSA.PKCS15
import qualified Data.ByteString              as BS

import           Network.SSH.Encoding
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Internal

dispatcher :: forall identity a. Config identity -> SessionId -> Sender -> (identity -> MessageDispatcher a) -> MessageDispatcher a
dispatcher config session send withIdentity = dispatchState0
    where
        exception code msg = throwIO $ Disconnect code msg mempty
        exceptionServiceNotAvailable = exception DisconnectServiceNotAvailable mempty
        exceptionUnexpectedMessageType = exception DisconnectProtocolError "unexpected message type (user auth module)"

        supportedAuthMethods =
            MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False
        unconditionallyConfirmPublicKeyIsOk algo pk =
            MsgUserAuthPublicKeyOk $ UserAuthPublicKeyOk algo pk

        dispatchState0 :: MessageDispatcher a
        dispatchState0 msg (Continuation continue) = case msg of
            MsgServiceRequest (ServiceRequest (ServiceName srv@"ssh-userauth")) -> do
                send $ MsgServiceAccept (ServiceAccept (ServiceName srv))
                continue dispatchState1
            MsgServiceRequest _ -> exceptionServiceNotAvailable
            _ -> exceptionUnexpectedMessageType

        dispatchState1 :: MessageDispatcher a
        dispatchState1 msg (Continuation continue) = case msg of
            MsgUserAuthRequest (UserAuthRequest user service method) -> case method of
                AuthPublicKey algo pk msig -> case msig of
                    Nothing -> do
                        send $ unconditionallyConfirmPublicKeyIsOk algo pk
                        continue dispatchState1
                    Just sig
                        | verifyAuthSignature session user service algo pk sig -> do
                            onAuthRequest config user service pk >>= \case
                                Nothing -> do
                                    send supportedAuthMethods
                                    continue dispatchState1
                                Just idnt -> case service of
                                    (ServiceName "ssh-connection") -> do
                                        send $ MsgUserAuthSuccess UserAuthSuccess
                                        continue (withIdentity idnt)
                                    _ -> exceptionServiceNotAvailable
                        | otherwise -> do
                            send supportedAuthMethods
                            continue dispatchState1
                _ -> do
                    send supportedAuthMethods
                    continue dispatchState1
            _ -> exceptionUnexpectedMessageType

verifyAuthSignature :: SessionId -> UserName -> ServiceName -> Algorithm -> PublicKey -> Signature -> Bool
verifyAuthSignature sessionIdentifier userName serviceName algorithm publicKey signature =
    case (publicKey,signature) of
        (PublicKeyEd25519 k, SignatureEd25519 s) -> Ed25519.verify k signedData s
        (PublicKeyRSA     k, SignatureRSA     s) -> RSA.PKCS15.verify (Just Hash.SHA1) k signedData s
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
