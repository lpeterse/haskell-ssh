{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.UserAuth where

import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Monad.STM
import qualified Crypto.Hash.Algorithms       as Hash
import qualified Crypto.PubKey.Ed25519        as Ed25519
import qualified Crypto.PubKey.RSA.PKCS15     as RSA.PKCS15
import qualified Data.ByteString              as BS

import           Network.SSH.Encoding
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport
import           Network.SSH.Server.Types

handleUserAuthRequest :: Connection identity -> UserAuthRequest -> IO ()
handleUserAuthRequest connection (UserAuthRequest user service method) =
    case method of
      AuthPublicKey algo pk msig -> case msig of
        Nothing ->
            unconditionallyConfirmPublicKeyIsOk algo pk
        Just sig
            | verifyAuthSignature (connSessionId connection) user service algo pk sig -> do
                onAuthRequest (connConfig connection) user service pk >>= \case
                    Nothing -> sendSupportedAuthMethods
                    Just ident -> atomically $ do
                        writeTVar (connIdentity connection) (Just ident)
                        writeTChan (connOutput connection) (MsgUserAuthSuccess UserAuthSuccess)
            | otherwise ->
                sendSupportedAuthMethods
      _ -> sendSupportedAuthMethods
    where
        sendSupportedAuthMethods =
            atomically $ send connection $ MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False
        unconditionallyConfirmPublicKeyIsOk algo pk =
            atomically $ send connection $ MsgUserAuthPublicKeyOk $ UserAuthPublicKeyOk algo pk

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
