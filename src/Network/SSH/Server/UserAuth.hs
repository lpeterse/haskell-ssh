{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.UserAuth where

import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Concurrent.STM.TVar
import           Control.Monad                (forever, unless, when)
import           Control.Monad.STM

import           Network.SSH.Message
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
