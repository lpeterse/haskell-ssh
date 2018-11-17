{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client.UserAuth
    ( UserAuthConfig (..)
    , requestServiceWithAuthentication
    )
where

import           Control.Applicative
import           Control.Concurrent.Async              ( Async (..), async, withAsync )
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Control.Exception                     ( Exception, throwIO )
import           Control.Monad
import           Control.Monad.STM
import           Data.Default
import           Data.Function                         ( fix )
import           Data.List                             ( intersect )
import           Data.Map.Strict                       as M
import           System.Exit
import           Data.Word
import qualified Data.ByteString                       as BS
import qualified Data.ByteString.Short                 as SBS

import           Network.SSH.AuthAgent
import           Network.SSH.Exception
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Key
import           Network.SSH.Name

data UserAuthConfig
    = UserAuthConfig
    { userName      :: UserName
    , getAgent      :: IO (Maybe KeyPair)
    , getPassword   :: IO (Maybe Password)
    }

instance Default UserAuthConfig where
    def = UserAuthConfig
        { userName    = Name "anonymous"
        , getAgent    = pure (Nothing :: Maybe KeyPair)
        , getPassword = pure Nothing
        }

data AuthResponse
    = A1 UserAuthBanner
    | A2 UserAuthSuccess
    | A3 UserAuthFailure

instance Decoding AuthResponse where
    get   = A1 <$> get
        <|> A2 <$> get
        <|> A3 <$> get

requestServiceWithAuthentication :: MessageStream stream =>
    UserAuthConfig -> stream -> SessionId -> ServiceName -> IO ()
requestServiceWithAuthentication config@UserAuthConfig { getAgent = getAgent' } transport sessionId service = do
    sendMessage transport $ ServiceRequest $ Name "ssh-userauth"
    ServiceAccept {} <- receiveMessage transport
    tryMethods [ methodPubkey, methodPassword ]
    where
        user           = userName config
        methodPassword = Name "password"
        methodPubkey   = Name "publickey"

        tryMethods []
            = throwIO exceptionNoMoreAuthMethodsAvailable
        tryMethods (m:ms)
            | m == methodPubkey = getAgent' >>= \case
                Nothing    -> tryMethods ms
                Just agent -> tryPubkeys ms (sign agent) =<< getPublicKeys agent
            | m == methodPassword = getPassword config >>= \case
                Nothing -> tryMethods ms
                Just pw -> do
                    sendMessage transport
                        $ UserAuthRequest user service
                        $ AuthPassword pw
                    fix $ \continue -> receiveMessage transport >>= \case
                        A1 (UserAuthBanner {}) -> continue
                        A2 (UserAuthSuccess {}) -> pure ()
                        -- Try the next method (if there is any in the intersection).
                        A3 (UserAuthFailure ms' _) -> tryMethods (ms `intersect` ms')
            -- Ignore method and try the next one.
            | otherwise = tryMethods ms

        tryPubkeys ms trySign = \case
            []       -> tryMethods ms -- no more keys to try
            (pk:pks) -> trySign pk (signatureData sessionId user service pk) >>= \case
                Nothing -> tryPubkeys ms trySign pks
                Just signature -> do
                    sendMessage transport
                        $ UserAuthRequest user service
                        $ AuthPublicKey pk (Just signature)
                    fix $ \continue -> receiveMessage transport >>= \case
                        A1 (UserAuthBanner {}) -> continue
                        A2 (UserAuthSuccess {}) -> pure ()
                        A3 (UserAuthFailure ms' _)
                            -- Try the next pubkey. Eventually reduce the methods to try.
                            | methodPubkey `elem` ms' -> tryPubkeys (ms `intersect` ms') trySign pks
                            -- Do not try any more pubkeys if the server indicates it won't
                            -- accept any. Try another method instead (if any).
                            | otherwise               -> tryMethods (ms `intersect` ms')

signatureData :: SessionId -> UserName -> ServiceName -> PublicKey -> BS.ByteString
signatureData sessionIdentifier user service publicKey = runPut $
    put           sessionIdentifier <>
    putWord8      50 <> -- SSH_MSG_USERAUTH_REQUEST
    putName       user <>
    putName       service <>
    putName       (Name "publickey") <>
    putWord8      1 <> -- TRUE
    putName       (name publicKey) <>
    putPublicKey  publicKey