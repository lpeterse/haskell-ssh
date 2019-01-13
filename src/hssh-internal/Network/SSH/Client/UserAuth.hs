{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client.UserAuth
    ( ClientIdentity (..)
    , userPassword
    , requestServiceWithAuthentication
    )
where

import           Control.Applicative
import           Control.Exception                     ( throwIO )
import qualified Data.ByteString                       as BS
import qualified Data.ByteString.Char8                 as BS8
import qualified Data.ByteString.Short                 as SBS
import           Data.Default
import           Data.Function                         ( fix )
import           Data.Maybe
import           Data.List                             ( intersect )
import           System.Environment

import           Network.SSH.Agent
import           Network.SSH.Exception
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Name

data ClientIdentity
    = ClientIdentity
    { getUserName   :: IO UserName
    , getAgent      :: IO Agent
    , getPassword   :: IO (Maybe Password)
    }

instance Default ClientIdentity where
    def = ClientIdentity
        { getUserName  = getLocalUserName
        , getAgent     = pure (Agent LocalAgent)
        , getPassword  = pure Nothing
        }

userPassword :: UserName -> Password -> ClientIdentity
userPassword u p = def
    { getUserName = pure u
    , getPassword = pure (Just p)
    }

getLocalUserName :: IO UserName
getLocalUserName  = do
    user <- fromMaybe "root" <$> lookupEnv "USER"
    pure $ Name $ SBS.toShort $ BS8.pack user

data AuthResponse
    = A1 UserAuthBanner
    | A2 UserAuthSuccess
    | A3 UserAuthFailure

instance Decoding AuthResponse where
    get   = A1 <$> get
        <|> A2 <$> get
        <|> A3 <$> get

requestServiceWithAuthentication :: MessageStream stream =>
    ClientIdentity -> stream -> SessionId -> ServiceName -> IO ()
requestServiceWithAuthentication config transport sessionId service = do
    sendMessage transport $ ServiceRequest $ Name "ssh-userauth"
    ServiceAccept {} <- receiveMessage transport
    user <- getUserName config
    tryMethods user [ methodPubkey, methodPassword ]
    where
        methodPassword = Name "password"
        methodPubkey   = Name "publickey"

        tryMethods _ []
            = throwIO exceptionNoMoreAuthMethodsAvailable
        tryMethods user (m:ms)
            | m == methodPubkey = getAgent config >>= \agent ->
                tryPubkeys user ms (signDigest agent) =<< getIdentities agent
            | m == methodPassword = getPassword config >>= \case
                Nothing -> tryMethods user ms
                Just pw -> do
                    sendMessage transport
                        $ UserAuthRequest user service
                        $ AuthPassword pw
                    fix $ \continue -> receiveMessage transport >>= \case
                        A1 UserAuthBanner  {} -> continue
                        A2 UserAuthSuccess {} -> pure ()
                        -- Try the next method (if there is any in the intersection).
                        A3 (UserAuthFailure ms' _) -> tryMethods user (ms `intersect` ms')
            -- Ignore method and try the next one.
            | otherwise = tryMethods user ms

        tryPubkeys user ms trySign = \case
            []       -> tryMethods user ms -- no more keys to try
            ((pk,_):pks) -> trySign pk (signatureData sessionId user service pk) def >>= \case
                Nothing -> tryPubkeys user ms trySign pks
                Just signature -> do
                    sendMessage transport
                        $ UserAuthRequest user service
                        $ AuthPublicKey pk (Just signature)
                    fix $ \continue -> receiveMessage transport >>= \case
                        A1 UserAuthBanner  {} -> continue
                        A2 UserAuthSuccess {} -> pure ()
                        A3 (UserAuthFailure ms' _)
                            -- Try the next pubkey. Eventually reduce the methods to try.
                            | methodPubkey `elem` ms' -> tryPubkeys user (ms `intersect` ms') trySign pks
                            -- Do not try any more pubkeys if the server indicates it won't
                            -- accept any. Try another method instead (if any).
                            | otherwise               -> tryMethods user (ms `intersect` ms')

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
