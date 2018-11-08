{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client where

import           Control.Applicative
import           Control.Exception                     ( throwIO )
import           Control.Concurrent.Async              ( Async (..) )
import           Data.Default
import qualified Data.ByteString                       as BS
import           Data.Function                         ( fix )
import           Data.List                             ( intersect )
import           System.Exit

import           Network.SSH.AuthAgent
import           Network.SSH.Exception
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Key
import           Network.SSH.Name
import           Network.SSH.Stream
import           Network.SSH.Transport

data Config
    = Config
    { transportConfig :: TransportConfig
    , userAuthConfig  :: UserAuthConfig
    }

data UserAuthConfig
    = UserAuthConfig
    { userName      :: UserName
    , getAgent      :: IO (Maybe KeyPair)
    , getPassword   :: IO (Maybe Password)
    }

instance Default Config where
    def = Config def def

instance Default UserAuthConfig where
    def = UserAuthConfig
        { userName    = Name "anonymous"
        , getAgent    = pure (Nothing :: Maybe KeyPair)
        , getPassword = pure Nothing
        }

data Connection
    = Connection Config

newtype Command = Command BS.ByteString

data AuthResponse
    = AuthFailure  UserAuthFailure
    | AuthSuccess  UserAuthSuccess
    | AuthBanner   UserAuthBanner

instance Encoding AuthResponse where
    put (AuthFailure  x) = put x
    put (AuthSuccess  x) = put x
    put (AuthBanner   x) = put x
    get   = AuthFailure  <$> get
        <|> AuthSuccess  <$> get
        <|> AuthBanner   <$> get

withConnection :: forall stream. (DuplexStream stream)
     => Config -> stream -> (Connection -> IO DisconnectMessage)
     -> IO Disconnect
withConnection config stream handler = mergeDisconnects $
    withTransport (transportConfig config) (Nothing :: Maybe KeyPair) stream $ \transport sessionId -> do
        requestServiceWithAuthentication (userAuthConfig config) transport sessionId (Name "ssh-connection")
        Disconnect Local DisconnectByApplication <$> handler undefined
    where
        mergeDisconnects :: IO (Either Disconnect Disconnect) -> IO Disconnect
        mergeDisconnects = fmap $ \case
            Left  d -> d
            Right d -> d

requestServiceWithAuthentication ::
    UserAuthConfig -> Transport -> SessionId -> ServiceName -> IO ()
requestServiceWithAuthentication config@UserAuthConfig { getAgent = getAgent' } transport sessionId service = do
    sendMessage transport $ ServiceRequest $ Name "ssh-userauth"
    ServiceAccept {} <- receiveMessage transport
    tryMethods [ methodPubkey, methodPassword ]
    where
        user           = userName config
        methodPassword = Name "password"
        methodPubkey   = Name "pubkey"

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
                        AuthSuccess _ -> pure ()
                        AuthBanner  _ -> continue
                        -- Try the next method (if there is any in the intersection).
                        AuthFailure (UserAuthFailure ms' _) -> tryMethods (ms `intersect` ms')
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
                        AuthSuccess _ -> pure ()
                        AuthBanner  _ -> continue
                        AuthFailure (UserAuthFailure ms' _)
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

newtype Environment = Environment ()

newtype SessionHandler = SessionHandler (forall stdin stdout stderr. (OutputStream stdin, InputStream stdout, InputStream stderr)
    => stdin -> stdout -> stderr -> IO ExitCode)

asyncSession :: Connection -> Environment -> Maybe Command -> SessionHandler -> IO (Async ExitCode)
asyncSession = undefined
