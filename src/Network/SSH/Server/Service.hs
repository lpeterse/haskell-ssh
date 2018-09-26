{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
module Network.SSH.Server.Service where

import           Control.Concurrent.MVar
import           Control.Monad     (void)
import           Control.Exception (bracket, throwIO)
import qualified Crypto.Hash.Algorithms       as Hash
import qualified Crypto.PubKey.Ed25519        as Ed25519
import qualified Crypto.PubKey.RSA.PKCS15     as RSA.PKCS15
import qualified Data.ByteString              as BS

import           Network.SSH.Encoding
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Service.Connection

newtype MessageDispatcher = MessageDispatcher (Message -> IO MessageDispatcher)

withServiceLayer :: forall identity a. Config identity -> SessionId -> (Message -> IO ()) -> ((Message -> IO ()) -> IO a) -> IO a
withServiceLayer config session send runWith = bracket
    ( newMVar dispatchAuth0 ) -- a disconnect message will be dispatched on termination!
    (\mvar -> modifyMVar_ mvar (\(MessageDispatcher f) -> f $ MsgDisconnect $ Disconnect DisconnectReserved mempty mempty))
    (\mvar -> runWith $ \msg -> modifyMVar_ mvar (\(MessageDispatcher f)-> f msg))
    where
        dispatchAuth0 :: MessageDispatcher
        dispatchAuth0 = MessageDispatcher $ \case
            MsgServiceRequest (ServiceRequest (ServiceName srv@"ssh-userauth")) -> do
                send $ MsgServiceAccept (ServiceAccept (ServiceName srv))
                pure $ dispatchAuth1
            MsgServiceRequest _ -> do
                throwIO $ Disconnect DisconnectServiceNotAvailable mempty mempty
            _ ->
                throwIO $ Disconnect DisconnectProtocolError mempty mempty

        dispatchAuth1 :: MessageDispatcher
        dispatchAuth1 = MessageDispatcher $ \case
            MsgUserAuthRequest (UserAuthRequest user service method) -> case method of
                AuthPublicKey algo pk msig -> case msig of
                    Nothing -> do
                        send $ unconditionallyConfirmPublicKeyIsOk algo pk
                        pure $ dispatchAuth1
                    Just sig
                        | verifyAuthSignature session user service algo pk sig -> do
                            onAuthRequest config user service pk >>= \case
                                Nothing -> do
                                    send supportedAuthMethods
                                    pure $ dispatchAuth1
                                Just identity -> case service of
                                    (ServiceName "ssh-connection") -> do
                                        send $ MsgUserAuthSuccess UserAuthSuccess
                                        conn <- connectionOpen config identity send
                                        pure $ dispatchConnection0 conn
                                    _ -> do
                                        send supportedAuthMethods
                                        pure dispatchAuth1
                        | otherwise -> do
                            send supportedAuthMethods
                            pure $ dispatchAuth1
                _ -> do
                    send supportedAuthMethods
                    pure $ dispatchAuth1
            _ -> throwIO $ Disconnect DisconnectProtocolError mempty mempty
            where
                supportedAuthMethods =
                    MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False
                unconditionallyConfirmPublicKeyIsOk algo pk =
                    MsgUserAuthPublicKeyOk $ UserAuthPublicKeyOk algo pk

        dispatchConnection0 :: Connection identity -> MessageDispatcher
        dispatchConnection0 connection = MessageDispatcher $ \msg-> do
            case msg of
                MsgChannelOpen x              -> connectionChannelOpen     connection x >>= \case
                    Left y  -> send (MsgChannelOpenFailure y)
                    Right y -> send (MsgChannelOpenConfirmation y)
                MsgChannelClose x             -> connectionChannelClose        connection x >>= \case
                    Nothing -> pure ()
                    Just y  -> send (MsgChannelClose y)
                MsgChannelEof x               -> connectionChannelEof          connection x
                MsgChannelRequest x           -> connectionChannelRequest      connection x >>= \case
                    Nothing -> pure ()
                    Just (Left y) -> send (MsgChannelFailure y)
                    Just (Right y) -> send (MsgChannelSuccess y)
                MsgChannelWindowAdjust x      -> connectionChannelWindowAdjust connection x
                MsgChannelData x              -> connectionChannelData         connection x
                _ -> do
                    connectionClose connection
                    throwIO $ Disconnect DisconnectProtocolError mempty mempty
            pure $ dispatchConnection0 connection

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
