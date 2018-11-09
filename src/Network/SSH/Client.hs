{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client where

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
import           Network.SSH.Constants
import           Network.SSH.Exception
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Key
import           Network.SSH.Name
import           Network.SSH.Stream
import           Network.SSH.Transport
import qualified Network.SSH.TStreamingQueue           as Q

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
    = Connection
    { connectionTransport :: Transport
    , connectionChannels  :: TVar (M.Map ChannelId ChannelState)
    }

data ChannelState
    = ChannelOpening (Either ChannelOpenFailure ChannelOpenConfirmation -> STM ())
    | ChannelRunning Channel
    | ChannelClosing

data Channel
    = Channel 
    { chanIdLocal             :: ChannelId
    , chanIdRemote            :: ChannelId
    , chanMaxPacketSizeRemote :: Word32
    , chanWindowSizeRemote    :: TVar Word32
    , chanApplication         :: ChannelApplication
    }

data ChannelApplication
    = ChannelApplicationSession ChannelSession

data ChannelSession
    = ChannelSession
    { sessStdout      :: Q.TStreamingQueue
    , sessStderr      :: Q.TStreamingQueue
    }

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
        c <- atomically $ Connection
            <$> pure transport
            <*> newTVar mempty
        withAsync (dispatchIncoming transport c) $ \thread ->
            Disconnect Local DisconnectByApplication <$> handler c
    where
        mergeDisconnects :: IO (Either Disconnect Disconnect) -> IO Disconnect
        mergeDisconnects = fmap $ \case
            Left  d -> d
            Right d -> d

        dispatchIncoming :: Transport -> Connection -> IO ()
        dispatchIncoming t c = forever $ do
            receiveMessage t >>= \case
                C1 x -> print x
                C2 x@(ChannelOpenConfirmation lid _ _ _) -> atomically $ do
                    getChannelStateSTM c lid >>= \case
                        ChannelOpening f -> f (Right x)
                        _                -> throwSTM exceptionInvalidChannelState
                C3 x@(ChannelOpenFailure lid _ _ _) -> atomically $ do
                    getChannelStateSTM c lid >>= \case
                        ChannelOpening f -> f (Left x)
                        _                -> throwSTM exceptionInvalidChannelState
                C4  x -> print x
                C5  x -> print x
                C6  x -> print x
                C7  x -> print x
                C8  x -> print x
                C9  x -> print x
                C96 x -> print x
                C97 x -> print x

requestServiceWithAuthentication ::
    UserAuthConfig -> Transport -> SessionId -> ServiceName -> IO ()
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

asyncSession :: Connection -> IO (Async ExitCode)
asyncSession c = do
    r <- newEmptyTMVarIO
    lid <- atomically $ openChannelSTM c $ \case
        Left x@ChannelOpenFailure {} -> do
            putTMVar r (Left x)
        Right (ChannelOpenConfirmation lid rid rws rps) -> do
            tlws <- newTVar 10000
            trws <- newTVar rws
            sstdout <- Q.newTStreamingQueue maxQueueSize tlws
            sstderr <- Q.newTStreamingQueue maxQueueSize tlws
            let session = ChannelSession
                    { sessStdout              = sstdout
                    , sessStderr              = sstderr
                    }
            let channel = Channel
                    { chanIdLocal             = lid
                    , chanIdRemote            = rid
                    , chanMaxPacketSizeRemote = rps
                    , chanWindowSizeRemote    = trws
                    , chanApplication         = ChannelApplicationSession session
                    }
            setChannelStateSTM c lid $ ChannelRunning channel
            putTMVar r (Right channel)
    sendMessage t $ ChannelOpen lid lw lp ChannelOpenSession
    atomically (readTMVar r) >>= \case
        Left (ChannelOpenFailure _ reason descr _) -> throwIO
            $ ChannelOpenFailed reason
            $ ChannelOpenFailureDescription $ SBS.fromShort descr
        Right ch -> do
            sendMessage t $ ChannelRequest
                { crChannel   = chanIdRemote ch
                , crType      = "exec"
                , crWantReply = True
                , crData      = runPut (put $ ChannelRequestExec "ls")
                }
    async $ pure ExitSuccess
    where
        t = connectionTransport c
        lw = 200
        lp = 100

        -- The maxQueueSize must at least be one (even if 0 in the config)
        -- and must not exceed the range of Int (might happen on 32bit systems
        -- as Int's guaranteed upper bound is only 2^29 -1).
        -- The value is adjusted silently as this won't be a problem
        -- for real use cases and is just the safest thing to do.
        maxQueueSize :: Word32
        maxQueueSize = max 1 $ fromIntegral $ min maxBoundIntWord32
            1000 -- (channelMaxQueueSize $ connConfig connection) FIXME

        maxPacketSize :: Word32
        maxPacketSize = max 1 $ fromIntegral $ min maxBoundIntWord32
            1000 -- (channelMaxPacketSize $ connConfig connection) FIXME

getFreeChannelIdSTM :: Connection -> STM ChannelId
getFreeChannelIdSTM c = pure (ChannelId 0) -- FIXME

openChannelSTM :: Connection -> (Either ChannelOpenFailure ChannelOpenConfirmation -> STM ()) -> STM ChannelId
openChannelSTM c handler = do
    setChannelStateSTM c (ChannelId 0) (ChannelOpening handler)
    pure (ChannelId 0)

getChannelStateSTM :: Connection -> ChannelId -> STM ChannelState
getChannelStateSTM c lid = do
    channels <- readTVar (connectionChannels c)
    maybe (throwSTM exceptionInvalidChannelId) pure (M.lookup lid channels)

setChannelStateSTM :: Connection -> ChannelId -> ChannelState -> STM ()
setChannelStateSTM c lid st = do
    channels <- readTVar (connectionChannels c)
    writeTVar (connectionChannels c) $! M.insert lid st channels

data ConnectionMessage
    = C1  GlobalRequest
    | C2  ChannelOpenConfirmation
    | C3  ChannelOpenFailure
    | C4  ChannelWindowAdjust
    | C5  ChannelRequest
    | C6  ChannelSuccess
    | C7  ChannelFailure
    | C8  ChannelData
    | C9  ChannelExtendedData
    | C96 ChannelEof
    | C97 ChannelClose

instance Encoding ConnectionMessage where
    get = C1  <$> get
      <|> C2  <$> get
      <|> C3  <$> get
      <|> C4  <$> get
      <|> C5  <$> get
      <|> C6  <$> get
      <|> C7  <$> get
      <|> C8  <$> get
      <|> C9  <$> get
      <|> C96 <$> get
      <|> C97 <$> get

data ChannelException
    = ChannelOpenFailed ChannelOpenFailureReason ChannelOpenFailureDescription
    deriving (Eq, Show)

instance Exception ChannelException where

newtype ChannelOpenFailureDescription = ChannelOpenFailureDescription BS.ByteString
    deriving (Eq, Ord, Show)
