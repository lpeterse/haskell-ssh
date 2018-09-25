{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE MultiWayIf          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Network.SSH.Server.Service.Connection
    ( Connection ()
    , connectionOpen
    , connectionClose
    , connectionClosed
    , connectionChannelOpen
    , connectionChannelClose
    , connectionChannelEof
    , connectionChannelRequest
    , connectionChannelData
    , connectionChannelExtendedData
    , connectionChannelWindowAdjust
    ) where

import           Control.Applicative
import           Control.Concurrent
import qualified Control.Concurrent.Async     as Async
import           Control.Concurrent.STM.TVar
import           Control.Monad                (join, void, when)
import           Control.Monad.STM            (STM, atomically, check, throwSTM)
import qualified Data.ByteArray               as BA
import qualified Data.ByteString              as BS
import qualified Data.Map.Strict              as M
import           Data.Word
import           System.Exit

import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Server.Config
import qualified Network.SSH.TAccountingQueue as AQ

data Connection identity
    = Connection
    { connConfig       :: Config identity
    , connIdentity     :: identity
    , connChannels     :: TVar (M.Map ChannelId (Channel identity))
    , connSend         :: Message -> IO ()
    , connClose        :: STM ()
    , connClosed       :: STM Bool
    }

data Channel identity
    = Channel
    { chanConnection          :: Connection identity
    , chanApplication         :: ChannelApplication
    , chanIdLocal             :: ChannelId
    , chanIdRemote            :: ChannelId
    , chanMaxPacketSizeRemote :: Word32
    , chanWindowSizeLocal     :: TVar Word32
    , chanWindowSizeRemote    :: TVar Word32
    , chanClose               :: STM ()
    , chanClosed              :: STM Bool
    }

data ChannelApplication
    = ChannelApplicationSession Session

data Session
    = Session
    { sessEnvironment :: TVar (M.Map BS.ByteString BS.ByteString)
    , sessTerminal    :: TVar (Maybe ())
    , sessThread      :: TVar (Maybe ThreadId)
    , sessStdin       :: AQ.TAccountingQueue
    , sessStdout      :: AQ.TAccountingQueue
    , sessStderr      :: AQ.TAccountingQueue
    }

connectionOpen :: Config identity -> identity -> (Message -> IO ()) -> IO (Connection identity)
connectionOpen config identity send = do
    closed <- newTVarIO False
    Connection
        <$> pure config
        <*> pure identity
        <*> newTVarIO mempty
        <*> pure send
        <*> pure (writeTVar closed True)
        <*> pure (readTVar closed)

connectionClose :: Connection identity -> IO ()
connectionClose = atomically . connClose

connectionClosed :: Connection identity -> IO Bool
connectionClosed = atomically . connClosed

connectionChannelOpen :: Connection identity -> ChannelOpen -> IO (Either ChannelOpenFailure ChannelOpenConfirmation)
connectionChannelOpen connection (ChannelOpen channelType remoteChannelId initialWindowSize maxPacketSize) =
    atomically openSTM
    where
        openSTM :: STM (Either ChannelOpenFailure ChannelOpenConfirmation)
        openSTM = do
            channels <- readTVar (connChannels connection)
            case selectLocalChannelId channels of
                Nothing ->
                    pure $ Left $ openFailure ChannelOpenResourceShortage
                Just localChannelId -> case channelType of
                    ChannelType "session" -> do
                        env    <- newTVar mempty
                        pty    <- newTVar Nothing
                        thread <- newTVar Nothing
                        stdin  <- AQ.newTAccountingQueue 1024
                        stdout <- AQ.newTAccountingQueue 1024
                        stderr <- AQ.newTAccountingQueue 1024
                        confirmation <- openApplicationChannel localChannelId $
                            ChannelApplicationSession Session
                                { sessEnvironment = env
                                , sessTerminal    = pty
                                , sessThread      = thread
                                , sessStdin       = stdin
                                , sessStdout      = stdout
                                , sessStderr      = stderr
                                }
                        pure (Right confirmation)
                    ChannelType {} ->
                        pure $ Left $ openFailure ChannelOpenUnknownChannelType

        selectLocalChannelId :: M.Map ChannelId a -> Maybe ChannelId
        selectLocalChannelId m
            | M.size m >= fromIntegral maxCount = Nothing
            | otherwise = f (ChannelId 0) $ M.keys m
            where
                f i []          = Just i
                f (ChannelId i) (ChannelId k:ks)
                    | i == k    = f (ChannelId $ i+1) ks
                    | otherwise = Just (ChannelId i)
                maxCount = channelMaxCount (connConfig connection)

        openFailure :: ChannelOpenFailureReason -> ChannelOpenFailure
        openFailure reason = ChannelOpenFailure remoteChannelId reason mempty mempty

        openApplicationChannel :: ChannelId -> ChannelApplication -> STM ChannelOpenConfirmation
        openApplicationChannel localChannelId application = do
            channels <- readTVar (connChannels connection)
            wsLocal  <- newTVar (channelMaxWindowSize $ connConfig connection)
            wsRemote <- newTVar initialWindowSize
            closed   <- newTVar False
            let channel = Channel {
                    chanConnection          = connection
                  , chanApplication         = application
                  , chanIdLocal             = localChannelId
                  , chanIdRemote            = remoteChannelId
                  , chanMaxPacketSizeRemote = maxPacketSize
                  , chanWindowSizeLocal     = wsLocal
                  , chanWindowSizeRemote    = wsRemote
                  , chanClose               = writeTVar closed True
                  , chanClosed              = (||) <$> connClosed connection <*> readTVar closed
                  }
            writeTVar (connChannels connection) $! M.insert localChannelId channel channels
            pure $ ChannelOpenConfirmation
                remoteChannelId
                localChannelId
                (channelMaxWindowSize $ connConfig connection)
                (channelMaxPacketSize $ connConfig connection)

connectionChannelClose :: Connection identity -> ChannelClose -> IO (Maybe ChannelClose)
connectionChannelClose connection (ChannelClose localChannelId) =
    atomically closeSTM
    where
        closeSTM :: STM (Maybe ChannelClose)
        closeSTM = do
            channels <- readTVar (connChannels connection)
            case M.lookup localChannelId channels of
                -- The client tries to close the same channel twice.
                -- This is a protocol error and the server shall disconnect.
                Nothing ->
                    throwSTM $ Disconnect DisconnectProtocolError mempty mempty
                Just channel -> do
                    writeTVar (connChannels connection) $! M.delete localChannelId channels
                    alreadyClosed <- chanClosed channel
                    -- When the channel is not marked as already closed then the close
                    -- must have been initiated by the client and the server needs to send
                    -- a confirmation.
                    if alreadyClosed then pure Nothing else do
                        chanClose channel
                        pure $ Just $ ChannelClose $ chanIdRemote channel

connectionChannelEof :: Connection identity -> ChannelEof -> IO ()
connectionChannelEof = undefined

connectionChannelData :: Connection identity -> ChannelData -> IO ()
connectionChannelData = undefined

connectionChannelExtendedData :: Connection identity -> ChannelExtendedData -> IO ()
connectionChannelExtendedData = undefined

connectionChannelWindowAdjust :: Connection identity -> ChannelWindowAdjust -> IO ()
connectionChannelWindowAdjust connection (ChannelWindowAdjust channelId increase) = atomically $ do
    channel <- getChannelSTM connection channelId
    windowSize <- readTVar (chanWindowSizeRemote channel)
    let windowSize' = fromIntegral windowSize + fromIntegral increase :: Word64
    -- Conversion to Word64 necessary for overflow check.
    when (windowSize' > 2 ^ (32 :: Word64) - 1) $
        throwSTM $ Disconnect DisconnectProtocolError "window size overflow" mempty
    -- Conversion from Word64 to Word32 never undefined as guaranteed by previous check.
    writeTVar (chanWindowSizeRemote channel) (fromIntegral windowSize')

connectionChannelRequest :: forall identity. Connection identity -> ChannelRequest -> IO (Maybe (Either ChannelFailure ChannelSuccess))
connectionChannelRequest connection (ChannelRequest channelId request) =
    join $ atomically $ do
        channel <- getChannelSTM connection channelId
        case chanApplication channel of
            ChannelApplicationSession session -> interpretAsSessionRequest channel session request
            -- Dispatch other channel request types here!
    where
        interpretAsSessionRequest :: Channel identity -> Session -> BS.ByteString -> STM (IO (Maybe (Either ChannelFailure ChannelSuccess)))
        interpretAsSessionRequest channel session req = case runGet get req of
            Nothing -> exception "invalid session channel request"
            Just sessionRequest -> case sessionRequest of
                ChannelRequestEnv wantReply name value -> do
                    env <- readTVar (sessEnvironment session)
                    writeTVar (sessEnvironment session) $! M.insert name value env
                    pure $ success wantReply
                ChannelRequestPty _wantReply _ptySettings ->
                    exception "pty-req not yet implemented"
                ChannelRequestShell _wantReply ->
                    exception "shell req not yet implemented"
                ChannelRequestExec wantReply command -> case onExecRequest (connConfig connection) of
                    Nothing-> pure $ failure wantReply
                    Just exec -> pure $ do
                        sessionExec channel session (\s0 s1 s2-> exec (connIdentity connection) s0 s1 s2 command)
                        success wantReply
                ChannelRequestOther _ wantReply -> pure $ failure wantReply
                ChannelRequestExitStatus {} -> pure $ success False
                ChannelRequestExitSignal {} -> pure $ success False
            where
                success True = pure $ Just $ Right $ ChannelSuccess (chanIdRemote channel)
                success _    = pure Nothing
                failure True = pure $ Just $ Left  $ ChannelFailure (chanIdRemote channel)
                failure _    = pure Nothing
                exception  e = throwSTM $ Disconnect DisconnectProtocolError e mempty

        sessionExec :: Channel identity -> Session
                    -> (AQ.TAccountingQueue -> AQ.TAccountingQueue -> AQ.TAccountingQueue -> IO ExitCode) -> IO ()
        sessionExec channel session handler =
            -- Two threads are forked: a worker thread running as Async and a dangling
            -- supervisor thread.
            -- -> The worker thread does never outlive the supervisor thread (`withAsync`).
            -- -> The supervisor thread terminates itself when either the worker thread
            --    has terminated (`waitExit`) or if the channel/connection has been closed
            --    (`waitClose`).
            void $ forkIO $ Async.withAsync work supervise
            where
                -- The worker thread is the user supplied action from the configuration.
                work :: IO ExitCode
                work = handler (sessStdin session) (sessStdout session) (sessStderr session)

                -- The supervisor thread waits for several event sources simultaneously,
                -- handles them and loops until the session thread has terminated and exit
                -- has been signaled or the channel/connection got closed.
                supervise :: Async.Async ExitCode -> IO ()
                supervise workerAsync = atomically (w0 <|> w1 <|> w2 <|> w3) >>= \case
                    Left  msgs -> mapM_ (connSend connection) msgs
                    Right msgs -> mapM_ (connSend connection) msgs >> supervise workerAsync
                    where
                        w0 = Left  <$> waitClose
                        w1 = Left  <$> waitExit workerAsync
                        w2 = Right <$> waitStdout
                        w3 = Right <$> waitStderr

                waitClose :: STM [Message]
                waitClose = chanClosed channel >>= check >> pure mempty

                waitExit :: Async.Async ExitCode -> STM [Message]
                waitExit thread = do
                    msg <- Async.waitCatchSTM thread >>= \case
                        Right c -> pure $ exitMessage $ ChannelRequestExitStatus c
                        Left  _ -> pure $ exitMessage $ ChannelRequestExitSignal "ILL" False "" ""
                    alreadyClosed <- chanClosed channel
                    if alreadyClosed then pure mempty else do
                        chanClose channel
                        pure [msg, MsgChannelClose $ ChannelClose $ chanIdRemote channel]
                    where
                        exitMessage :: ChannelRequestSession -> Message
                        exitMessage = MsgChannelRequest . ChannelRequest (chanIdRemote channel) . runPut . put

                waitStdout :: STM [Message]
                waitStdout = do
                    window <- getWindow
                    ba <- AQ.dequeue (sessStdout session) (fromIntegral window)
                    decWindow $ BA.length ba
                    pure [MsgChannelData $ ChannelData (chanIdRemote channel) (BA.convert ba)]

                waitStderr :: STM [Message]
                waitStderr = do
                    window <- getWindow
                    ba <- AQ.dequeue (sessStderr session) (fromIntegral window)
                    decWindow $ BA.length ba
                    pure [MsgChannelExtendedData $ ChannelExtendedData (chanIdRemote channel) 1 (BA.convert ba)]

                getWindow :: STM Int
                getWindow = do
                    -- The standard (RFC 4254) is a bit vague about window size calculation.
                    -- See https://marc.info/?l=openssh-unix-dev&m=118466419618541&w=2
                    -- for a clarification.
                    windowSize <- fromIntegral <$> readTVar (chanWindowSizeRemote channel) :: STM Word64
                    maxPacketSize <- fromIntegral <$> pure (chanMaxPacketSizeRemote channel) :: STM Word64
                    let window = min windowSize maxPacketSize
                    -- Transaction fails here if no window space is available.
                    check (window > 0)
                    -- Int is only guaranteed up to 2^29-1. Conversion to Word64 and comparison
                    -- with maxBound shall rule out undefined behaviour by potential integer overflow.
                    pure $ fromIntegral $ min (fromIntegral (maxBound :: Int)) window

                -- Decrement the outbound window by the specified number of bytes.
                decWindow :: Int -> STM ()
                decWindow i = do
                    windowSize <- readTVar (chanWindowSizeRemote channel)
                    when (fromIntegral i > windowSize) $ error "decrement smaller than available window size"
                    writeTVar (chanWindowSizeRemote channel) $! windowSize - fromIntegral i

getChannelSTM :: Connection identity -> ChannelId -> STM (Channel identity)
getChannelSTM connection channelId = do
    channels <- readTVar (connChannels connection)
    case M.lookup channelId channels of
        Just channel -> pure channel
        Nothing      -> throwSTM (Disconnect DisconnectProtocolError "invalid channel id" "")
