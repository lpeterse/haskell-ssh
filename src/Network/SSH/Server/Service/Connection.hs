{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE MultiWayIf          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Network.SSH.Server.Service.Connection
    ( Connection ()
    , connectionOpen
    , connectionClose
    , connectionChannelOpen
    , connectionChannelEof
    , connectionChannelClose
    , connectionChannelRequest
    , connectionChannelData
    , connectionChannelWindowAdjust
    , dispatcher
    ) where

import           Control.Applicative
import           Control.Concurrent
import qualified Control.Concurrent.Async     as Async
import           Control.Concurrent.STM.TVar
import           Control.Monad                (join, void, when)
import           Control.Monad.STM            (STM, atomically, check, throwSTM)
import           Control.Exception            (throwIO, bracket)
import qualified Data.ByteString              as BS
import qualified Data.Map.Strict              as M
import           Data.Word
import           System.Exit

import           Network.SSH.Encoding
import           Network.SSH.Constants
import           Network.SSH.Message
import           Network.SSH.Server.Internal
import           Network.SSH.Server.Config hiding (identity)
import qualified Network.SSH.TStreamingQueue as Q

data Connection identity
    = Connection
    { connConfig       :: Config identity
    , connIdentity     :: identity
    , connChannels     :: TVar (M.Map ChannelId Channel)
    , connSend         :: Message -> IO ()
    , connClose        :: STM ()
    , connClosed       :: STM Bool
    }

data Channel
    = Channel
    { chanApplication         :: ChannelApplication
    , chanIdRemote            :: ChannelId
    , chanMaxPacketSizeRemote :: Word32
    --, chanWindowSizeLocal     :: TVar Word32
    --, chanWindowSizeRemote    :: TVar Word32
    , chanStdin               :: Q.TStreamingQueue
    , chanStdout              :: Q.TStreamingQueue
    , chanStderr              :: Q.TStreamingQueue
    , chanClose               :: STM ()
    , chanClosed              :: STM Bool
    }

data ChannelApplication
    = ChannelApplicationSession SessionState

data SessionState
    = SessionState
    { sessEnvironment :: TVar (M.Map BS.ByteString BS.ByteString)
    , sessPtySettings :: TVar (Maybe PtySettings)
    }

dispatcher :: Config identity -> Sender -> identity -> MessageDispatcher a
dispatcher config send idnt msg0 cont0 =
    bracket (connectionOpen config idnt send) connectionClose (\c-> f c msg0 cont0)
    where 
        f connection msg (Continuation continue) = do
            handle connection msg
            continue (f connection)

        handle connection = \case
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
            msg -> do
                print msg
                connectionClose connection -- FIXME
                throwIO $ Disconnect DisconnectProtocolError "unexpected message type (2)" mempty

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

connectionChannelOpen :: Connection identity -> ChannelOpen -> IO (Either ChannelOpenFailure ChannelOpenConfirmation)
connectionChannelOpen connection (ChannelOpen channelType remoteChannelId initialWindowSize maxPacketSize) = atomically $ do
    channels <- readTVar (connChannels connection)
    case selectLocalChannelId channels of
        Nothing ->
            pure $ Left $ openFailure ChannelOpenResourceShortage
        Just localChannelId -> case channelType of
            ChannelType "session" -> do
                env          <- newTVar mempty
                pty          <- newTVar Nothing
                confirmation <- openApplicationChannel localChannelId $
                    ChannelApplicationSession SessionState
                        { sessEnvironment = env
                        , sessPtySettings = pty
                        }
                pure (Right confirmation)
            ChannelType {} ->
                pure $ Left $ openFailure ChannelOpenUnknownChannelType
    where
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
            let maxQueueSize = max 1 $ fromIntegral $ min maxBoundIntWord32
                                        (channelMaxQueueSize $ connConfig connection)
            channels      <- readTVar (connChannels connection)
            wsLocal       <- newTVar maxQueueSize
            wsRemote      <- newTVar initialWindowSize
            stdIn         <- Q.newTStreamingQueue maxQueueSize wsLocal
            stdOut        <- Q.newTStreamingQueue maxQueueSize wsRemote
            stdErr        <- Q.newTStreamingQueue maxQueueSize wsRemote
            closed        <- newTVar False
            let channel = Channel {
                    chanApplication         = application
                  , chanIdRemote            = remoteChannelId
                  , chanMaxPacketSizeRemote = maxPacketSize
                  --, chanWindowSizeLocal     = wsLocal
                  --, chanWindowSizeRemote    = wsRemote
                  , chanStdin               = stdIn
                  , chanStdout              = stdOut
                  , chanStderr              = stdErr
                  , chanClose               = writeTVar closed True
                  , chanClosed              = (||) <$> connClosed connection <*> readTVar closed
                  }
            writeTVar (connChannels connection) $! M.insert localChannelId channel channels
            pure $ ChannelOpenConfirmation
                remoteChannelId
                localChannelId
                maxQueueSize
                (channelMaxPacketSize $ connConfig connection)

connectionChannelEof :: Connection identity -> ChannelEof -> IO ()
connectionChannelEof connection (ChannelEof localChannelId) = atomically $ do
    channel <- getChannelSTM connection localChannelId
    Q.terminate (chanStdin channel)

connectionChannelClose :: Connection identity -> ChannelClose -> IO (Maybe ChannelClose)
connectionChannelClose connection (ChannelClose localChannelId) = atomically $ do
    channel <- getChannelSTM connection localChannelId
    channels <- readTVar (connChannels connection)
    writeTVar (connChannels connection) $! M.delete localChannelId channels
    alreadyClosed <- chanClosed channel
    -- When the channel is not marked as already closed then the close
    -- must have been initiated by the client and the server needs to send
    -- a confirmation.
    if alreadyClosed then pure Nothing else do
        chanClose channel
        pure $ Just $ ChannelClose $ chanIdRemote channel

connectionChannelData :: Connection identity -> ChannelData -> IO ()
connectionChannelData connection (ChannelData localChannelId payload) = atomically $ do
    channel <- getChannelSTM connection localChannelId
    i <- Q.enqueue (chanStdin channel) payload <|> exceptionWindowSize
    when (i == 0) exceptionDataAfterEof
    when (i /= payloadLen) exceptionWindowSize
    where
        payloadLen            = fromIntegral $ BS.length payload
        exception msg         = throwSTM $ Disconnect DisconnectProtocolError msg mempty
        exceptionWindowSize   = exception "window size underrun"
        exceptionDataAfterEof = exception "data after eof"

connectionChannelWindowAdjust :: Connection identity -> ChannelWindowAdjust -> IO ()
connectionChannelWindowAdjust connection (ChannelWindowAdjust channelId increment) = atomically $ do
    channel <- getChannelSTM connection channelId
    Q.addWindowSpace (chanStdout channel) increment <|> exception "window size overflow"
    where
        exception msg = throwSTM $ Disconnect DisconnectProtocolError msg mempty

connectionChannelRequest :: forall identity. Connection identity -> ChannelRequest -> IO (Maybe (Either ChannelFailure ChannelSuccess))
connectionChannelRequest connection (ChannelRequest channelId typ wantReply dat) = join $ atomically $ do
    channel <- getChannelSTM connection channelId
    case chanApplication channel of
        ChannelApplicationSession sessionState -> case typ of
            "env" -> interpret $ \(ChannelRequestEnv name value) -> do
                env <- readTVar (sessEnvironment sessionState)
                writeTVar (sessEnvironment sessionState) $! M.insert name value env
                pure $ success channel
            "pty-req" -> interpret $ \(ChannelRequestPty settings) -> do
                writeTVar (sessPtySettings sessionState) (Just settings)
                pure $ success channel
            "shell" -> interpret $ \ChannelRequestShell ->
                case onShellRequest (connConfig connection) of
                    Nothing-> pure $ failure channel
                    Just exec -> pure $ do
                        sessionExec channel sessionState exec
                        success channel
            "exec" -> interpret $ \(ChannelRequestExec command) ->
                case onExecRequest (connConfig connection) of
                    Nothing-> pure $ failure channel
                    Just exec -> pure $ do
                        sessionExec channel sessionState $ flip exec command
                        success channel
            -- "signal" ->
            -- "exit-status" ->
            -- "exit-signal" ->
            -- "window-change" ->
            _ -> pure $ failure channel
    where
        exception e     = throwSTM $ Disconnect DisconnectProtocolError e mempty
        interpret f     = maybe (exception "invalid channel request") f (runGet get dat)
        success channel
            | wantReply = pure $ Just $ Right $ ChannelSuccess (chanIdRemote channel)
            | otherwise = pure $ channel `seq` Nothing -- 100% test coverage ;-)
        failure channel = pure $ Just $ Left  $ ChannelFailure (chanIdRemote channel)

        sessionExec :: Channel -> SessionState -> (Session identity -> IO ExitCode) -> IO ()
        sessionExec channel sessState handle = do
            session <- Session (connIdentity connection)
                <$> readTVarIO (sessEnvironment sessState)
                <*> pure (chanStdin channel)
                <*> pure (chanStdout channel)
                <*> pure (chanStderr channel)
            -- Two threads are forked: a worker thread running as Async and a dangling
            -- supervisor thread.
            -- -> The worker thread does never outlive the supervisor thread (`withAsync`).
            -- -> The supervisor thread terminates itself when either the worker thread
            --    has terminated (`waitExit`) or if the channel/connection has been closed
            --    (`waitClose`).
            void $ forkIO $ Async.withAsync (handle session) supervise
            where
                -- The supervisor thread waits for several event sources simultaneously,
                -- handles them and loops until the session thread has terminated and exit
                -- has been signaled or the channel/connection got closed.
                supervise :: Async.Async ExitCode -> IO ()
                supervise workerAsync = atomically (w0 <|> w1 <|> w2 <|> w3 <|> w4) >>= \case
                    Left  msgs -> mapM_ (connSend connection) msgs
                    Right msgs -> mapM_ (connSend connection) msgs >> supervise workerAsync
                    where
                        -- NB: The order is critical: Another order would cause a close
                        -- or eof to be sent before all data has been flushed.
                        w0 = Right <$> waitStdout
                        w1 = Right <$> waitStderr
                        w2 = Left  <$> waitClose
                        w3 = Left  <$> waitExit workerAsync
                        w4 = Right <$> waitLocalWindowAdjust

                waitClose :: STM [Message]
                waitClose = chanClosed channel >>= check >> pure mempty

                waitExit :: Async.Async ExitCode -> STM [Message]
                waitExit thread = do
                    exitMessage <- Async.waitCatchSTM thread >>= \case
                        Right c -> pure $ req "exit-status" $ runPut $ put $ ChannelRequestExitStatus c
                        Left  _ -> pure $ req "exit-signal" $ runPut $ put $ ChannelRequestExitSignal "ILL" False "" ""
                    chanClose channel
                    pure [eofMessage, exitMessage, closeMessage]
                    where
                        req t        = MsgChannelRequest . ChannelRequest (chanIdRemote channel) t False
                        eofMessage   = MsgChannelEof $ ChannelEof (chanIdRemote channel)
                        closeMessage = MsgChannelClose $ ChannelClose (chanIdRemote channel)

                waitStdout :: STM [Message]
                waitStdout = do
                    bs <- Q.dequeue (chanStdout channel) (chanMaxPacketSizeRemote channel)
                    pure [MsgChannelData $ ChannelData (chanIdRemote channel) bs]

                waitStderr :: STM [Message]
                waitStderr = do
                    bs <- Q.dequeue (chanStderr channel) (chanMaxPacketSizeRemote channel)
                    pure [MsgChannelExtendedData $ ChannelExtendedData (chanIdRemote channel) 1 bs]

                waitLocalWindowAdjust :: STM [Message]
                waitLocalWindowAdjust = do
                    check =<< Q.askWindowSpaceAdjustRecommended (chanStdin channel)
                    increaseBy <- Q.fillWindowSpace (chanStdin channel)
                    pure [MsgChannelWindowAdjust $ ChannelWindowAdjust (chanIdRemote channel) increaseBy]

getChannelSTM :: Connection identity -> ChannelId -> STM Channel
getChannelSTM connection channelId = do
    channels <- readTVar (connChannels connection)
    case M.lookup channelId channels of
        Just channel -> pure channel
        Nothing      -> throwSTM (Disconnect DisconnectProtocolError "invalid channel id" "")
