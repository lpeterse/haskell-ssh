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
    , connectionChannelEof
    , connectionChannelClose
    , connectionChannelRequest
    , connectionChannelData
    , connectionChannelWindowAdjust
    ) where

import           Control.Applicative
import           Control.Concurrent
import qualified Control.Concurrent.Async     as Async
import           Control.Concurrent.STM.TVar
import           Control.Monad                (join, void, when)
import           Control.Monad.STM            (STM, atomically, check, throwSTM, retry)
import qualified Data.ByteString              as BS
import qualified Data.Map.Strict              as M
import           Data.Maybe
import           Data.Word
import           System.Exit

import           Network.SSH.Encoding
import           Network.SSH.Constants
import           Network.SSH.Message
import           Network.SSH.Server.Config
import qualified Network.SSH.TStreamingQueue as Q

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
    , chanStdin               :: Q.TStreamingQueue
    , chanStdout              :: Q.TStreamingQueue
    , chanStderr              :: Q.TStreamingQueue
    , chanEofSent             :: TVar Bool
    , chanEofReceived         :: TVar Bool
    , chanCloseSent           :: TVar Bool
    , chanCloseReceived       :: TVar Bool
    , chanClose               :: STM ()
    , chanClosed              :: STM Bool
    }

data ChannelApplication
    = ChannelApplicationSession Session

data Session
    = Session
    { sessEnvironment :: TVar (M.Map BS.ByteString BS.ByteString)
    , sessPtySettings :: TVar (Maybe PtySettings)
    , sessThread      :: TVar (Maybe ThreadId)
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
connectionChannelOpen connection (ChannelOpen channelType remoteChannelId initialWindowSize maxPacketSize) = atomically $ do
    channels <- readTVar (connChannels connection)
    case selectLocalChannelId channels of
        Nothing ->
            pure $ Left $ openFailure ChannelOpenResourceShortage
        Just localChannelId -> case channelType of
            ChannelType "session" -> do
                env          <- newTVar mempty
                pty          <- newTVar Nothing
                thread       <- newTVar Nothing
                confirmation <- openApplicationChannel localChannelId $
                    ChannelApplicationSession Session
                        { sessEnvironment = env
                        , sessPtySettings = pty
                        , sessThread      = thread
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
            stdin         <- Q.newTStreamingQueue maxQueueSize wsLocal
            stdout        <- Q.newTStreamingQueue maxQueueSize wsRemote
            stderr        <- Q.newTStreamingQueue maxQueueSize wsRemote
            eofSent       <- newTVar False
            eofReceived   <- newTVar False
            closeSent     <- newTVar False
            closeReceived <- newTVar False
            closed        <- newTVar False
            let channel = Channel {
                    chanConnection          = connection
                  , chanApplication         = application
                  , chanIdLocal             = localChannelId
                  , chanIdRemote            = remoteChannelId
                  , chanMaxPacketSizeRemote = maxPacketSize
                  , chanWindowSizeLocal     = wsLocal
                  , chanWindowSizeRemote    = wsRemote
                  , chanStdin               = stdin
                  , chanStdout              = stdout
                  , chanStderr              = stderr
                  , chanEofSent             = eofSent
                  , chanEofReceived         = eofReceived
                  , chanCloseSent           = closeSent
                  , chanCloseReceived       = closeReceived
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
    writeTVar (chanEofReceived channel) True

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
    eofReceived <- readTVar (chanEofReceived channel)
    when eofReceived $ exception "data after eof"
    enqueued <- Q.enqueue (chanStdin channel) payload <|> pure 0
    when (enqueued /= payloadLen) (exception "window size underrun")
    where
        exception msg = throwSTM $ Disconnect DisconnectProtocolError msg mempty
        payloadLen    = fromIntegral $ BS.length payload

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
        ChannelApplicationSession session -> case typ of
            "env" -> interpret $ \(ChannelRequestEnv name value) -> do
                env <- readTVar (sessEnvironment session)
                writeTVar (sessEnvironment session) $! M.insert name value env
                pure $ success channel
            "pty-req" -> interpret $ \(ChannelRequestPty settings) -> do
                writeTVar (sessPtySettings session) (Just settings)
                pure $ success channel
            "shell" -> interpret $ \ChannelRequestShell ->
                case onShellRequest (connConfig connection) of
                    Nothing-> pure $ failure channel
                    Just exec -> pure $ do
                        sessionExec channel session $ exec (connIdentity connection)
                        success channel
            "exec" -> interpret $ \(ChannelRequestExec command) ->
                case onExecRequest (connConfig connection) of
                    Nothing-> pure $ failure channel
                    Just exec -> pure $ do
                        sessionExec channel session $ \s0 s1 s2-> exec (connIdentity connection) s0 s1 s2 command
                        success channel
            -- "signal" ->
            -- "exit-status" ->
            -- "exit-signal" ->
            -- "window-change" ->
            _ -> pure $ failure channel
    where
        exception e     = throwSTM $ Disconnect DisconnectProtocolError e mempty
        interpret f     = fromMaybe (exception "invalid channel request") (f <$> runGet get dat)
        success channel
            | wantReply = pure $ Just $ Right $ ChannelSuccess (chanIdRemote channel)
            | otherwise = pure Nothing
        failure channel
            | wantReply = pure $ Just $ Left  $ ChannelFailure (chanIdRemote channel)
            | otherwise = pure Nothing

        sessionExec :: Channel identity -> Session
                    -> (Q.TStreamingQueue -> Q.TStreamingQueue -> Q.TStreamingQueue -> IO ExitCode) -> IO () 
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
                work = handler (chanStdin channel) (chanStdout channel) (chanStderr channel)

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
                        req typ      = MsgChannelRequest . ChannelRequest (chanIdRemote channel) typ False 
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

getChannelSTM :: Connection identity -> ChannelId -> STM (Channel identity)
getChannelSTM connection channelId = do
    channels <- readTVar (connChannels connection)
    case M.lookup channelId channels of
        Just channel -> pure channel
        Nothing      -> throwSTM (Disconnect DisconnectProtocolError "invalid channel id" "")
