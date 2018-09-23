{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE MultiWayIf          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Network.SSH.Server.Service.Connection.Channel where

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
import           Network.SSH.Server.Service.Connection.Internal
import qualified Network.SSH.TAccountingQueue as AQ

handleChannelOpen :: forall identity. Connection identity -> ChannelOpen -> IO ()
handleChannelOpen connection (ChannelOpen channelType remoteChannelId initialWindowSize maxPacketSize) =
    atomically openSTM >>= connOutput connection
    where
        openSTM :: STM Message
        openSTM = do
            channels <- readTVar (connChannels connection)
            case selectLocalChannelId channels of
                Nothing ->
                    pure $ openFailure ChannelOpenResourceShortage
                Just localChannelId -> case channelType of
                    ChannelType "session" -> do
                        env    <- newTVar mempty
                        pty    <- newTVar Nothing
                        thread <- newTVar Nothing
                        stdin  <- AQ.newTAccountingQueue 1024
                        stdout <- AQ.newTAccountingQueue 1024
                        stderr <- AQ.newTAccountingQueue 1024
                        openApplicationChannel localChannelId $ ChannelApplicationSession Session {
                            sessEnvironment = env
                            , sessTerminal    = pty
                            , sessThread      = thread
                            , sessStdin       = stdin
                            , sessStdout      = stdout
                            , sessStderr      = stderr
                            }
                    ChannelType {} ->
                        pure $ openFailure ChannelOpenUnknownChannelType

        selectLocalChannelId :: M.Map ChannelId a -> Maybe ChannelId
        selectLocalChannelId m
            | M.size m >= fromIntegral maxCount = Nothing
            | otherwise = f (ChannelId 1) $ M.keys m
            where
                f i [] = Just i
                f (ChannelId i) (ChannelId k:ks)
                    | i == maxBound = Nothing
                    | i == k        = f (ChannelId $ i+1) ks
                    | otherwise     = Just (ChannelId i)
                maxCount = channelMaxCount (connConfig connection)

        openFailure :: ChannelOpenFailureReason -> Message
        openFailure reason = MsgChannelOpenFailure $
            ChannelOpenFailure remoteChannelId reason mempty mempty

        openApplicationChannel :: ChannelId -> ChannelApplication -> STM Message
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
                  , chanClosed              = closed
                  }
            writeTVar (connChannels connection) $! M.insert localChannelId channel channels
            pure $ MsgChannelOpenConfirmation $ ChannelOpenConfirmation
                remoteChannelId
                localChannelId
                (channelMaxWindowSize $ connConfig connection)
                (channelMaxPacketSize $ connConfig connection)

handleChannelClose :: Connection identtiy -> ChannelClose -> IO ()
handleChannelClose connection (ChannelClose localChannelId) =
    atomically closeSTM >>= \case
      Nothing  -> pure ()
      Just msg -> connOutput connection msg 
    where
        closeSTM = do
            channels <- readTVar (connChannels connection)
            case M.lookup localChannelId channels of
                -- The client tries to close the same channel twice.
                -- This is a protocol error and the server shall disconnect.
                Nothing ->
                    throwSTM $ Disconnect DisconnectProtocolError mempty mempty
                Just channel -> do
                    writeTVar (connChannels connection) $! M.delete localChannelId channels
                    alreadyClosed <- swapTVar (chanClosed channel) True
                    -- When the channel is not marked as already closed then the close
                    -- must have been initiated by the client and the server needs to send
                    -- a confirmation.
                    pure $ if alreadyClosed
                        then Nothing
                        else Just $ MsgChannelClose $ ChannelClose $ chanIdRemote channel

handleChannelEof :: Connection identity -> ChannelEof -> IO ()
handleChannelEof = undefined

handleChannelData :: Connection identity -> ChannelData -> IO ()
handleChannelData = undefined

handleChannelExtendedData :: Connection identity -> ChannelExtendedData -> IO ()
handleChannelExtendedData = undefined

getChannel :: Connection identity -> ChannelId -> STM (Channel identity)
getChannel connection channelId = do
    channels <- readTVar (connChannels connection)
    case M.lookup channelId channels of
        Just channel -> pure channel
        Nothing      -> throwSTM (Disconnect DisconnectProtocolError "invalid channel id" "")

handleChannelWindowAdjust :: Connection identity -> ChannelWindowAdjust -> IO ()
handleChannelWindowAdjust connection (ChannelWindowAdjust channelId increase) =
    atomically $ do
        channel <- getChannel connection channelId
        windowSize <- readTVar (chanWindowSizeRemote channel)
        let windowSize' = fromIntegral windowSize + fromIntegral increase :: Word64
        -- Conversion to Word64 necessary for overflow check.
        when (windowSize' > 2 ^ (32 :: Word64) - 1) $
            throwSTM $ Disconnect DisconnectProtocolError "window size overflow" mempty
        -- Conversion from Word64 to Word32 never undefined as guaranteed by previous check.
        writeTVar (chanWindowSizeRemote channel) (fromIntegral windowSize')

handleChannelRequest :: forall identity. Connection identity -> ChannelRequest -> IO ()
handleChannelRequest connection (ChannelRequest channelId request) =
    join $ atomically $ do
        channel <- getChannel connection channelId
        case chanApplication channel of
            ChannelApplicationSession session -> interpretAsSessionRequest channel session request
    where
        pass                 = pure $ pure ()
        throwProtocolError e = throwSTM $ Disconnect DisconnectProtocolError e mempty
        sendSuccess channel  = connOutput connection $ MsgChannelSuccess $ ChannelSuccess (chanIdRemote channel)
        sendFailure channel  = connOutput connection $ MsgChannelFailure $ ChannelFailure (chanIdRemote channel)

        interpretAsSessionRequest :: Channel identity -> Session -> BS.ByteString -> STM (IO ())
        interpretAsSessionRequest channel session req = case runGet get req of
            Nothing -> throwProtocolError "invalid session channel request"
            Just sessionRequest -> case sessionRequest of
                ChannelRequestEnv wantReply name value -> do
                    env <- readTVar (sessEnvironment session)
                    writeTVar (sessEnvironment session) $! M.insert name value env
                    pure $
                        when wantReply $ sendSuccess channel
                ChannelRequestPty _wantReply _ptySettings ->
                    throwProtocolError "pty-req not yet implemented"
                ChannelRequestShell _wantReply ->
                    throwProtocolError "shell req not yet implemented"
                ChannelRequestExec wantReply command -> case onExecRequest (connConfig connection) of
                    Nothing-> pure $
                        when wantReply $ sendFailure channel
                    Just exec -> readTVar (connIdentity connection) >>= \identity -> pure $ do
                        when wantReply $ sendSuccess channel
                        sessionExec connection channel session (\s0 s1 s2-> exec identity s0 s1 s2 command)
                ChannelRequestOther _ wantReply -> pure $
                    when wantReply $ sendFailure channel
                ChannelRequestExitStatus {} -> pass
                ChannelRequestExitSignal {} -> pass

close :: Channel identity -> STM (Maybe Message)
close channel = do
    alreadyClosed <- swapTVar (chanClosed channel) True
    pure $ if alreadyClosed
        then Nothing
        else Just $ MsgChannelClose $ ChannelClose $ chanIdRemote channel

sessionExec :: Connection identity -> Channel identity -> Session
            -> (AQ.TAccountingQueue -> AQ.TAccountingQueue -> AQ.TAccountingQueue -> IO ExitCode) -> IO ()
sessionExec connection channel session handler =
    void $ forkIO $ Async.withAsync action wait
    where
        action :: IO ExitCode
        action = handler (sessStdin session) (sessStdout session) (sessStderr session)

        -- Waits for several event sources simultaneously, handles them and
        -- loops until the session thread has terminated and exit has been signaled.
        wait :: Async.Async ExitCode ->IO ()
        wait thread = do
            atomically (Right <$> waitStdout <|> Right <$> waitStderr <|> Left <$> waitExit thread) >>= \case
                Left  msgs -> mapM_ (connOutput connection) msgs
                Right msgs -> mapM_ (connOutput connection) msgs >> wait thread

        waitExit :: Async.Async ExitCode -> STM [Message]
        waitExit thread = do
            msg <- Async.waitCatchSTM thread >>= \case
                Right c -> pure $ exitMessage $ ChannelRequestExitStatus c
                Left  _ -> pure $ exitMessage $ ChannelRequestExitSignal "ILL" False "" ""
            close channel >>= \case
                Nothing -> pure [msg]
                Just m  -> pure [msg,m]
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
