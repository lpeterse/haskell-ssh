{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE MultiWayIf          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Network.SSH.Server.Channel where

import           Control.Applicative
import           Control.Concurrent
import qualified Control.Concurrent.Async     as Async
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Concurrent.STM.TVar
import           Control.Exception
import           Control.Monad                (forever, join, unless, void,
                                               when)
import           Control.Monad.STM
import qualified Data.ByteArray               as BA
import qualified Data.ByteString              as BS
import           Data.Function                (fix)
import qualified Data.Map.Strict              as M
import           Data.Maybe
import           Data.Text                    as T
import           Data.Text.Encoding           as T
import           Data.Typeable
import           Data.Word
import           System.Exit

import           Network.SSH.Constants
import qualified Network.SSH.DuplexStream     as DS
import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport
import           Network.SSH.Server.Types
import qualified Network.SSH.TAccountingQueue as AQ

handleChannelOpen :: Connection identity -> ChannelOpen -> IO ()
handleChannelOpen connection (ChannelOpen channelType remoteChannelId initialWindowSize maxPacketSize) = atomically $ do
    channels <- readTVar (connChannels connection)
    case selectLocalChannelId channels of
        Nothing ->
            sendOpenFailure ChannelOpenResourceShortage
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
                sendOpenFailure ChannelOpenUnknownChannelType
    where
        selectLocalChannelId :: M.Map ChannelId a -> Maybe ChannelId
        selectLocalChannelId m
            | M.size m >= channelMaxCount (connConfig connection) = Nothing
            | otherwise = f (ChannelId 1) $ M.keys m
            where
                f i [] = Just i
                f (ChannelId i) (ChannelId k:ks)
                    | i == maxBound = Nothing
                    | i == k        = f (ChannelId $ i+1) ks
                    | otherwise     = Just (ChannelId i)

        sendOpenFailure :: ChannelOpenFailureReason -> STM ()
        sendOpenFailure reason = send connection $ MsgChannelOpenFailure $
            ChannelOpenFailure remoteChannelId reason mempty mempty

        sendOpenConfirmation :: ChannelOpenConfirmation -> STM ()
        sendOpenConfirmation = send connection . MsgChannelOpenConfirmation

        openApplicationChannel :: ChannelId -> ChannelApplication -> STM ()
        openApplicationChannel localChannelId application = do
            channels <- readTVar (connChannels connection)
            wsLocal  <- newTVar initialWindowSize
            wsRemote <- newTVar initialWindowSize
            closed   <- newTVar False
            let channel = Channel {
                    chanConnection          = connection
                  , chanApplication         = application
                  , chanIdLocal             = localChannelId
                  , chanIdRemote            = remoteChannelId
                  , chanMaxPacketSizeLocal  = maxPacketSize
                  , chanMaxPacketSizeRemote = maxPacketSize
                  , chanWindowSizeLocal     = wsLocal
                  , chanWindowSizeRemote    = wsRemote
                  , chanClosed              = closed
                  }
            writeTVar (connChannels connection) $! M.insert localChannelId channel channels
            sendOpenConfirmation $ ChannelOpenConfirmation
                remoteChannelId
                localChannelId
                initialWindowSize
                maxPacketSize

handleChannelClose :: Connection identtiy -> ChannelClose -> IO ()
handleChannelClose connection (ChannelClose localChannelId) = atomically $ do
    channels <- readTVar (connChannels connection)
    case M.lookup localChannelId channels of
        -- The client tries to close the same channel twice.
        -- This is a protocol error and the server shall disconnect.
        Nothing ->
            disconnectWith connection DisconnectProtocolError
        Just channel -> do
            writeTVar (connChannels connection) $! M.delete localChannelId channels
            alreadyClosed <- swapTVar (chanClosed channel) True
            -- When the channel is not marked as already closed then the close
            -- must have been initiated by the client and the server needs to send
            -- a confirmation.
            unless alreadyClosed $
                send connection $ MsgChannelClose $ ChannelClose $ chanIdRemote channel

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
handleChannelWindowAdjust connection (ChannelWindowAdjust channelId (Size increase)) =
    atomically $ do
        channel <- getChannel connection channelId
        Size ws <- readTVar (chanWindowSizeRemote channel)
        -- Conversion to Word64 necessary for overflow check.
        let ws' = fromIntegral ws + fromIntegral increase :: Word64
        when (ws' > 2 ^ 32 - 1) $
            throwSTM $ Disconnect DisconnectProtocolError "window size overflow" mempty
        writeTVar (chanWindowSizeRemote channel) $ Size (fromIntegral ws')

handleChannelRequest :: forall identity. Connection identity -> ChannelRequest -> IO ()
handleChannelRequest connection (ChannelRequest channelId request) =
    join $ atomically $ do
        channel <- getChannel connection channelId
        case chanApplication channel of
            ChannelApplicationSession session -> interpretAsSessionRequest channel session request
    where
        pass                 = pure $ pure ()
        throwProtocolError e = throwSTM $ Disconnect DisconnectProtocolError e mempty
        sendSuccess channel  = send connection $ MsgChannelSuccess $ ChannelSuccess (chanIdRemote channel)
        sendFailure channel  = send connection $ MsgChannelFailure $ ChannelFailure (chanIdRemote channel)

        interpretAsSessionRequest :: Channel identity -> Session -> BS.ByteString -> STM (IO ())
        interpretAsSessionRequest channel session request = case runGet get request of
            Nothing -> throwProtocolError "invalid session channel request"
            Just sessionRequest -> case sessionRequest of
                ChannelRequestEnv wantReply name value -> do
                    env <- readTVar (sessEnvironment session)
                    writeTVar (sessEnvironment session) $! M.insert name value env
                    when wantReply (sendSuccess channel)
                    pass
                ChannelRequestPty wantReply ptySettings ->
                    throwProtocolError "pty-req not yet implemented"
                ChannelRequestShell wantReply ->
                    throwProtocolError "shell req not yet implemented"
                ChannelRequestExec wantReply command -> case onExecRequest (connConfig connection) of
                    Nothing -> do
                        when wantReply (sendFailure channel)
                        pass
                    Just exec -> readTVar (connIdentity connection) >>= \case
                        Nothing -> do
                          when wantReply (sendFailure channel)
                          pass
                        Just identity -> do
                          when wantReply (sendSuccess channel)
                          pure (sessionExec connection channel session (\s0 s1 s2-> exec identity s0 s1 s2 command))
                ChannelRequestOther _ wantReply -> do
                    when wantReply (sendFailure channel)
                    pass

-- Free all associated resources like threads etc.
free :: Channel identity -> IO ()
free channel = pure ()

close :: Channel identity -> STM ()
close channel = do
    alreadyClosed <- swapTVar (chanClosed channel) True
    unless alreadyClosed $
        send (chanConnection channel) $ MsgChannelClose $ ChannelClose $ chanIdRemote channel

sessionExec :: Connection identity -> Channel identity -> Session
            -> (AQ.TAccountingQueue -> AQ.TAccountingQueue -> AQ.TAccountingQueue -> IO ExitCode) -> IO ()
sessionExec connection channel session handler =
    void $ forkIO $ Async.withAsync thread wait
    where
        thread :: IO ExitCode
        thread = handler (sessStdin session) (sessStdout session) (sessStderr session)

        -- Waits for several event sources simultaneously, handles them and
        -- loops until the session thread has terminated and exit has been signaled.
        wait :: Async.Async ExitCode ->IO ()
        wait thread = do
            exit <- atomically $ waitStdout <|> waitStderr <|> waitExit thread
            unless exit (wait thread)

        waitExit :: Async.Async ExitCode -> STM Bool
        waitExit thread = do
            Async.waitCatchSTM thread >>= \case
                Right c -> sendExit $ ChannelRequestExitStatus c
                Left  _ -> sendExit $ ChannelRequestExitSignal "ILL" False "" ""
            close channel
            pure True
            where
                sendExit :: ChannelRequestSession -> STM ()
                sendExit = send connection . MsgChannelRequest
                    . ChannelRequest (chanIdRemote channel) . runPut . put

        waitStdout :: STM Bool
        waitStdout = do
            window <- getWindow
            ba <- AQ.dequeue (sessStdout session) window
            decWindow (BA.length ba)
            send connection $ MsgChannelData $ ChannelData (chanIdRemote channel) (BA.convert ba)
            pure False

        waitStderr :: STM Bool
        waitStderr = do
            window <- getWindow
            ba <- AQ.dequeue (sessStderr session) window
            decWindow (BA.length ba)
            send connection $ MsgChannelExtendedData $ ChannelExtendedData (chanIdRemote channel) 1 (BA.convert ba)
            pure False

        getWindow :: STM Int
        getWindow = do
            -- The standard (RFC 4254) is a bit vague about window size calculation.
            -- See https://marc.info/?l=openssh-unix-dev&m=118466419618541&w=2
            -- for a clarification.
            Size windowSize <- readTVar (chanWindowSizeRemote channel)
            Size maxPacketSize <- pure (chanMaxPacketSizeRemote channel)
            let window = min windowSize maxPacketSize
            check (window > 0) -- transaction fails here if no window space is available
            pure $ fromIntegral window

        decWindow :: Int -> STM ()
        decWindow i = do
            Size windowSize <- readTVar (chanWindowSizeRemote channel)
            writeTVar (chanWindowSizeRemote channel) (Size $ windowSize - fromIntegral i)
