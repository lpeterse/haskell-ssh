{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiWayIf                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE ExistentialQuantification  #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.SSH.Server.Connection
    ( Connection ()
    , ConnectionConfig (..)
    , SessionHandler (..)
    , DirectTcpIpHandler (..)
    , serveConnection
    ) where

import           Control.Applicative
import           Control.Concurrent
import qualified Control.Concurrent.Async     as Async
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Control.Monad                (join, when, forever, unless, void)
import           Control.Monad.STM            (STM, atomically, check, throwSTM, retry)
import           Control.Exception            (bracket, onException, throwIO)
import qualified Data.ByteString.Short        as SBS
import           Data.Default
import qualified Data.Map.Strict              as M
import qualified Data.Set                     as Set
import           Data.Word
import           System.Exit

import           Network.SSH.Encoding
import           Network.SSH.Environment
import           Network.SSH.Exception
import           Network.SSH.Constants
import           Network.SSH.Address
import           Network.SSH.Message
import           Network.SSH.Name
import qualified Network.SSH.Stream as S
import           Network.SSH.Server.Switchboard
import           Network.SSH.TermInfo
import qualified Network.SSH.TWindowBuffer as B

data ConnectionConfig state user
    = ConnectionConfig
    { onSessionRequest      :: state -> user -> IO (Maybe SessionHandler)
      -- ^ This callback will be executed for every session request.
      --
      --   Return a `SessionHandler` or `Nothing` to reject the request (default).
    , onDirectTcpIpRequest  :: state -> user -> SourceAddress -> DestinationAddress -> IO (Maybe DirectTcpIpHandler)
      -- ^ This callback will be executed for every direct-tcpip request.
      --
      --   Return a `DirectTcpIpHandler` or `Nothing` to reject the request (default).
    , channelMaxCount       :: Int
      -- ^ The maximum number of channels that may be active simultaneously (default: 256).
      --
      --   Any requests that would exceed the limit will be rejected.
      --   Setting the limit to high values might expose the server to denial
      --   of service issues!
    , channelMaxBufferSize  :: Word32
      -- ^ The maximum size of the internal buffers in bytes (also
      --   limits the maximum window size, default: 32 kB)
      --
      --   Increasing this value might help with performance issues
      --   (if connection delay is in a bad ration with the available bandwidth the window
      --   resizing might cause unncessary throttling).
    , channelMaxPacketSize  :: Word32
      -- ^ The maximum size of inbound channel data payload (default: 32 kB)
      --
      --   Values that are larger than `channelMaxBufferSize` or the
      --   maximum uncompressed packet size (35000 bytes) will be automatically adjusted
      --   to the maximum possible value.
    , switchboard           :: Maybe Switchboard
    }

instance Default (ConnectionConfig state user) where
    def = ConnectionConfig
        { onSessionRequest              = \_ _ -> pure Nothing
        , onDirectTcpIpRequest          = \_ _ _ _ -> pure Nothing
        , channelMaxCount               = 256
        , channelMaxBufferSize          = 32 * 1024
        , channelMaxPacketSize          = 32 * 1024
        , switchboard                   = Nothing
        }

-- | The session handler contains the application logic that serves a client's
--   shell or exec request.
--
--   * The `Command` parameter will be present if this is an exec request and absent
--     for shell requests.
--   * The `TermInfo` parameter will be present if the client requested a pty.
--   * The `Environment` parameter contains the set of all env requests
--     the client issued before the actual shell or exec request.
--   * @stdin@, @stdout@ and @stderr@ are streams. The former can only be read
--     from while the latter can only be written to.
--     After the handler has gracefully terminated, the implementation assures
--     that all bytes will be sent before sending an eof and actually closing the
--     channel.
--     has gracefully terminated. The client will then receive an eof and close.
--   * A @SIGILL@ exit signal will be sent if the handler terminates with an exception.
--     Otherwise the client will receive the returned exit code.
--
-- @
-- handler :: SessionHandler
-- handler = SessionHandler $ \\env mterm mcmd stdin stdout stderr -> case mcmd of
--     Just "echo" -> do
--         bs <- `receive` stdin 1024
--         `sendAll` stdout bs
--         pure `ExitSuccess`
--     Nothing ->
--         pure (`ExitFailure` 1)
-- @
newtype SessionHandler =
    SessionHandler (forall stdin stdout stderr. (S.InputStream stdin, S.OutputStream stdout, S.OutputStream stderr)
        => Environment -> Maybe TermInfo -> Maybe Command -> stdin -> stdout -> stderr -> IO ExitCode)

-- | The `DirectTcpIpHandler` contains the application logic
--   that handles port forwarding requests.
--
--   There is of course no need to actually do a real forwarding - this
--   mechanism might also be used to give access to process internal services
--   like integrated web servers etc.
--
--   * When the handler exits gracefully, the implementation assures that
--     all bytes will be sent to the client before terminating the stream
--     with an eof and actually closing the channel.
newtype DirectTcpIpHandler =
    DirectTcpIpHandler (forall stream. S.DuplexStream stream => stream -> IO ())

data Connection state user
    = Connection
    { connConfig       :: ConnectionConfig state user
    , connState        :: state
    , connUser         :: user
    , connClosed       :: TVar Bool
    , connChannels     :: TVar (M.Map ChannelId ChannelState)
    , connForwardings  :: TVar (Set.Set Address)
    , connResponse     :: TMVar (Either RequestFailure RequestSuccess)
    , connQueue        :: TChan ConnectionMessage
    }

data ChannelState
    = ChannelOpening (Either ChannelOpenFailure ChannelOpenConfirmation -> STM ())
    | ChannelRunning Channel
    | ChannelClosing

data Channel
    = Channel
    { chanApplication         :: ChannelApplication
    , chanIdLocal             :: ChannelId
    , chanIdRemote            :: ChannelId
    , chanWindowSizeLocal     :: TVar Word32
    , chanWindowSizeRemote    :: TVar Word32
    , chanMaxPacketSizeLocal  :: Word32
    , chanMaxPacketSizeRemote :: Word32
    , chanEofSent             :: TVar Bool
    , chanClosed              :: TVar Bool
    , chanResponse            :: TMVar (Either ChannelFailure ChannelSuccess)
    }

data ChannelApplication
    = ChannelApplicationSession SessionState
    | ChannelApplicationDirectTcpIp DirectTcpIpState
    | ChannelApplicationForwardedTcpIp ForwardedTcpIpState

data SessionState
    = SessionState
    { sessHandler     :: SessionHandler
    , sessEnvironment :: TVar Environment
    , sessPtySettings :: TVar (Maybe PtySettings)
    , sessStdin       :: B.TWindowBuffer
    , sessStdout      :: B.TWindowBuffer
    , sessStderr      :: B.TWindowBuffer
    }

data DirectTcpIpState
    = DirectTcpIpState
    { dtiStreamIn     :: B.TWindowBuffer
    , dtiStreamOut    :: B.TWindowBuffer
    }

data ForwardedTcpIpState
    = ForwardedTcpIpState
    { ftiStreamIn     :: B.TWindowBuffer
    , ftiStreamOut    :: B.TWindowBuffer
    }

-- | Serve a single client connection (see RFC 4254).
--
-- * This operation never returns. Connection close is a matter of the transport layer.
-- * All resources (handler threads etc) get freed/closed/canceled on termination.
-- * The `user` dependency implies that it is only usable after user authentication.
serveConnection :: forall stream state user. (MessageStream stream, HasName user) =>
    ConnectionConfig state user -> state -> user -> stream -> IO ()
serveConnection config state user stream = bracket open close $ \conn -> do
    let runReceiver = forever $
            receiveMessage stream >>= dispatchMessage conn 
    Async.withAsync runReceiver $ \asyncReceiver -> do
        let waitMessage = readTChan (connQueue conn)
            waitReceiver = Async.waitSTM asyncReceiver >> retry
        forever do
            msg <- atomically (waitMessage <|> waitReceiver)
            sendMessage stream msg
    where
        open :: IO (Connection state user)
        open = Connection config state user
            <$> newTVarIO False
            <*> newTVarIO mempty
            <*> newTVarIO mempty
            <*> newEmptyTMVarIO
            <*> newTChanIO

        close :: Connection state user -> IO ()
        close conn = do
            atomically $ writeTVar (connClosed conn) True
            case switchboard (connConfig conn) of
                Nothing -> pure ()
                Just sb -> do
                    bindAddrs <- readTVarIO (connForwardings conn)
                    mapM_ (cancelForwarding sb (name $ connUser conn)) bindAddrs

-- | Enqueue a message for sending.
--
-- * The message is enqueued in a non-bounded queue. Do not use this
--   for data messages (use `sendMessageLowPrioSTM` instead)!
sendMessageSTM :: Connection state user -> ConnectionMessage -> STM ()
sendMessageSTM conn = writeTChan (connQueue conn)

-- | Enqueue a message for sending with low priority.
--
-- * The message is only enqueued when the queue is empty.
--   It is meant to be used for data messages which are generated by user supplied handler
--   functions which might be generated faster than messages can actually be sent over the
--   connection. This operation avoids messages piling up in the queue by blocking the transaction
---  until capacity becomes available. Another effect is that control messages (channel close etc)
--   are treated with priority and don't starve on high volume data transmission.
-- * NB: Only one invocation of this operation will succeed per transaction. Make sure to not
--   have two or more invocations or a combination with `sendMessageSTM` in a transaction or
--   it will block forever!
sendMessageLowPrioSTM :: Connection state user -> ConnectionMessage -> STM ()
sendMessageLowPrioSTM conn msg = do
    isEmptyTChan (connQueue conn) >>= check
    sendMessageSTM conn msg

---------------------------------------------------------------------------------------------------
-- MESSAGE DISPATCH
---------------------------------------------------------------------------------------------------

-- | Dispatch an inbound message.
dispatchMessage :: (HasName user) => Connection state user -> ConnectionMessage -> IO ()
dispatchMessage conn = \case
    M080 msg -> dispatchGlobalRequest           conn msg
    M081 msg -> dispatchRequestSuccess          conn msg
    M082 msg -> dispatchRequestFailure          conn msg
    M090 msg -> dispatchChannelOpen             conn msg
    M091 msg -> dispatchChannelOpenConfirmation conn msg
    M092 msg -> dispatchChannelOpenFailure      conn msg
    M093 msg -> dispatchChannelWindowAdjust     conn msg
    M094 msg -> dispatchChannelData             conn msg
    M095 msg -> dispatchChannelExtendedData     conn msg
    M096 msg -> dispatchChannelEof              conn msg
    M097 msg -> dispatchChannelClose            conn msg
    M098 msg -> dispatchChannelRequest          conn msg
    M099 msg -> dispatchChannelSuccess          conn msg
    M100 msg -> dispatchChannelFailure          conn msg

-- | Dispatch SSH_MSG_GLOBAL_REQUEST.
dispatchGlobalRequest :: (HasName user) => Connection state user -> GlobalRequest -> IO ()
dispatchGlobalRequest conn (GlobalRequest wantReply tp) = case tp of
    GlobalRequestOther {} -> failure
    -- A forwarding requests shall be delegated to the switchboard for registration.
    -- If a switchboard has been configured it may decide whether forwarding
    -- is accepted or not. The switchboard is especially responsible for not
    -- accepting a binding to the same address twice.
    GlobalRequestTcpIpForward bindAddr -> case switchboard (connConfig conn) of
        Nothing -> failure
        Just sb -> do
            let user = name (connUser conn)
            let server = StreamServer (runForwarding conn bindAddr)
            let register = requestForwarding sb user bindAddr server >>= \case
                    False -> failure
                    True  -> success >> addForwarding bindAddr
            let unregister = do
                    cancelForwarding sb user bindAddr
                    delForwarding bindAddr
            -- Catching the exception is only relevant for the very
            -- unlikely case that the connection gets closed right after
            -- external registration but before local registration.
            register `onException` unregister
    where
        success = when wantReply $ atomically $ sendMessageSTM conn $ M081 RequestSuccess
        failure = when wantReply $ atomically $ sendMessageSTM conn $ M082 RequestFailure
        -- The forwarding needs to registered locally as well as it needs to be
        -- removed from the switchboard when the connection is closed.
        addForwarding bindAddr = atomically do
            fwds <- readTVar (connForwardings conn)
            writeTVar (connForwardings conn) $! Set.insert bindAddr fwds
        delForwarding bindAddr = atomically do
            fwds <- readTVar (connForwardings conn)
            writeTVar (connForwardings conn) $! Set.delete bindAddr fwds

-- | Dispatch SSH_MSG_REQUEST_SUCCESS.
dispatchRequestSuccess :: Connection state user -> RequestSuccess -> IO ()
dispatchRequestSuccess conn msg = atomically $
    putTMVar (connResponse conn) (Right msg) <|> throwSTM exceptionUnexpectedGlobalResponse

-- | Dispatch SSH_MSG_REQUEST_FAILURE.
dispatchRequestFailure :: Connection state user -> RequestFailure -> IO ()
dispatchRequestFailure conn msg = atomically $
    putTMVar (connResponse conn) (Left msg) <|> throwSTM exceptionUnexpectedGlobalResponse

-- | Dispatch SSH_MSG_CHANNEL_OPEN.
dispatchChannelOpen :: Connection state user -> ChannelOpen -> IO ()
dispatchChannelOpen conn (ChannelOpen rid rws rps ct) = case ct of
    ChannelOpenSession          -> openSessionChannel
    ChannelOpenDirectTcpIp    x -> openDirectTcpIpChannel x
    ChannelOpenForwardedTcpIp x -> openForwardedTcpIpChannel x
    ChannelOpenOther          x -> openOtherChannel x 
    where
        lws, lps :: Word32
        lws = maxBufferSize conn
        lps = maxPacketSize conn

        openSessionChannel :: IO ()
        openSessionChannel = onSessionRequest
            (connConfig conn)
            (connState conn)
            (connUser conn) >>= \case
                Nothing -> atomically do
                    sendFailureSTM ChannelOpenAdministrativelyProhibited
                Just handler -> do
                    tEnv    <- newTVarIO (Environment [])
                    tPty    <- newTVarIO Nothing
                    tLws    <- newTVarIO lws
                    tRws    <- newTVarIO rws
                    tStdin  <- B.newTWindowBufferIO (maxBufferSize conn) tLws
                    tStdout <- B.newTWindowBufferIO (maxBufferSize conn) tRws
                    tStderr <- B.newTWindowBufferIO (maxBufferSize conn) tRws
                    void $ atomically $ openApplicationChannelSTM tLws tRws $
                        ChannelApplicationSession SessionState
                        { sessHandler      = handler
                        , sessEnvironment  = tEnv
                        , sessPtySettings  = tPty
                        , sessStdin        = tStdin
                        , sessStdout       = tStdout
                        , sessStderr       = tStderr
                        }

        openDirectTcpIpChannel :: OpenDirectTcpIp -> IO ()
        openDirectTcpIpChannel (OpenDirectTcpIp dst src) = onDirectTcpIpRequest
            (connConfig conn) (connState conn) (connUser conn) src dst >>= \case
                Nothing -> atomically do
                    sendFailureSTM ChannelOpenAdministrativelyProhibited
                Just (DirectTcpIpHandler handler) -> do
                    tLws <- newTVarIO lws
                    tRws <- newTVarIO rws
                    dtis <- DirectTcpIpState
                        <$> B.newTWindowBufferIO (maxBufferSize conn) tLws
                        <*> B.newTWindowBufferIO (maxBufferSize conn) tRws
                    mch <- atomically $ openApplicationChannelSTM tLws tRws $
                        ChannelApplicationDirectTcpIp dtis
                    maybe (pure ())
                        (\ch -> forkDirectTcpIpHandler conn ch dtis (handler dtis)) mch

        openForwardedTcpIpChannel :: OpenForwardedTcpIp -> IO ()
        openForwardedTcpIpChannel _ = atomically do
            sendFailureSTM ChannelOpenAdministrativelyProhibited

        openOtherChannel :: Name -> IO ()
        openOtherChannel _ = atomically do
            sendFailureSTM ChannelOpenUnknownChannelType

        openApplicationChannelSTM :: TVar Word32 -> TVar Word32 -> ChannelApplication -> STM (Maybe Channel)
        openApplicationChannelSTM tLws tRws app = getLocalChannelIdSTM conn >>= \case
            Nothing -> do
                sendFailureSTM ChannelOpenResourceShortage
                pure Nothing
            Just lid -> do
                sendConfirmSTM lid
                ch <- newChannelSTM lid
                insertChannelSTM conn lid (ChannelRunning ch)
                pure (Just ch)
            where
                newChannelSTM lid = do
                    tEof      <- newTVar False
                    tClosed   <- newTVar False
                    tResponse <- newEmptyTMVar
                    pure Channel
                        { chanApplication         = app
                        , chanIdLocal             = lid
                        , chanIdRemote            = rid
                        , chanWindowSizeLocal     = tLws
                        , chanWindowSizeRemote    = tRws
                        , chanMaxPacketSizeLocal  = lps
                        , chanMaxPacketSizeRemote = rps
                        , chanClosed              = tClosed
                        , chanEofSent             = tEof
                        , chanResponse            = tResponse
                        }

        sendConfirmSTM :: ChannelId -> STM ()
        sendConfirmSTM lid = sendMessageSTM conn $ M091 $ ChannelOpenConfirmation rid lid lws lps

        sendFailureSTM :: ChannelOpenFailureReason -> STM ()
        sendFailureSTM r = sendMessageSTM conn $ M092 $ ChannelOpenFailure rid r mempty mempty

-- | Dispatch SSH_MSG_CHANNEL_OPEN_CONFIRMATION.
dispatchChannelOpenConfirmation :: Connection state user -> ChannelOpenConfirmation -> IO ()
dispatchChannelOpenConfirmation conn x@(ChannelOpenConfirmation lid _ _ _) = 
    atomically $ getChannelSTM conn lid >>= \case
        ChannelClosing    -> throwSTM exceptionInvalidChannelState -- FIXME
        ChannelRunning {} -> throwSTM exceptionInvalidChannelState
        ChannelOpening f  -> f (Right x)

-- | Dispatch SSH_MSG_CHANNEL_OPEN_FAILURE.
dispatchChannelOpenFailure :: Connection state user -> ChannelOpenFailure -> IO ()
dispatchChannelOpenFailure conn x@(ChannelOpenFailure lid _ _ _ ) =
    atomically $ getChannelSTM conn lid >>= \case
        ChannelClosing    -> throwSTM exceptionInvalidChannelState -- FIXME
        ChannelRunning {} -> throwSTM exceptionInvalidChannelState
        ChannelOpening f  -> f (Left x)

-- | Dispatch SSH_MSG_CHANNEL_WINDOW_ADJUST.
dispatchChannelWindowAdjust :: Connection state user -> ChannelWindowAdjust -> IO ()
dispatchChannelWindowAdjust connection (ChannelWindowAdjust lid increment) =
    atomically $ getChannelSTM connection lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelClosing    -> pure () -- ignore
        ChannelRunning ch -> do
            window <- readTVar (chanWindowSizeRemote ch)
            unless ((fromIntegral window + fromIntegral increment :: Word64) <= fromIntegral (maxBound :: Word32))
                $ throwSTM exceptionWindowSizeOverflow
            writeTVar (chanWindowSizeRemote ch) $! window + increment

-- | Dispatch SSH_MSG_CHANNEL_DATA.
dispatchChannelData :: Connection state user -> ChannelData -> IO ()
dispatchChannelData conn (ChannelData lid bytes) =
    atomically $ getChannelSTM conn lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelClosing    -> pure () -- ignore
        ChannelRunning ch -> do
            when (len > chanMaxPacketSizeRemote ch) (throwSTM exceptionPacketSizeExceeded)
            let queue = case chanApplication ch of
                    ChannelApplicationSession        st -> sessStdin   st
                    ChannelApplicationDirectTcpIp    st -> dtiStreamIn st
                    ChannelApplicationForwardedTcpIp st -> ftiStreamIn st
            eof <- B.askEofSTM queue
            when eof (throwSTM exceptionDataAfterEof)
            enqueued <- B.enqueueShortSTM queue bytes <|> pure 0
            when (enqueued /= len) (throwSTM exceptionWindowSizeUnderrun)
    where
        len :: Word32
        len = fromIntegral $ SBS.length bytes

-- | Dispatch SSH_MSG_CHANNEL_EXTENDED_DATA.
dispatchChannelExtendedData :: Connection state user -> ChannelExtendedData -> IO ()
dispatchChannelExtendedData _ _ =
    throwIO exceptionUnexpectedExtendedData

-- | Dispatch SSH_MSG_CHANNEL_EOF.
dispatchChannelEof :: Connection state user -> ChannelEof -> IO ()
dispatchChannelEof conn (ChannelEof lid) =
    atomically $ getChannelSTM conn lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState 
        ChannelClosing    -> pure () -- ignore
        ChannelRunning ch -> do
            let queue = case chanApplication ch of
                    ChannelApplicationSession        st -> sessStdin   st
                    ChannelApplicationDirectTcpIp    st -> dtiStreamIn st
                    ChannelApplicationForwardedTcpIp st -> ftiStreamIn st
            S.sendEofSTM queue

-- | Dispatch SSH_MSG_CHANNEL_CLOSE.
dispatchChannelClose :: Connection state user -> ChannelClose -> IO ()
dispatchChannelClose conn (ChannelClose lid) =
    atomically $ getChannelSTM conn lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        -- Close has already been sent and this is the response.
        -- Channel may now be removed.
        ChannelClosing    -> do
            deleteChannelSTM conn lid
        -- When the channel is not marked as closing then the close
        -- must have been initiated by the client and the server needs to send
        -- a confirmation (both sides may issue close messages simultaneously
        -- and receive them afterwards).
        ChannelRunning ch -> do
            writeTVar (chanClosed ch) True
            deleteChannelSTM conn lid
            sendMessageSTM conn $ M097 $ ChannelClose $ chanIdRemote ch

-- | Dispatch SSH_MSG_CHANNEL_REQUEST.
dispatchChannelRequest :: Connection state user -> ChannelRequest -> IO ()
dispatchChannelRequest conn (ChannelRequest lid typ wantReply dat) =
    join $ atomically $ getChannelSTM conn lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelClosing    -> pure $ pure () -- ignore
        ChannelRunning ch -> case chanApplication ch of
            ChannelApplicationSession st -> case typ of
                "env"     -> interpret $ sessionEnv ch st
                "pty-req" -> interpret $ sessionPty ch st
                "shell"   -> interpret $ sessionRun ch st . Left
                "exec"    -> interpret $ sessionRun ch st . Right
                _ -> do
                    failure ch
                    pure $ pure ()
            ChannelApplicationDirectTcpIp {} -> do
                failure ch
                pure $ pure ()
            ChannelApplicationForwardedTcpIp {} -> do
                failure ch
                pure $ pure ()
    where
        interpret f = maybe (throwSTM exceptionInvalidChannelRequest) f (runGet dat)
        success ch = when wantReply $ sendMessageSTM conn $ M099 $ ChannelSuccess (chanIdRemote ch)
        failure ch = when wantReply $ sendMessageSTM conn $ M100 $ ChannelFailure (chanIdRemote ch)

        sessionEnv :: Channel -> SessionState -> ChannelRequestEnv -> STM (IO ())
        sessionEnv ch st (ChannelRequestEnv key value) = do
            Environment env <- readTVar (sessEnvironment st)
            -- Limit the number of env variables for security reasons (DoS).
            if length env < 100
                then do
                    writeTVar (sessEnvironment st) $! Environment $ (SBS.fromShort key, SBS.fromShort value):env
                    success ch 
                else do
                    failure ch
            pure $ pure ()

        sessionPty :: Channel -> SessionState -> ChannelRequestPty -> STM (IO ())
        sessionPty ch st (ChannelRequestPty settings) = do
            writeTVar (sessPtySettings st) (Just settings)
            success ch
            pure $ pure ()

        sessionRun :: Channel -> SessionState -> (Either ChannelRequestShell ChannelRequestExec) -> STM (IO ())
        sessionRun ch st shellOrExec = do
            env    <- readTVar (sessEnvironment st)
            pty    <- readTVar (sessPtySettings st)
            stdin  <- pure (sessStdin  st)
            stdout <- pure (sessStdout st)
            stderr <- pure (sessStderr st)
            success ch
            pure do
                let cmd = case shellOrExec of
                        Left {}                      -> Nothing
                        Right (ChannelRequestExec c) -> Just c
                let SessionHandler handler = sessHandler st
                forkSessionHandler conn ch stdin stdout stderr $
                    handler env (TermInfo <$> pty) cmd stdin stdout stderr

-- | Dispatch SSH_MSG_CHANNEL_SUCCESS.
dispatchChannelSuccess :: Connection state user -> ChannelSuccess -> IO ()
dispatchChannelSuccess conn x@(ChannelSuccess lid) =
    atomically $ getChannelSTM conn lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelClosing    -> pure () -- ignore
        ChannelRunning ch -> putTMVar (chanResponse ch) (Right x)
            <|> throwSTM exceptionUnexpectedChannelResponse

-- | Dispatch SSH_MSG_CHANNEL_FAILURE.
dispatchChannelFailure :: Connection state user -> ChannelFailure -> IO ()
dispatchChannelFailure conn x@(ChannelFailure lid) =
    atomically $ getChannelSTM conn lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelClosing    -> pure () -- ignore
        ChannelRunning ch -> putTMVar (chanResponse ch) (Left x)
            <|> throwSTM exceptionUnexpectedChannelResponse

---------------------------------------------------------------------------------------------------
-- HANDLER THREADS
---------------------------------------------------------------------------------------------------

forkSessionHandler :: Connection state user -> Channel -> B.TWindowBuffer
    -> B.TWindowBuffer -> B.TWindowBuffer -> IO ExitCode -> IO ()
forkSessionHandler conn ch stdin stdout stderr run =
    void $ forkIO $ Async.withAsync run supervise
    where
        -- The supervisor thread waits for several event sources simultaneously,
        -- handles them and loops until the session thread has terminated and exit
        -- has been signaled or the channel/connection got closed.
        supervise :: Async.Async ExitCode -> IO ()
        supervise t =
            let loop = atomically (waitSTM t) >>= \stop -> unless stop loop in loop

        -- NB: The order is critical: Another order would cause a close
        -- to be sent before all data has been flushed.
        waitSTM :: Async.Async ExitCode -> STM Bool
        waitSTM t =
            waitClosedSTM conn ch <|>
            waitDataSTM conn ch stdout False <|>
            waitDataSTM conn ch stderr True <|>
            waitHandlerSTM t <|>
            waitWindowSTM conn ch stdin

        waitHandlerSTM :: Async.Async ExitCode -> STM Bool
        waitHandlerSTM thread = do
            exitMessage <- Async.waitCatchSTM thread >>= \case
                Right c -> pure $ reqMessage "exit-status" $ runPut $ put $ ChannelRequestExitStatus c
                Left  _ -> pure $ reqMessage "exit-signal" $ runPut $ put $ ChannelRequestExitSignal "ILL" False "" ""
            writeTVar (chanClosed ch) True
            sendMessageSTM conn exitMessage
            sendMessageSTM conn closeMessage
            setChannelClosingSTM conn (chanIdLocal ch)
            pure True
            where
                reqMessage t = M098 . ChannelRequest (chanIdRemote ch) t False
                closeMessage = M097 $ ChannelClose (chanIdRemote ch)

forkDirectTcpIpHandler :: Connection state user -> Channel -> DirectTcpIpState -> IO () -> IO ()
forkDirectTcpIpHandler conn ch st run =
    void $ forkIO $ Async.withAsync run supervise
    where
        supervise :: Async.Async () -> IO ()
        supervise t =
            let loop = atomically (waitSTM t) >>= \stop -> unless stop loop in loop

        waitSTM :: Async.Async () -> STM Bool
        waitSTM t =
            waitClosedSTM conn ch <|>
            waitDataSTM conn ch (dtiStreamOut st) False <|>
            waitHandlerSTM t <|>
            waitWindowSTM conn ch (dtiStreamIn st)

        waitHandlerSTM :: Async.Async () -> STM Bool
        waitHandlerSTM t = do
            void $ Async.waitCatchSTM t
            writeTVar (chanClosed ch) True
            sendMessageSTM conn $ M097 $ ChannelClose (chanIdRemote ch)
            setChannelClosingSTM conn (chanIdLocal ch)
            pure True

-- | NB: This operation is supposed to be executed by an external thread.
--       Special precautions within in it make this safe wrt resource allocation and release.
--       It is safe to throw an async exception to it at any time.
runForwarding :: Connection state user -> Address -> Address -> StreamHandler a -> IO (Maybe a)
runForwarding conn bindAddr origAddr (StreamHandler run) = do
    tChanStream <- newEmptyTMVarIO :: IO (TMVar (Maybe (Channel, ForwardedTcpIpState)))
    -- This is a bit tricky: The user handler may run longer than the channel is alive.
    -- Its Async is therefor started first and gets its dependency injected.
    -- The channel gets cleaned up either when the handler terminates, an async
    -- exception occurs or when the channel gets closed for whatever reason.
    Async.withAsync (maybe (pure Nothing) ((Just <$>) . run . snd) =<< atomically (readTMVar tChanStream)) $ \t -> do
        x <- bracket (open tChanStream) (close tChanStream) $ const $ atomically (readTMVar tChanStream) >>= \case
            -- Channel failed to open.
            Nothing -> pure False
            -- Channel open: Run stream and other event handlers.
            Just (ch,st) ->
                -- Wait for and handle events until close.
                let loop = atomically (wait ch st t) >>= \stop -> unless stop loop in loop >> pure True
        -- Channel has been closed. Now just wait for the handler (`wait` may re-throw!) if it was ever open.
        if x then Async.wait t else pure Nothing
    where
        -- The order is crucial: It ensures that outstanding data is sent before closing the channel.
        wait :: Channel -> ForwardedTcpIpState -> Async.Async a -> STM Bool
        wait ch st t =
            waitClosedSTM conn ch <|>
            waitDataSTM conn ch (ftiStreamOut st) False <|>
            waitHandlerSTM t <|>
            waitWindowSTM conn ch (ftiStreamIn st)

        waitHandlerSTM :: Async.Async a -> STM Bool
        waitHandlerSTM t = do
            void (Async.waitCatchSTM t)
            pure True

        open :: TMVar (Maybe (Channel, ForwardedTcpIpState)) -> IO (Maybe ChannelId)
        open tChanStream = atomically do
            closed <- readTVar (connClosed conn)
            if closed then pure Nothing else do
                mlid <- getLocalChannelIdSTM conn
                maybe (pure Nothing) openWithLid mlid
            where
                openWithLid lid = do
                    sendMessageSTM conn $ M090
                        $ ChannelOpen lid lws lps
                        $ ChannelOpenForwardedTcpIp $ OpenForwardedTcpIp bindAddr origAddr
                    insertChannelSTM conn lid $ ChannelOpening $ \case
                        Left (ChannelOpenFailure {}) -> do
                            deleteChannelSTM conn lid
                            putTMVar tChanStream Nothing
                        Right (ChannelOpenConfirmation _ rid rws rps) -> do
                            tLws      <- newTVar lws
                            tRws      <- newTVar rws
                            tClosed   <- newTVar False
                            tEofSent  <- newTVar False
                            tResponse <- newEmptyTMVar
                            st        <- ForwardedTcpIpState
                                        <$> B.newTWindowBufferSTM (maxBufferSize conn) tLws
                                        <*> B.newTWindowBufferSTM (maxBufferSize conn) tRws
                            let ch = Channel
                                    { chanApplication         = ChannelApplicationForwardedTcpIp st
                                    , chanIdLocal             = lid
                                    , chanIdRemote            = rid
                                    , chanWindowSizeLocal     = tLws
                                    , chanWindowSizeRemote    = tRws
                                    , chanMaxPacketSizeLocal  = lps
                                    , chanMaxPacketSizeRemote = rps
                                    , chanClosed              = tClosed
                                    , chanEofSent             = tEofSent
                                    , chanResponse            = tResponse
                                    }
                            insertChannelSTM conn lid $ ChannelRunning ch
                            putTMVar tChanStream (Just (ch,st))
                    pure (Just lid)

        close :: TMVar (Maybe (Channel, ForwardedTcpIpState)) -> Maybe ChannelId -> IO ()
        close tChanStream = \case
            -- Allocation failed locally: No resources allocated.
            Nothing  -> pure ()
            -- Channel allocated. State unclear.
            Just lid -> atomically $ tryReadTMVar tChanStream >>= \case
                -- No response yet: Set channel to closing.
                -- It will unregistered when the response arrives.
                Nothing -> setChannelClosingSTM conn lid
                -- Channel open failed: Nothing to do.
                -- It has already been freed when the response arrived.
                Just Nothing -> pure ()
                -- Channel eventually still open.
                Just (Just (ch,_)) -> readTVar (chanClosed ch) >>= \case
                    -- Channel closed: Nothing to do.
                    True  -> pure ()
                    -- Channel still open: Set to closing, send close.
                    -- It will be unregistered when the reponse arrives.
                    False -> do
                        writeTVar (chanClosed ch) True -- just for completeness
                        setChannelClosingSTM conn lid
                        sendMessageSTM conn $ M097 $ ChannelClose $ chanIdRemote ch

        lws, lps :: Word32
        lws = maxBufferSize conn
        lps = maxPacketSize conn

---------------------------------------------------------------------------------------------------
-- CHANNEL UTILS
---------------------------------------------------------------------------------------------------

getChannelSTM :: Connection state user -> ChannelId -> STM ChannelState
getChannelSTM conn lid = do
    channels <- readTVar (connChannels conn)
    case M.lookup lid channels of
        Just channel -> pure channel
        Nothing      -> throwSTM exceptionInvalidChannelId

setChannelClosingSTM :: Connection state user -> ChannelId -> STM ()
setChannelClosingSTM conn lid = do
    channels <- readTVar (connChannels conn)
    writeTVar (connChannels conn) $! M.insert lid ChannelClosing channels

insertChannelSTM :: Connection state user -> ChannelId -> ChannelState -> STM ()
insertChannelSTM conn lid chst = do
    channels <- readTVar (connChannels conn)
    writeTVar (connChannels conn) $! M.insert lid chst channels

deleteChannelSTM :: Connection state user -> ChannelId -> STM ()
deleteChannelSTM conn lid = do
    channels <- readTVar (connChannels conn)
    writeTVar (connChannels conn) $! M.delete lid channels

getLocalChannelIdSTM :: Connection state user -> STM (Maybe ChannelId)
getLocalChannelIdSTM conn =
    findFree <$> readTVar (connChannels conn)
    where
        findFree m
            | M.size m >= fromIntegral maxCount = Nothing
            | otherwise = f (ChannelId 0) $ M.keys m
        f i []          = Just i
        f (ChannelId i) (ChannelId k:ks)
            | i == k    = f (ChannelId $ i+1) ks
            | otherwise = Just (ChannelId i)
        maxCount = channelMaxCount (connConfig conn)

waitClosedSTM :: Connection state user -> Channel -> STM Bool
waitClosedSTM conn ch = do
    closed <- (||) <$> readTVar (connClosed conn) <*> readTVar (chanClosed ch)
    check closed
    pure True

waitDataSTM :: Connection state user -> Channel -> B.TWindowBuffer -> Bool -> STM Bool
waitDataSTM conn ch wb extended = do
    readTVar (chanEofSent ch) >>= check . not -- no data after eof
    bs <- B.dequeueShortSTM wb (chanMaxPacketSizeRemote ch)
    if SBS.null bs
        then do
            writeTVar (chanEofSent ch) True
            sendMessageSTM conn $ M096 $ ChannelEof (chanIdRemote ch)
        else do
            sendMessageLowPrioSTM conn $ if extended
                then M095 $ ChannelExtendedData (chanIdRemote ch) 1 bs
                else M094 $ ChannelData (chanIdRemote ch) bs
    pure False

waitWindowSTM :: Connection state user -> Channel -> B.TWindowBuffer -> STM Bool
waitWindowSTM conn ch wb = do
    increment <- B.getRecommendedWindowAdjustSTM wb
    window <- readTVar (chanWindowSizeLocal ch)
    writeTVar (chanWindowSizeLocal ch) $! window + increment
    sendMessageSTM conn $ M093 $ ChannelWindowAdjust (chanIdRemote ch) increment
    pure False

-- The maxBufferSize must at least be one (even if 0 in the config)
-- and must not exceed the range of Int (might happen on 32bit systems
-- as Int's guaranteed upper bound is only 2^29 -1).
-- The value is adjusted silently as this won't be a problem
-- for real use cases and is just the safest thing to do.
maxBufferSize :: Connection state user -> Word32
maxBufferSize conn = max 1 $ fromIntegral $ min
    maxBoundIntWord32
    (channelMaxBufferSize $ connConfig conn)

-- The maxPacketSize is adjusted to be at least one and small
-- enough to not exceed the transport layer limitations.
maxPacketSize :: Connection state user -> Word32
maxPacketSize conn = max 1 $ min
    maxDataPacketLength
    (channelMaxPacketSize $ connConfig conn)

---------------------------------------------------------------------------------------------------
-- AUXILLIARY DATA TYPES AND INSTANCES
---------------------------------------------------------------------------------------------------

instance S.InputStream DirectTcpIpState where
    peek x = S.peek (dtiStreamIn x)
    receive x = S.receive (dtiStreamIn x)

instance S.OutputStream DirectTcpIpState where
    send x = S.send (dtiStreamOut x)

instance S.DuplexStream DirectTcpIpState where

instance S.InputStream ForwardedTcpIpState where
    peek x = S.peek (ftiStreamIn x)
    receive x = S.receive (ftiStreamIn x)

instance S.OutputStream ForwardedTcpIpState where
    send x = S.send (ftiStreamOut x)

instance S.DuplexStream ForwardedTcpIpState where


