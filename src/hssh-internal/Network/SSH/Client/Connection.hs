{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client.Connection
    ( ConnectionConfig (..)
    , Connection ()
    , ChannelException (..)
    , ChannelOpenFailureDescription (..)
    , Environment (..)
    , Command (..)
    , ExitSignal (..)
    , SessionHandler (..)
    , InboundMessage (..)
    , OutboundMessage (..)
    , withConnection
    , getChannelCount
    , runShell
    , runExec
    ) where

import           Control.Applicative
import           Control.Concurrent.Async              ( withAsync, waitSTM )
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Control.Exception                     ( Exception, bracket, throwIO )
import           Control.Monad
import           Control.Monad.STM
import qualified Data.ByteString                       as BS
import qualified Data.ByteString.Short                 as SBS
import           Data.Default
import           Data.Function                         ( fix )
import           Data.Map.Strict                       as M
import           Data.Word
import           System.Exit

import           Network.SSH.Constants
import           Network.SSH.Exception
import           Network.SSH.Encoding
import           Network.SSH.Environment
import           Network.SSH.Message
import           Network.SSH.Name
import           Network.SSH.Stream
import qualified Network.SSH.TWindowBuffer             as B

data ConnectionConfig
    = ConnectionConfig
    { channelMaxCount       :: Word16
      -- ^ The maximum number of channels that may be active simultaneously (default: 256).
    , channelMaxQueueSize   :: Word32
      -- ^ The maximum size of the internal buffers in bytes (also
      --   limits the maximum window size, default: 32 kB)
      --
      --   Increasing this value might help with performance issues
      --   (if connection delay is in a bad ratio with the available bandwidth the window
      --   resizing might cause unncessary throttling).
    , channelMaxPacketSize  :: Word32
      -- ^ The maximum size of inbound channel data payload (default: 32 kB)
      --
      --   Values that are larger than `channelMaxQueueSize` or the
      --   maximum message size (35000 bytes) will be automatically adjusted
      --   to the maximum possible value.
    , getEnvironment        :: IO Environment
    }

instance Default ConnectionConfig where
    def = ConnectionConfig
        { channelMaxCount      = 256
        , channelMaxQueueSize  = 32 * 1024
        , channelMaxPacketSize = 32 * 1024
        , getEnvironment       = getDefaultEnvironment
        }

data Connection
    = Connection
    { connConfig    :: ConnectionConfig
    , connOutChan   :: TChan OutboundMessage
    , connChannels  :: TVar (M.Map ChannelId ChannelState)
    }

data ChannelState
    = ChannelOpening (Either ChannelOpenFailure ChannelOpenConfirmation -> STM ())
    | ChannelRunning Channel
    | ChannelClosing

data Channel
    = Channel
    { chanIdLocal             :: ChannelId
    , chanIdRemote            :: ChannelId
    , chanMaxPacketSizeLocal  :: Word32
    , chanMaxPacketSizeRemote :: Word32
    , chanWindowSizeLocal     :: TVar Word32
    , chanWindowSizeRemote    :: TVar Word32
    -- ^ This variable seems redundant, but it is not!
    --   A channel handler may outlive the channel itself
    --   (meaning it being registered in the channels map).
    --   In this case referring to the channel by id
    --   is use-after-free and might have undesired effects.
    --   In other words: The local channel id is only valid
    --   as long as this variable is False.
    , chanClosed              :: TVar Bool
    , chanRequestSuccess      :: TMVar Bool
    , chanApplication         :: ChannelApplication
    }

data ChannelApplication
    = ChannelApplicationSession ChannelSession

data ChannelSession
    = ChannelSession
    { sessStdin       :: B.TWindowBuffer
    , sessStdout      :: B.TWindowBuffer
    , sessStderr      :: B.TWindowBuffer
    , sessExit        :: TMVar (Either ExitSignal ExitCode)
    }

data InboundMessage
    = I080 GlobalRequest
    | I091 ChannelOpenConfirmation
    | I092 ChannelOpenFailure
    | I093 ChannelWindowAdjust
    | I094 ChannelData
    | I095 ChannelExtendedData
    | I096 ChannelEof
    | I097 ChannelClose
    | I098 ChannelRequest
    | I099 ChannelSuccess
    | I100 ChannelFailure
    deriving (Eq, Show)

instance Decoding InboundMessage where
    get =   I080 <$> get
        <|> I091 <$> get
        <|> I092 <$> get
        <|> I093 <$> get
        <|> I094 <$> get
        <|> I095 <$> get
        <|> I096 <$> get
        <|> I097 <$> get
        <|> I098 <$> get
        <|> I099 <$> get
        <|> I100 <$> get

data OutboundMessage
    = O081 RequestSuccess
    | O082 RequestFailure
    | O090 ChannelOpen
    | O093 ChannelWindowAdjust
    | O094 ChannelData
    | O096 ChannelEof
    | O097 ChannelClose
    | O098 ChannelRequest
    | O099 ChannelSuccess
    | O100 ChannelFailure
    deriving (Eq, Show)

instance Encoding OutboundMessage where
    put (O081 x) = put x
    put (O082 x) = put x
    put (O090 x) = put x
    put (O093 x) = put x
    put (O094 x) = put x
    put (O096 x) = put x
    put (O097 x) = put x
    put (O098 x) = put x
    put (O099 x) = put x
    put (O100 x) = put x

instance Decoding OutboundMessage where
    get =   O081 <$> get
        <|> O082 <$> get
        <|> O090 <$> get
        <|> O093 <$> get
        <|> O094 <$> get
        <|> O096 <$> get
        <|> O097 <$> get
        <|> O098 <$> get
        <|> O099 <$> get
        <|> O100 <$> get

data ChannelException
    = ChannelOpenFailed ChannelOpenFailureReason ChannelOpenFailureDescription
    | ChannelRequestFailed
    | ChannelClosed
    deriving (Eq, Show)

instance Exception ChannelException where

newtype ChannelOpenFailureDescription = ChannelOpenFailureDescription BS.ByteString
    deriving (Eq, Ord, Show)

data ExitSignal
    = ExitSignal
    { exitSignalName   :: Name
    , exitCoreDumped   :: Bool
    , exitErrorMessage :: BS.ByteString
    } deriving (Eq, Ord, Show)

newtype SessionHandler a = SessionHandler (forall stdin stdout stderr. (OutputStream stdin, InputStream stdout, InputStream stderr)
    => stdin -> stdout -> stderr -> STM (Either ExitSignal ExitCode) -> IO a)

---------------------------------------------------------------------------------------------------
-- PUBLIC FUNCTIONS
---------------------------------------------------------------------------------------------------

withConnection :: (MessageStream stream) => ConnectionConfig -> stream -> (Connection -> IO a) -> IO a
withConnection config stream runHandler = do
    c <- atomically $ Connection config <$> newTChan <*> newTVar mempty
    withAsync (runReceiver c) $ \receiverThread -> do
        withAsync (runHandler c) $ \handlerThread -> fix $ \continue -> do
            let left  = Left  <$> readTChan (connOutChan c)
                right = Right <$> waitSTM handlerThread
                receiverThreadException = do
                    void $ waitSTM receiverThread -- throws exception or blocks forever
                    throwSTM exceptionInvalidState
            atomically (left <|> right <|> receiverThreadException) >>= \case
                Left msg -> sendMessage stream msg >> continue
                Right a  -> pure a
    where
        runReceiver c = forever $ receiveMessage stream >>= dispatchMessage c

runShell :: Connection -> SessionHandler a -> IO a
runShell c = runSession c Nothing

runExec :: Connection -> Command -> SessionHandler a -> IO a
runExec c command = runSession c (Just command)

getChannelCount :: Connection -> IO Int
getChannelCount c = atomically do
    M.size <$> readTVar (connChannels c)

---------------------------------------------------------------------------------------------------
-- INTERNAL FUNCTIONS
---------------------------------------------------------------------------------------------------

sendMessageSTM :: Connection -> OutboundMessage -> STM ()
sendMessageSTM c = writeTChan (connOutChan c)

-- | Must not try to send more than one per transaction!
sendMessageLowPrioSTM :: Connection -> OutboundMessage -> STM ()
sendMessageLowPrioSTM c msg = do
    isEmptyTChan (connOutChan c) >>= check
    sendMessageSTM c msg

runSession :: Connection -> Maybe Command -> SessionHandler a -> IO a
runSession c mcommand (SessionHandler handler) = do
    tmOpenResult      <- newEmptyTMVarIO
    tmExit            <- newEmptyTMVarIO
    tClosed           <- newTVarIO False
    tRequestSuccess   <- newEmptyTMVarIO
    tLocalWindowSize  <- newTVarIO maxQueueSize
    tRemoteWindowSize <- newTVarIO 0
    stdin             <- atomically (B.newTWindowBufferSTM maxQueueSize tLocalWindowSize)
    stdout            <- atomically (B.newTWindowBufferSTM maxQueueSize tRemoteWindowSize)
    stderr            <- atomically (B.newTWindowBufferSTM maxQueueSize tRemoteWindowSize)
    -- This function will be executed with the server's reponse
    -- and eventually turn the 'opening' channel into a 'running' one.
    -- NB: This code is executed by the receiver thread and not
    -- by the thread that called `session`. It makes the channel or failure
    -- available to the session handler thread via `tOpenResult`.
    let withOpenResponse = \case
            Left failure -> do
                -- Set the channel close flag in order to avoid that `closeChannel`
                -- tries to close the channel. A channel that failed to open has never
                -- been in open state and no close messages shall be sent for it.
                writeTVar tClosed True
                putTMVar tmOpenResult (Left failure)
            Right (ChannelOpenConfirmation lid rid rws rps) -> do
                let session = ChannelSession
                        { sessStdin               = stdin
                        , sessStdout              = stdout
                        , sessStderr              = stderr
                        , sessExit                = tmExit
                        }
                let channel = Channel
                        { chanIdLocal             = lid
                        , chanIdRemote            = rid
                        , chanMaxPacketSizeLocal  = maxPacketSize
                        , chanMaxPacketSizeRemote = rps
                        , chanWindowSizeLocal     = tLocalWindowSize
                        , chanWindowSizeRemote    = tRemoteWindowSize
                        , chanRequestSuccess      = tRequestSuccess
                        , chanClosed              = tClosed
                        , chanApplication         = ChannelApplicationSession session
                        }
                writeTVar tRemoteWindowSize rws
                setChannelStateSTM c lid $ ChannelRunning channel
                putTMVar tmOpenResult (Right channel)

    let openChannel = atomically do
            lid <- registerChannelSTM c withOpenResponse
            sendMessageSTM c $ O090 $ ChannelOpen lid maxQueueSize maxPacketSize ChannelOpenSession
            pure lid

    let closeChannel lid = atomically do
            alreadyClosed <- swapTVar tClosed True
            unless alreadyClosed $ getChannelStateSTM c lid >>= \case
                -- The channel is opening:
                -- We cannot send a close message as we don't know the
                -- remote channel id. Instead we set it to closing state and
                -- the response handler will unregister it when ChannelOpenFailure
                -- or ChannelOpenConfirmation arrives. It will also send the close
                -- message (ChannelOpenConfirmation contains the remote channel id).
                ChannelOpening {} -> do
                    setChannelStateSTM c lid ChannelClosing
                -- The channel is running and not yet closed:
                -- Set it to closing and send the close message. The response
                -- handler will then unregister the channel when the repose arrives.
                ChannelRunning ch -> do
                    setChannelStateSTM c lid ChannelClosing
                    sendMessageSTM c $ O096 $ ChannelEof   (chanIdRemote ch)
                    sendMessageSTM c $ O097 $ ChannelClose (chanIdRemote ch)
                -- Only this handler sets the channel to closing state and
                -- it is excuted exactly once. Getting here should be impossible.
                ChannelClosing {} -> throwSTM exceptionInvalidChannelState

    -- Waits for decision whether this channel could be opened or not.
    -- The previously registered callback will fill the variable waited for.
    let waitChannel = atomically $ readTMVar tmOpenResult >>= \case
            Right ch -> pure ch
            Left (ChannelOpenFailure _ reason descr _) -> throwSTM
                $ ChannelOpenFailed reason
                $ ChannelOpenFailureDescription $ SBS.fromShort descr
    bracket openChannel closeChannel $ const $ waitChannel >>= \ch -> do
        -- Send environment variables. Confirmation is not necessary.
        Environment env <- getEnvironment (connConfig c)
        forM_ env $ \(k,v) -> atomically $ sendMessageLowPrioSTM c $ O098 $ ChannelRequest
            { crChannel   = chanIdRemote ch
            , crType      = "env"
            , crWantReply = False
            , crData      = runPut (put $ ChannelRequestEnv (SBS.toShort k) (SBS.toShort v))
            }
        -- Send the command to execute or shell request.
        atomically $ sendMessageSTM c $ O098 $ case mcommand of
            Just command -> ChannelRequest
                { crChannel   = chanIdRemote ch
                , crType      = "exec"
                , crWantReply = True
                , crData      = runPut (put $ ChannelRequestExec command)
                }
            Nothing -> ChannelRequest
                { crChannel   = chanIdRemote ch
                , crType      = "shell"
                , crWantReply = True
                , crData      = runPut (put ChannelRequestShell)
                }
        -- Wait for response for this channel request.
        -- Throw exception in case the request failed or the channel has been
        -- closed in the meantime.
        success <- atomically $ takeTMVar (chanRequestSuccess ch) <|> throwWhenClosedSTM ch
        unless success $ throwIO ChannelRequestFailed
        -- Invoke the user supplied handler function.
        let exitSTM = readTMVar tmExit <|> (readTVar tClosed >>= check >> pure (Right $ ExitFailure (-1)))
        withAsync (handler stdin stdout stderr exitSTM) $ \handlerAsync -> do
            let x1 = do
                    -- Wait for channel data on stdin to be transmitted to server.
                    checkNotClosedSTM ch
                    dat <- B.dequeueShortSTM stdin (chanMaxPacketSizeRemote ch)
                    sendMessageSTM c $ O094 $ ChannelData (chanIdRemote ch) dat
                    pure Nothing
                x2 = do
                    -- Wait for necessary window adjust to be transmitted to server.
                    -- As both stdout and stderr depend on the same window it is necessary
                    -- to query both for their window size adjust recommendation
                    -- and take the minimum in order to never exceed either buffer limits.
                    checkNotClosedSTM ch
                    increment <- min <$> B.getRecommendedWindowAdjustSTM stdout
                                     <*> B.getRecommendedWindowAdjustSTM stderr
                    window <- readTVar (chanWindowSizeRemote ch)
                    writeTVar (chanWindowSizeRemote ch) $! window + increment
                    sendMessageSTM c $ O093 $ ChannelWindowAdjust (chanIdRemote ch) increment
                    pure Nothing
                x3 = do -- Wait for handler thread to terminate.
                    Just <$> waitSTM handlerAsync
            fix $ \continue -> atomically (x1 <|> x2 <|> x3) >>= \case
                Nothing -> continue
                Just a  -> pure a
    where
        -- The maxQueueSize must at least be 1 (even if 0 in the config)
        -- and lower than range of Int (might happen on 32bit systems
        -- as Int's guaranteed upper bound is only 2^29 -1).
        -- The value is adjusted silently as this won't be a problem
        -- for real use cases and is just the safest thing to do.
        maxQueueSize :: Word32
        maxQueueSize = max 1 $ fromIntegral $ min maxBoundIntWord32
            (channelMaxQueueSize $ connConfig c)

        maxPacketSize :: Word32
        maxPacketSize = max 1 $ fromIntegral $ min maxBoundIntWord32
            (channelMaxPacketSize $ connConfig c)

        checkNotClosedSTM :: Channel -> STM ()
        checkNotClosedSTM ch =
            readTVar (chanClosed ch) >>= check . not

        throwWhenClosedSTM :: Channel -> STM a
        throwWhenClosedSTM ch =
            readTVar (chanClosed ch) >>= check >> throwSTM ChannelClosed

registerChannelSTM ::
    Connection ->
    (Either ChannelOpenFailure ChannelOpenConfirmation -> STM ()) ->
    STM ChannelId
registerChannelSTM c handler = do
    channels <- readTVar (connChannels c)
    case findSlot channels of
        Nothing -> retry
        Just lid -> do
            setChannelStateSTM c lid (ChannelOpening handler)
            pure lid
    where
        findSlot :: M.Map ChannelId a -> Maybe ChannelId
        findSlot m
            | M.size m >= fromIntegral maxCount = Nothing
            | otherwise = f (ChannelId 0) $ M.keys m
            where
                f i []          = Just i
                f (ChannelId i) (ChannelId k:ks)
                    | i == k    = f (ChannelId $ i+1) ks
                    | otherwise = Just (ChannelId i)
                maxCount = channelMaxCount (connConfig c)

unregisterChannelSTM :: Connection -> ChannelId -> STM ()
unregisterChannelSTM c lid = do
    channels <- readTVar (connChannels c)
    writeTVar (connChannels c) $! M.delete lid channels

getChannelStateSTM :: Connection -> ChannelId -> STM ChannelState
getChannelStateSTM c lid = do
    channels <- readTVar (connChannels c)
    maybe (throwSTM exceptionInvalidChannelId) pure (M.lookup lid channels)

setChannelStateSTM :: Connection -> ChannelId -> ChannelState -> STM ()
setChannelStateSTM c lid st = do
    channels <- readTVar (connChannels c)
    writeTVar (connChannels c) $! M.insert lid st channels

---------------------------------------------------------------------------------------------------
-- MESSAGE DISPATCH
---------------------------------------------------------------------------------------------------

dispatchMessage :: Connection -> InboundMessage -> IO ()
dispatchMessage c msg = atomically $ case msg of
    I080 x -> dispatchGlobalRequestSTM c x
    I091 x -> dispatchChannelOpenConfirmationSTM c x
    I092 x -> dispatchChannelOpenFailureSTM c x
    I093 x -> dispatchChannelWindowAdjustSTM c x
    I094 x -> dispatchChannelDataSTM c x
    I095 x -> dispatchChannelExtendedDataSTM c x
    I096 x -> dispatchChannelEofSTM c x
    I097 x -> dispatchChannelCloseSTM c x
    I098 x -> dispatchChannelRequestSTM c x
    I099 x -> dispatchChannelSuccessSTM c x
    I100 x -> dispatchChannelFailureSTM c x

dispatchGlobalRequestSTM :: Connection -> GlobalRequest -> STM ()
dispatchGlobalRequestSTM c (GlobalRequest wantReply _) =
    when wantReply $ sendMessageSTM c $ O082 RequestFailure

dispatchChannelOpenConfirmationSTM :: Connection -> ChannelOpenConfirmation -> STM ()
dispatchChannelOpenConfirmationSTM c x@(ChannelOpenConfirmation lid rid _ _) =
    getChannelStateSTM c lid >>= \case
        ChannelOpening f  -> f (Right x)
        ChannelRunning {} -> throwSTM exceptionInvalidChannelState
        -- The channel was set to closing locally:
        -- It is left in closing state and a close message is sent to the
        -- peer. The channel will be freed when the close reponse arrives.
        ChannelClosing {} -> sendMessageSTM c $ O097 $ ChannelClose rid

dispatchChannelOpenFailureSTM :: Connection -> ChannelOpenFailure -> STM ()
dispatchChannelOpenFailureSTM c x@(ChannelOpenFailure lid _ _ _) =
    getChannelStateSTM c lid >>= \case
        -- The channel open request failed:
        -- Free the channel and call the registered handler.
        ChannelOpening f  -> do
            unregisterChannelSTM c lid
            f (Left x)
        ChannelRunning {} -> throwSTM exceptionInvalidChannelState
        -- The channel was set to closing locally:
        -- As the channel open failed a close message is not required
        -- and the channel can bee freed immediately.
        ChannelClosing {} -> unregisterChannelSTM c lid

dispatchChannelWindowAdjustSTM :: Connection -> ChannelWindowAdjust -> STM ()
dispatchChannelWindowAdjustSTM c (ChannelWindowAdjust lid increment) =
    getChannelStateSTM c lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelRunning ch -> do
            window <- readTVar (chanWindowSizeLocal ch)
            unless ((fromIntegral window + fromIntegral increment :: Word64) <= fromIntegral (maxBound :: Word32))
                $ throwSTM exceptionWindowSizeOverflow
            writeTVar (chanWindowSizeLocal ch) $! window + increment
        ChannelClosing {} -> pure ()

dispatchChannelDataSTM :: Connection -> ChannelData -> STM ()
dispatchChannelDataSTM c (ChannelData lid bytes) =
    getChannelStateSTM c lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelRunning ch -> case chanApplication ch of
            ChannelApplicationSession ChannelSession { sessStdout = queue } -> do
                when (len > chanMaxPacketSizeRemote ch) (throwSTM exceptionPacketSizeExceeded) 
                enqueued <- B.enqueueShortSTM queue bytes <|> pure 0
                when (enqueued /= len) (throwSTM exceptionWindowSizeUnderrun)
        ChannelClosing {} -> pure ()
    where
        len = fromIntegral (SBS.length bytes)

dispatchChannelExtendedDataSTM :: Connection -> ChannelExtendedData -> STM ()
dispatchChannelExtendedDataSTM c (ChannelExtendedData lid _ bytes) =
    getChannelStateSTM c lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelRunning ch -> case chanApplication ch of
            ChannelApplicationSession ChannelSession { sessStderr = queue } -> do
                when (len > chanMaxPacketSizeRemote ch) (throwSTM exceptionPacketSizeExceeded) 
                enqueued <- B.enqueueShortSTM queue bytes <|> pure 0
                when (enqueued /= len) (throwSTM exceptionWindowSizeUnderrun)
        ChannelClosing {} -> pure ()
    where
        len = fromIntegral (SBS.length bytes)

dispatchChannelEofSTM :: Connection -> ChannelEof -> STM ()
dispatchChannelEofSTM c (ChannelEof lid) =
    getChannelStateSTM c lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelRunning ch -> case chanApplication ch of
            ChannelApplicationSession ChannelSession { sessStdout = out, sessStderr = err } -> do
                sendEofSTM out
                sendEofSTM err
        ChannelClosing {} -> pure ()

dispatchChannelCloseSTM :: Connection -> ChannelClose -> STM ()
dispatchChannelCloseSTM c (ChannelClose lid) =
    getChannelStateSTM c lid >>= \case
        -- A close message must not occur unless the channel is open.
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        -- A running channel means that the close is initiated
        -- by the server. We respond and free the channel immediately.
        -- It is also necessary to mark the channel itself as closed
        -- so that the handler thread knows about the close
        -- (looking up the channel id in the map is unsafe as it
        -- might have been reused after this transaction).
        ChannelRunning ch -> do
            unregisterChannelSTM c lid
            writeTVar (chanClosed ch) True
            sendMessageSTM c $ O097 $ ChannelClose (chanIdRemote ch)
        -- A closing channel means that we have already sent
        -- a close message and this is the reponse. The channel gets
        -- freed and its id is ready for reuse.
        ChannelClosing {} -> unregisterChannelSTM c lid

dispatchChannelRequestSTM :: Connection -> ChannelRequest -> STM ()
dispatchChannelRequestSTM c (ChannelRequest lid typ wantReply dat) =
    getChannelStateSTM c lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelRunning ch -> case chanApplication ch of
            ChannelApplicationSession ChannelSession { sessExit = exit } -> case (typ, wantReply) of
                ("exit-signal", False) -> case runGet dat of
                    Nothing -> throwSTM exceptionInvalidChannelRequest
                    Just (ChannelRequestExitSignal signame coredumped errmsg _) ->
                        void $ tryPutTMVar exit $ Left $ ExitSignal
                            (Name signame)
                            coredumped
                            (SBS.fromShort errmsg)
                ("exit-status", False) -> case runGet dat of
                    Nothing -> throwSTM exceptionInvalidChannelRequest
                    Just (ChannelRequestExitStatus status) ->
                        void $ tryPutTMVar exit $ Right status
                _ -> when wantReply $ sendMessageSTM c $ O100 $ ChannelFailure (chanIdRemote ch)
        ChannelClosing {} -> pure ()

dispatchChannelSuccessSTM :: Connection -> ChannelSuccess -> STM ()
dispatchChannelSuccessSTM c (ChannelSuccess lid) =
    getChannelStateSTM c lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelRunning ch -> putTMVar (chanRequestSuccess ch) True
            <|> throwSTM exceptionUnexpectedChannelResponse
        ChannelClosing {} -> pure ()

dispatchChannelFailureSTM :: Connection -> ChannelFailure -> STM ()
dispatchChannelFailureSTM c (ChannelFailure lid) =
    getChannelStateSTM c lid >>= \case
        ChannelOpening {} -> throwSTM exceptionInvalidChannelState
        ChannelRunning ch -> putTMVar (chanRequestSuccess ch) False
            <|> throwSTM exceptionUnexpectedChannelResponse
        ChannelClosing {} -> pure ()
