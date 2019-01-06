{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client.Connection where

import           Control.Applicative
import           Control.Concurrent.Async              ( withAsync, waitSTM )
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Control.Exception                     ( Exception, bracket, throwIO )
import           Control.Monad
import           Control.Monad.STM
import           Data.Default
import           Data.Function                         ( fix )
import           Data.Map.Strict                       as M
import           System.Exit
import           Data.Word
import qualified Data.ByteString                       as BS
import qualified Data.ByteString.Short                 as SBS

import           Network.SSH.Constants
import           Network.SSH.Exception
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Name
import           Network.SSH.Stream
import qualified Network.SSH.TStreamingQueue           as Q

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
    }

instance Default ConnectionConfig where
    def = ConnectionConfig
        { channelMaxCount      = 256
        , channelMaxQueueSize  = 32 * 1024
        , channelMaxPacketSize = 32 * 1024
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
    { sessStdin       :: Q.TStreamingQueue
    , sessStdout      :: Q.TStreamingQueue
    , sessStderr      :: Q.TStreamingQueue
    , sessExit        :: TMVar (Either ExitSignal ExitCode)
    }

newtype Command = Command BS.ByteString

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
    = O81 RequestSuccess
    | O82 RequestFailure
    | O90 ChannelOpen
    | O93 ChannelWindowAdjust
    | O94 ChannelData
    | O96 ChannelEof
    | O97 ChannelClose
    | O98 ChannelRequest

instance Encoding OutboundMessage where
    put (O81 x) = put x
    put (O82 x) = put x
    put (O90 x) = put x
    put (O93 x) = put x
    put (O94 x) = put x
    put (O96 x) = put x
    put (O97 x) = put x
    put (O98 x) = put x

data ChannelException
    = ChannelOpenFailed ChannelOpenFailureReason ChannelOpenFailureDescription
    | ChannelRequestFailed
    | ChannelClosed
    deriving (Eq, Show)

instance Exception ChannelException where

newtype ChannelOpenFailureDescription = ChannelOpenFailureDescription BS.ByteString
    deriving (Eq, Ord, Show)

newtype Environment = Environment ()

data ExitSignal
    = ExitSignal
    { exitSignalName   :: Name
    , exitCoreDumped   :: Bool
    , exitErrorMessage :: BS.ByteString
    } deriving (Eq, Ord, Show)

newtype SessionHandler a = SessionHandler (forall stdin stdout stderr. (OutputStream stdin, InputStream stdout, InputStream stderr)
    => stdin -> stdout -> stderr -> STM (Either ExitSignal ExitCode) -> IO a)

withConnection :: (MessageStream stream) => ConnectionConfig -> stream -> (Connection -> IO a) -> IO a
withConnection config stream runHandler = do
    c <- atomically $ Connection config <$> newTChan <*> newTVar mempty
    withAsync (runReceiver c) $ \receiverThread -> do
        withAsync (runHandler c) $ \handlerThread -> fix $ \continue -> do
            let left  = Left  <$> readTChan (connOutChan c)
                right = Right <$> waitSTM handlerThread
                receiverThreadException = do
                    waitSTM receiverThread -- throws exception or blocks forever
                    throwSTM exceptionInvalidState
            atomically (left <|> right <|> receiverThreadException) >>= \case
                Left msg -> sendMessage stream msg >> continue
                Right a  -> pure a
    where
        runReceiver c = forever $ receiveMessage stream >>= dispatchMessage c

---------------------------------------------------------------------------------------------------
-- PUBLIC FUNCTIONS
---------------------------------------------------------------------------------------------------

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
sendMessageSTM  c = writeTChan (connOutChan c)

runSession :: Connection -> Maybe Command -> SessionHandler a -> IO a
runSession c mcommand (SessionHandler handler) = do
    tlws     <- newTVarIO maxQueueSize
    trws     <- newTVarIO 0
    stdin    <- atomically (Q.newTStreamingQueue maxQueueSize trws)
    stdout   <- atomically (Q.newTStreamingQueue maxQueueSize tlws)
    stderr   <- atomically (Q.newTStreamingQueue maxQueueSize tlws)
    exit     <- newEmptyTMVarIO
    r        <- newEmptyTMVarIO
    rs       <- newEmptyTMVarIO
    clsd     <- newTVarIO False

    -- This function will be executed with the server's reponse
    -- and eventually turn the 'opening' channel into a 'running' one.
    -- NB: This code is executed by the receiver thread and not
    -- by the thread that called `session`.
    let withOpenResponse = \case
            Left failure -> do
                -- Set the channel close flag in order to avoid that `closeChannel`
                -- tries to close the channel. A channel that failed to open has never
                -- been in open state and no close messages shall be sent for it.
                writeTVar clsd True
                putTMVar r (Left failure)
            Right (ChannelOpenConfirmation lid rid rws rps) -> do
                let session = ChannelSession
                        { sessStdin               = stdin
                        , sessStdout              = stdout
                        , sessStderr              = stderr
                        , sessExit                = exit
                        }
                let channel = Channel
                        { chanIdLocal             = lid
                        , chanIdRemote            = rid
                        , chanMaxPacketSizeLocal  = maxPacketSize
                        , chanMaxPacketSizeRemote = rps
                        , chanWindowSizeLocal     = tlws
                        , chanWindowSizeRemote    = trws
                        , chanRequestSuccess      = rs
                        , chanClosed              = clsd
                        , chanApplication         = ChannelApplicationSession session
                        }
                writeTVar trws rws
                setChannelStateSTM c lid $ ChannelRunning channel
                putTMVar r (Right channel)

    let openChannel = atomically do
            lid <- registerChannelSTM c withOpenResponse
            sendMessageSTM c $ O90 $ ChannelOpen lid maxQueueSize maxPacketSize ChannelOpenSession
            pure lid

    let closeChannel lid = atomically do
            alreadyClosed <- swapTVar clsd True
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
                    sendMessageSTM c $ O96 $ ChannelEof   (chanIdRemote ch)
                    sendMessageSTM c $ O97 $ ChannelClose (chanIdRemote ch)
                -- Only this handler sets the channel to closing state and
                -- it is excuted exactly once. Getting here should be impossible.
                ChannelClosing {} -> throwSTM exceptionInvalidChannelState

    -- Waits for decision whether this channel could be opened or not.
    -- The previously registered callback will fill the variable waited for.
    let waitChannel = atomically $ readTMVar r >>= \case
            Right ch -> pure ch
            Left (ChannelOpenFailure _ reason descr _) -> throwSTM
                $ ChannelOpenFailed reason
                $ ChannelOpenFailureDescription $ SBS.fromShort descr

    bracket openChannel closeChannel $ const $ waitChannel >>= \ch -> do
        atomically $ sendMessageSTM c $ O98 $ case mcommand of
            Just (Command command) -> ChannelRequest
                { crChannel   = chanIdRemote ch
                , crType      = "exec"
                , crWantReply = True
                , crData      = runPut (put $ ChannelRequestExec $ SBS.toShort command)
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
        let exitSTM = readTMVar exit <|> (readTVar clsd >>= check >> pure (Right $ ExitFailure (-1)))
        withAsync (handler stdin stdout stderr exitSTM) $ \handlerAsync -> do
            let x1 = do
                    -- Wait for channel data on stdin to be transmitted to server.
                    checkNotClosedSTM ch
                    dat <- Q.dequeueShort stdin (chanMaxPacketSizeRemote ch)
                    sendMessageSTM c $ O94 $ ChannelData (chanIdRemote ch) dat
                    pure Nothing
                x2 = do
                    -- Wait for necessary window adjust to be transmitted to server.
                    checkNotClosedSTM ch
                    -- FIXME: need to consider stderr as well
                    recommended <- Q.askWindowSpaceAdjustRecommended stdout
                    unless recommended retry
                    increment <- Q.fillWindowSpace stdout
                    sendMessageSTM c $ O93 $ ChannelWindowAdjust (chanIdRemote ch) increment
                    pure Nothing
                x3 = do -- wait for handler thread to terminate
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
            readTVar (chanClosed ch) >>= check

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

channelAdjustWindowSTM :: Channel -> Word32 -> STM ()
channelAdjustWindowSTM ch increment = case chanApplication ch of
    ChannelApplicationSession ChannelSession { sessStdin = queue } ->
        Q.addWindowSpace queue increment <|> throwSTM exceptionWindowSizeOverflow

channelDataSTM :: Channel -> SBS.ShortByteString -> STM ()
channelDataSTM ch datShort = case chanApplication ch of
    ChannelApplicationSession ChannelSession { sessStdout = queue } -> do
        enqueued <- Q.enqueue queue dat <|> pure 0
        when (enqueued /= len) (throwSTM exceptionWindowSizeUnderrun)
    where
        dat = SBS.fromShort datShort -- TODO
        len = fromIntegral (SBS.length datShort)

channelExtendedDataSTM :: Channel -> Word32 -> SBS.ShortByteString -> STM ()
channelExtendedDataSTM ch _ datShort = case chanApplication ch of
    ChannelApplicationSession ChannelSession { sessStderr = queue } -> do
        enqueued <- Q.enqueue queue dat <|> pure 0
        when (enqueued /= len) (throwSTM exceptionWindowSizeUnderrun)
    where
        dat = SBS.fromShort datShort -- TODO
        len = fromIntegral (SBS.length datShort)

channelEofSTM :: Channel -> STM ()
channelEofSTM ch = case chanApplication ch of
    ChannelApplicationSession ChannelSession { sessStdout = out, sessStderr = err } -> do
        Q.terminate out
        Q.terminate err

channelRequestSTM :: Channel -> SBS.ShortByteString -> Bool -> BS.ByteString -> STM ()
channelRequestSTM ch typ wantReply dat = case chanApplication ch of
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
        _ -> throwSTM exceptionInvalidChannelRequest

dispatchMessage :: Connection -> InboundMessage -> IO ()
dispatchMessage c = \case
    I080 (GlobalRequest wantReply _) -> when wantReply
        $ atomically $ sendMessageSTM c
        $ O82 RequestFailure
    I091 x@(ChannelOpenConfirmation lid rid _ _) ->
        atomically $ getChannelStateSTM c lid >>= \case
            ChannelOpening f  -> f (Right x)
            ChannelRunning {} -> throwSTM exceptionInvalidChannelState
            -- The channel was set to closing locally:
            -- It is left in closing state and a close message is sent to the
            -- peer. The channel will be freed when the close reponse arrives.
            ChannelClosing {} -> sendMessageSTM c $ O97 $ ChannelClose rid
    I092 x@(ChannelOpenFailure lid _ _ _) ->
        atomically $ getChannelStateSTM c lid >>= \case
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
    I093 (ChannelWindowAdjust lid sz) ->
        atomically $ getChannelStateSTM c lid >>= \case
            ChannelOpening {} -> throwSTM exceptionInvalidChannelState
            ChannelRunning ch -> channelAdjustWindowSTM ch sz
            ChannelClosing {} -> pure ()
    I094 (ChannelData lid dat) ->
        atomically $ getChannelStateSTM c lid >>= \case
            ChannelOpening {} -> throwSTM exceptionInvalidChannelState
            ChannelRunning ch -> channelDataSTM ch dat
            ChannelClosing {} -> pure ()
    I095  (ChannelExtendedData lid typ dat) ->
        atomically $ getChannelStateSTM c lid >>= \case
            ChannelOpening {} -> throwSTM exceptionInvalidChannelState
            ChannelRunning ch -> channelExtendedDataSTM ch typ dat
            ChannelClosing {} -> pure ()
    I096 (ChannelEof lid) ->
        atomically $ getChannelStateSTM c lid >>= \case
            ChannelOpening {} -> throwSTM exceptionInvalidChannelState
            ChannelRunning ch -> channelEofSTM ch
            ChannelClosing {} -> pure ()
    I097 (ChannelClose lid) ->
        atomically $ getChannelStateSTM c lid >>= \case
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
                sendMessageSTM c $ O97 $ ChannelClose (chanIdRemote ch)
            -- A closing channel means that we have already sent
            -- a close message and this is the reponse. The channel gets
            -- freed and its id is ready for reuse.
            ChannelClosing {} -> unregisterChannelSTM c lid
    I098 (ChannelRequest lid typ wantReply dat) ->
        atomically $ getChannelStateSTM c lid >>= \case
            ChannelOpening {} -> throwSTM exceptionInvalidChannelState
            ChannelRunning ch -> channelRequestSTM ch typ wantReply dat
            ChannelClosing {} -> pure ()
    I099 (ChannelSuccess lid) ->
        atomically $ getChannelStateSTM c lid >>= \case
            ChannelOpening {} -> throwSTM exceptionInvalidChannelState
            ChannelRunning ch -> putTMVar (chanRequestSuccess ch) True
                <|> throwSTM exceptionUnexpectedChannelResponse
            ChannelClosing {} -> pure ()
    I100  (ChannelFailure lid) ->
        atomically $ getChannelStateSTM c lid >>= \case
            ChannelOpening {} -> throwSTM exceptionInvalidChannelState
            ChannelRunning ch -> putTMVar (chanRequestSuccess ch) False
                <|> throwSTM exceptionUnexpectedChannelResponse
            ChannelClosing {} -> pure ()
