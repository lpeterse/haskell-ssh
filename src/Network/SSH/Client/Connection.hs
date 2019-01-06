{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Client.Connection where

import           Control.Applicative
import           Control.Concurrent.Async              ( ExceptionInLinkedThread (..), link, withAsync, waitSTM )
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Control.Exception                     ( Exception, bracket, catch, throwIO )
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
withConnection config stream handler = withMappedLinkedExceptions do
    c <- atomically $ Connection config <$> newTChan <*> newTVar mempty
    withAsync (dispatchIncoming stream c) $ \receiverThread -> do
        link receiverThread -- rethrow exceptions in main thread -- FIXME
        withAsync (handler c) $ \handlerThread -> fix $ \continue -> do
            let left  = Left  <$> readTChan (connOutChan c)
                right = Right <$> waitSTM handlerThread
            atomically (left <|> right) >>= \case
                Left msg -> sendMessage stream msg >> continue
                Right a  -> pure a
    where
        withMappedLinkedExceptions :: IO a -> IO a
        withMappedLinkedExceptions action =
            action `catch` \(ExceptionInLinkedThread _ e) -> throwIO e

        dispatchIncoming :: (MessageStream stream) => stream -> Connection -> IO ()
        dispatchIncoming s c = forever $ receiveMessage s >>= \case
            I080 (GlobalRequest wantReply _) -> when wantReply
                $ atomically $ sendMessageSTM c
                $ O82 RequestFailure
            I091 x@(ChannelOpenConfirmation lid _ _ _) ->
                atomically $ getChannelStateSTM c lid >>= \case
                    ChannelOpening f  -> f (Right x)
                    _                 -> throwSTM exceptionInvalidChannelState
            I092 x@(ChannelOpenFailure lid _ _ _) ->
                atomically $ getChannelStateSTM c lid >>= \case
                    ChannelOpening f  -> f (Left x)
                    _                 -> throwSTM exceptionInvalidChannelState
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
                    ChannelOpening {} -> throwSTM exceptionInvalidChannelState
                    -- A running channel means that the close is initiated
                    -- by the server.
                    -- In order to properly close the channel it is necessary to
                    -- set the closed flag in the channel, deregister
                    -- it from the channels map and respond with another close
                    -- message.
                    ChannelRunning ch -> do
                        writeTVar (chanClosed ch) True
                        unregisterChannelSTM c lid
                        sendMessageSTM c $ O97 $ ChannelClose (chanIdRemote ch)
                    -- A closing channel means that we have already sent
                    -- a close message and this is either a reponse or
                    -- a coincidence. In either case, it is okay to just
                    -- free the channel.
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

---------------------------------------------------------------------------------------------------
-- PUBLIC FUNCTIONS
---------------------------------------------------------------------------------------------------

shell :: Connection -> SessionHandler a -> IO a
shell c = session c Nothing

exec :: Connection -> Command -> SessionHandler a -> IO a
exec c command = session c (Just command)

---------------------------------------------------------------------------------------------------
-- INTERNAL FUNCTIONS
---------------------------------------------------------------------------------------------------

sendMessageSTM :: Connection -> OutboundMessage -> STM ()
sendMessageSTM  c = writeTChan (connOutChan c)

session :: Connection -> Maybe Command -> SessionHandler a -> IO a
session c mcommand (SessionHandler handler) = do
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
    -- and turn the 'opening' channel into a 'running' one.
    -- NB: This code is executed by the receiver thread and not
    -- by the thread that called `session`.
    let withOpenResponse = \case
            Left x@ChannelOpenFailure {} -> do
                putTMVar r (Left x)
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

    let openChannel = atomically $ do
            lid <- registerChannelSTM c withOpenResponse
            sendMessageSTM c $ O90 $ ChannelOpen lid maxQueueSize maxPacketSize ChannelOpenSession
            pure lid

    let closeChannel lid = atomically $ getChannelStateSTM c lid >>= \case
            -- An opening channel means that we have sent the
            -- channel open request but not yet got a reponse.
            -- We cannot unregister the channel until we go a response,
            -- but we can set it to closing state so that the
            -- server response dispatch function will unregister it.
            ChannelOpening {} -> setChannelStateSTM c lid ChannelClosing
            -- In order to properly close the channel it is necessary to
            -- set the closed flag in the channel, deregister
            -- it from the channels map and respond with another close
            -- message.
            ChannelRunning ch -> do
                writeTVar (chanClosed ch) True
                setChannelStateSTM c lid ChannelClosing
                sendMessageSTM c $ O96 $ ChannelEof   (chanIdRemote ch)
                sendMessageSTM c $ O97 $ ChannelClose (chanIdRemote ch)
            -- A closing channel means that we have already sent
            -- a close message. The dispatch handler will unregister the
            -- channel as soon as the close from peer arrives.
            ChannelClosing {} -> pure ()

    -- Waits for decision whether this channel could be opened or not.
    -- The previously registered callback will fill the variable waited for.
    let waitChannel = atomically $ readTMVar r >>= \case
            Right ch -> pure ch
            Left (ChannelOpenFailure _ reason descr _) -> throwSTM
                $ ChannelOpenFailed reason
                $ ChannelOpenFailureDescription $ SBS.fromShort descr

    bracket openChannel closeChannel $ \lid -> waitChannel >>= \ch -> do
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
        withAsync (handler stdin stdout stderr (readTMVar exit)) $ \handlerAsync -> do
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
