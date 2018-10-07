{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE MultiWayIf                #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE TupleSections             #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RankNTypes                #-}
module Network.SSH.Server.Service.Connection
    ( Connection ()
    , ConnectionConfig (..)
    , Address (..)
    , Session (..)
    , DirectTcpIpRequest (..)
    , ConnectionMsg (..)
    , serveConnection
    ) where

import           Control.Applicative
import qualified Control.Concurrent.Async     as Async
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Control.Monad                (join, when, forever, unless)
import           Control.Monad.STM            (STM, atomically, check, throwSTM)
import           Control.Exception            (bracket, bracketOnError)
import qualified Data.ByteString              as BS
import           Data.Default
import qualified Data.Map.Strict              as M
import           Data.Word
import           System.Exit

import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Constants
import           Network.SSH.Message
import qualified Network.SSH.Stream as S
import qualified Network.SSH.TStreamingQueue as Q

data Connection identity
    = Connection
    { connConfig       :: ConnectionConfig identity
    , connIdentity     :: identity
    , connChannels     :: TVar (M.Map ChannelId Channel)
    }

data ConnectionConfig identity
    = ConnectionConfig
    { onExecRequest         :: Maybe (Session identity -> BS.ByteString -> IO ExitCode)
    , onShellRequest        :: Maybe (Session identity -> IO ExitCode)
    , onDirectTcpIpRequest  :: forall stream. S.DuplexStream stream => identity -> DirectTcpIpRequest -> IO (Maybe (stream -> IO ()))
    , channelMaxCount       :: Word16
    , channelMaxQueueSize   :: Word32
    , channelMaxPacketSize  :: Word32
    }

data Channel
    = Channel
    { chanApplication         :: ChannelApplication
    , chanIdLocal             :: ChannelId
    , chanIdRemote            :: ChannelId
    , chanMaxPacketSizeRemote :: Word32
    , chanClosed              :: TVar Bool
    , chanThread              :: TMVar (Async.Async ())
    }

data ChannelApplication
    = ChannelApplicationSession SessionState
    | ChannelApplicationDirectTcpIp DirectTcpIpState

data SessionState
    = SessionState
    { sessEnvironment :: TVar (M.Map BS.ByteString BS.ByteString)
    , sessPtySettings :: TVar (Maybe PtySettings)
    , sessStdin       :: Q.TStreamingQueue
    , sessStdout      :: Q.TStreamingQueue
    , sessStderr      :: Q.TStreamingQueue
    }

data Session identity
    = forall stdin stdout stderr. (S.InputStream stdin, S.OutputStream stdout, S.OutputStream stderr) => Session
    { identity    :: identity
    , environment :: M.Map BS.ByteString BS.ByteString
    , ptySettings :: Maybe PtySettings
    , stdin       :: stdin
    , stdout      :: stdout
    , stderr      :: stderr
    }

data DirectTcpIpState
    = DirectTcpIpState
    { dtiStreamIn     :: Q.TStreamingQueue
    , dtiStreamOut    :: Q.TStreamingQueue
    }

data DirectTcpIpRequest
    = DirectTcpIpRequest
    { destination   :: Address
    , origin        :: Address
      } deriving (Eq, Ord, Show)

data Address
    = Address
    { address :: BS.ByteString
    , port    :: Word32
    } deriving (Eq, Ord, Show)

instance S.InputStream DirectTcpIpState where
    receive x = S.receive (dtiStreamIn x)

instance S.OutputStream DirectTcpIpState where
    send x = S.send (dtiStreamOut x)

instance S.DuplexStream DirectTcpIpState where

data ConnectionMsg
    = ConnectionChannelOpen         ChannelOpen
    | ConnectionChannelClose        ChannelClose
    | ConnectionChannelEof          ChannelEof
    | ConnectionChannelData         ChannelData
    | ConnectionChannelRequest      ChannelRequest
    | ConnectionChannelWindowAdjust ChannelWindowAdjust
    deriving (Eq, Show)

instance Encoding ConnectionMsg where
    len (ConnectionChannelOpen x) = len x
    len (ConnectionChannelClose x) = len x
    len (ConnectionChannelEof x) = len x
    len (ConnectionChannelData x) = len x
    len (ConnectionChannelRequest x) = len x
    len (ConnectionChannelWindowAdjust x) = len x
    put (ConnectionChannelOpen x) = put x
    put (ConnectionChannelClose x) = put x
    put (ConnectionChannelEof x) = put x
    put (ConnectionChannelData x) = put x
    put (ConnectionChannelRequest x) = put x
    put (ConnectionChannelWindowAdjust x) = put x
    get = ConnectionChannelOpen <$> get
      <|> ConnectionChannelClose <$> get
      <|> ConnectionChannelEof <$> get
      <|> ConnectionChannelData <$> get
      <|> ConnectionChannelRequest <$> get
      <|> ConnectionChannelWindowAdjust <$> get

instance Default (ConnectionConfig identity) where
    def = ConnectionConfig
        { onExecRequest                 = Nothing
        , onShellRequest                = Nothing
        , onDirectTcpIpRequest          = \_ _ -> pure Nothing
        , channelMaxCount               = 256
        , channelMaxQueueSize           = 256 * 1024
        , channelMaxPacketSize          = 32 * 1024
        }

serveConnection :: forall stream identity. MessageStream stream =>
    ConnectionConfig identity -> stream -> identity -> IO ()
serveConnection config stream identity = bracket open close $ \connection ->
    forever $ receiveMessage stream >>= \case
        ConnectionChannelOpen         req -> connectionChannelOpen         connection stream req
        ConnectionChannelClose        req -> connectionChannelClose        connection stream req
        ConnectionChannelEof          req -> connectionChannelEof          connection        req
        ConnectionChannelData         req -> connectionChannelData         connection        req
        ConnectionChannelRequest      req -> connectionChannelRequest      connection stream req
        ConnectionChannelWindowAdjust req -> connectionChannelWindowAdjust connection        req
    where
        open :: IO (Connection identity)
        open = Connection
            <$> pure config
            <*> pure identity
            <*> newTVarIO mempty

        close :: Connection identity -> IO ()
        close connection = do
            channels <- readTVarIO (connChannels connection)
            mapM_ terminate (M.elems channels)
            where
                terminate channel =
                    maybe (pure ()) Async.cancel =<< atomically (tryReadTMVar $ chanThread channel)

connectionChannelOpen :: forall stream identity. MessageStream stream =>
    Connection identity -> stream -> ChannelOpen -> IO ()
connectionChannelOpen connection stream (ChannelOpen remoteChannelId remoteWindowSize remotePacketSize channelType) =
    case channelType of
        ChannelOpenSession -> do
            env      <- newTVarIO mempty
            pty      <- newTVarIO Nothing
            wsLocal  <- newTVarIO maxQueueSize
            wsRemote <- newTVarIO remoteWindowSize
            stdIn    <- atomically $ Q.newTStreamingQueue maxQueueSize wsLocal
            stdOut   <- atomically $ Q.newTStreamingQueue maxQueueSize wsRemote
            stdErr   <- atomically $ Q.newTStreamingQueue maxQueueSize wsRemote
            let app = ChannelApplicationSession SessionState
                    { sessEnvironment = env
                    , sessPtySettings = pty
                    , sessStdin       = stdIn
                    , sessStdout      = stdOut
                    , sessStderr      = stdErr
                    }
            atomically (openApplicationChannel app) >>= \case
                Left failure           -> sendMessage stream failure
                Right (_,confirmation) -> sendMessage stream confirmation
        ChannelOpenDirectTcpIp da dp oa op -> do
            let req = DirectTcpIpRequest (Address da dp) (Address oa op)
            onDirectTcpIpRequest (connConfig connection) (connIdentity connection) req >>= \case
                Nothing ->
                    sendMessage stream $ openFailure ChannelOpenAdministrativelyProhibited
                Just handler -> do
                    wsLocal   <- newTVarIO maxQueueSize
                    wsRemote  <- newTVarIO remoteWindowSize
                    streamIn  <- atomically $ Q.newTStreamingQueue maxQueueSize wsLocal
                    streamOut <- atomically $ Q.newTStreamingQueue maxQueueSize wsRemote
                    let st = DirectTcpIpState
                            { dtiStreamIn  = streamIn
                            , dtiStreamOut = streamOut
                            }
                    let app = ChannelApplicationDirectTcpIp st
                    atomically (openApplicationChannel app) >>= \case
                        Left failure -> sendMessage stream failure
                        Right (c,confirmation) -> do
                            forkDirectTcpIpHandler stream c st (handler st)
                            sendMessage stream confirmation
        ChannelOpenOther {} ->
            sendMessage stream $ openFailure ChannelOpenUnknownChannelType
    where
        openFailure :: ChannelOpenFailureReason -> ChannelOpenFailure
        openFailure reason = ChannelOpenFailure remoteChannelId reason mempty mempty

        openApplicationChannel :: ChannelApplication -> STM (Either ChannelOpenFailure (Channel, ChannelOpenConfirmation))
        openApplicationChannel application = tryRegisterChannel $ \localChannelId -> do
            closed <- newTVar False
            thread <- newEmptyTMVar
            pure Channel
                { chanApplication         = application
                , chanIdLocal             = localChannelId
                , chanIdRemote            = remoteChannelId
                , chanMaxPacketSizeRemote = remotePacketSize
                , chanClosed              = closed
                , chanThread              = thread
                }

        tryRegisterChannel :: (ChannelId -> STM Channel) -> STM (Either ChannelOpenFailure (Channel, ChannelOpenConfirmation))
        tryRegisterChannel createChannel = do
            channels <- readTVar (connChannels connection)
            case selectFreeLocalChannelId channels of
                Nothing -> pure $ Left $ openFailure ChannelOpenResourceShortage
                Just localChannelId -> do
                    channel <- createChannel localChannelId
                    writeTVar (connChannels connection) $! M.insert localChannelId channel channels
                    pure $ Right $ (channel,) $ ChannelOpenConfirmation
                        remoteChannelId
                        localChannelId
                        maxQueueSize
                        maxPacketSize

        maxQueueSize :: Word32
        maxQueueSize = max 1 $ fromIntegral $ min maxBoundIntWord32
            (channelMaxQueueSize $ connConfig connection)

        maxPacketSize :: Word32
        maxPacketSize = max 1 $ fromIntegral $ min maxBoundIntWord32
            (channelMaxPacketSize $ connConfig connection)

        selectFreeLocalChannelId :: M.Map ChannelId a -> Maybe ChannelId
        selectFreeLocalChannelId m
            | M.size m >= fromIntegral maxCount = Nothing
            | otherwise = f (ChannelId 0) $ M.keys m
            where
                f i []          = Just i
                f (ChannelId i) (ChannelId k:ks)
                    | i == k    = f (ChannelId $ i+1) ks
                    | otherwise = Just (ChannelId i)
                maxCount = channelMaxCount (connConfig connection)

connectionChannelEof ::
    Connection identity -> ChannelEof -> IO ()
connectionChannelEof connection (ChannelEof localChannelId) = atomically $ do
    channel <- getChannelSTM connection localChannelId
    let queue = case chanApplication channel of
            ChannelApplicationSession     st -> sessStdin   st
            ChannelApplicationDirectTcpIp st -> dtiStreamIn st
    Q.terminate queue

connectionChannelClose :: forall stream identity. MessageStream stream =>
    Connection identity -> stream -> ChannelClose -> IO ()
connectionChannelClose connection stream (ChannelClose localChannelId) = do
    channel <- atomically $ getChannelSTM connection localChannelId
    maybe (pure ()) Async.cancel =<< atomically (tryReadTMVar $ chanThread channel)
    atomically $ do
        channels <- readTVar (connChannels connection)
        writeTVar (connChannels connection) $! M.delete localChannelId channels
    -- When the channel is not marked as already closed then the close
    -- must have been initiated by the client and the server needs to send
    -- a confirmation (both sides may issue close messages simultaneously
    -- and receive them afterwards).
    closeAlreadySent <- readTVarIO (chanClosed channel)
    unless closeAlreadySent $
        sendMessage stream $ ChannelClose $ chanIdRemote channel

connectionChannelData ::
    Connection identity -> ChannelData -> IO ()
connectionChannelData connection (ChannelData localChannelId payload) = atomically $ do
    channel <- getChannelSTM connection localChannelId
    let queue = case chanApplication channel of
            ChannelApplicationSession     st -> sessStdin   st
            ChannelApplicationDirectTcpIp st -> dtiStreamIn st
    i <- Q.enqueue queue payload <|> throwSTM exceptionWindowSizeUnderrun
    when (i == 0) (throwSTM exceptionDataAfterEof)
    when (i /= payloadLen) (throwSTM exceptionWindowSizeUnderrun)
    where
        payloadLen = fromIntegral $ BS.length payload

connectionChannelWindowAdjust ::
    Connection identity -> ChannelWindowAdjust -> IO ()
connectionChannelWindowAdjust connection (ChannelWindowAdjust channelId increment) = atomically $ do
    channel <- getChannelSTM connection channelId
    let queue = case chanApplication channel of
            ChannelApplicationSession     st -> sessStdout   st
            ChannelApplicationDirectTcpIp st -> dtiStreamOut st
    Q.addWindowSpace queue increment <|> throwSTM exceptionWindowSizeOverflow

connectionChannelRequest :: forall identity stream. MessageStream stream =>
    Connection identity -> stream -> ChannelRequest -> IO ()
connectionChannelRequest connection stream (ChannelRequest channelId typ wantReply dat) = join $ atomically $ do
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
            "shell" -> interpret $ \ChannelRequestShell -> do
                st <- Session (connIdentity connection)
                    <$> readTVar (sessEnvironment sessionState)
                    <*> readTVar (sessPtySettings sessionState)
                    <*> pure (sessStdin  sessionState)
                    <*> pure (sessStdout sessionState)
                    <*> pure (sessStderr sessionState)
                case onShellRequest (connConfig connection) of
                    Nothing->
                        pure $ failure channel
                    Just exec -> pure $ do
                        forkSessionExecHandler stream channel sessionState (exec st)
                        success channel
            "exec" -> interpret $ \(ChannelRequestExec command) -> do
                st <- Session (connIdentity connection)
                    <$> readTVar (sessEnvironment sessionState)
                    <*> readTVar (sessPtySettings sessionState)
                    <*> pure (sessStdin  sessionState)
                    <*> pure (sessStdout sessionState)
                    <*> pure (sessStderr sessionState)
                case onExecRequest (connConfig connection) of
                    Nothing->
                        pure $ failure channel
                    Just exec -> pure $ do
                        forkSessionExecHandler stream channel sessionState (exec st command)
                        success channel
            -- "signal" ->
            -- "exit-status" ->
            -- "exit-signal" ->
            -- "window-change" ->
            _ -> pure $ failure channel
        ChannelApplicationDirectTcpIp {} -> pure $ failure channel
    where
        interpret f     = maybe (throwSTM exceptionInvalidChannelRequest) f (tryParse dat)
        success channel
            | wantReply = sendMessage stream $ ChannelSuccess (chanIdRemote channel)
            | otherwise = pure ()
        failure channel
            | wantReply = sendMessage stream $ ChannelFailure (chanIdRemote channel)
            | otherwise = pure ()

forkDirectTcpIpHandler :: forall stream. MessageStream stream =>
    stream -> Channel -> DirectTcpIpState -> IO () -> IO ()
forkDirectTcpIpHandler stream channel st handle = do
    registerThread channel handle supervise
    where
        supervise :: Async.Async () -> IO ()
        supervise thread = do
            continue <- join $ atomically
                $   waitOutput
                <|> waitExit thread
                <|> waitLocalWindowAdjust
            when continue $ supervise thread

        waitExit :: Async.Async () -> STM (IO Bool)
        waitExit thread = do
            eof <- Async.waitCatchSTM thread >>= \case
                Right _ -> pure True
                Left  _ -> pure False
            writeTVar (chanClosed channel) True
            pure $ do
                when eof $ sendMessage stream $ ChannelEof (chanIdRemote channel)
                sendMessage stream $ ChannelClose (chanIdRemote channel)
                pure False

        waitOutput :: STM (IO Bool)
        waitOutput = do
            bs <- Q.dequeue (dtiStreamOut st) (chanMaxPacketSizeRemote channel)
            pure $ do
                sendMessage stream $ ChannelData (chanIdRemote channel) bs
                pure True

        waitLocalWindowAdjust :: STM (IO Bool)
        waitLocalWindowAdjust = do
            check =<< Q.askWindowSpaceAdjustRecommended (dtiStreamIn st)
            increaseBy <- Q.fillWindowSpace (dtiStreamIn st)
            pure $ do
                sendMessage stream $ ChannelWindowAdjust (chanIdRemote channel) increaseBy
                pure True

forkSessionExecHandler :: forall stream. MessageStream stream =>
    stream -> Channel -> SessionState -> IO ExitCode -> IO ()
forkSessionExecHandler stream channel sessState handle = do
    registerThread channel handle supervise
    where
        -- The supervisor thread waits for several event sources simultaneously,
        -- handles them and loops until the session thread has terminated and exit
        -- has been signaled or the channel/connection got closed.
        supervise :: Async.Async ExitCode -> IO ()
        supervise workerAsync = atomically (w0 <|> w1 <|> w2 <|> w3) >>= \case
            Left  msgs -> mapM_ (sendMessage stream) msgs
            Right msgs -> mapM_ (sendMessage stream) msgs >> supervise workerAsync
            where
                -- NB: The order is critical: Another order would cause a close
                -- or eof to be sent before all data has been flushed.
                w0 = Right <$> waitStdout
                w1 = Right <$> waitStderr
                w2 = Left  <$> waitExit workerAsync
                w3 = Right <$> waitLocalWindowAdjust

        waitExit :: Async.Async ExitCode -> STM [Message]
        waitExit thread = do
            exitMessage <- Async.waitCatchSTM thread >>= \case
                Right c -> pure $ req "exit-status" $ runPut $ put $ ChannelRequestExitStatus c
                Left  _ -> pure $ req "exit-signal" $ runPut $ put $ ChannelRequestExitSignal "ILL" False "" ""
            writeTVar (chanClosed channel) True
            pure [eofMessage, exitMessage, closeMessage]
            where
                req t        = MsgChannelRequest . ChannelRequest (chanIdRemote channel) t False
                eofMessage   = MsgChannelEof $ ChannelEof (chanIdRemote channel)
                closeMessage = MsgChannelClose $ ChannelClose (chanIdRemote channel)

        waitStdout :: STM [Message]
        waitStdout = do
            bs <- Q.dequeue (sessStdout sessState) (chanMaxPacketSizeRemote channel)
            pure [MsgChannelData $ ChannelData (chanIdRemote channel) bs]

        waitStderr :: STM [Message]
        waitStderr = do
            bs <- Q.dequeue (sessStderr sessState) (chanMaxPacketSizeRemote channel)
            pure [MsgChannelExtendedData $ ChannelExtendedData (chanIdRemote channel) 1 bs]

        waitLocalWindowAdjust :: STM [Message]
        waitLocalWindowAdjust = do
            check =<< Q.askWindowSpaceAdjustRecommended (sessStdin sessState)
            increaseBy <- Q.fillWindowSpace (sessStdin sessState)
            pure [MsgChannelWindowAdjust $ ChannelWindowAdjust (chanIdRemote channel) increaseBy]

getChannelSTM :: Connection identity -> ChannelId -> STM Channel
getChannelSTM connection channelId = do
    channels <- readTVar (connChannels connection)
    case M.lookup channelId channels of
        Just channel -> pure channel
        Nothing      -> throwSTM exceptionInvalidChannelId

-- Two threads are forked: a worker thread running as Async and a
-- supervisor thread which is registered with the channel.
-- -> The worker thread does never outlive the supervisor thread (`withAsync`).
-- -> The supervisor thread terminates itself when either the worker thread
--    has terminated (`waitExit`) or gets cancelled when the channel/connection
--    gets closed.
-- -> The supervisor thread is started even if a thread is already running.
--    It is blocked until it is notified that it is the only one
--    running and its Async has been registered with the channel (meaning
--    it will be reliably cancelled on main thread termination).
registerThread :: Channel -> IO a -> (Async.Async a -> IO ()) -> IO ()
registerThread channel run supervise = do
    barrier <- newTVarIO False
    let prepare = Async.async $ do
            atomically $ readTVar barrier >>= check
            Async.withAsync run supervise
    let abort = Async.cancel
    let register thread =
            putTMVar (chanThread channel) thread
            <|> throwSTM exceptionAlreadyExecuting
    bracketOnError prepare abort $ \thread -> atomically $
        register thread >> writeTVar barrier True
