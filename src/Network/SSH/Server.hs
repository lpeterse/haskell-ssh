{-# LANGUAGE LambdaCase #-}
module Network.SSH.Server
    ( serve
    )
where

import           Control.Applicative            ( (<|>) )
import           Control.Concurrent             ( threadDelay )
import           Control.Concurrent.Async       ( link
                                                , waitCatchSTM
                                                , withAsync
                                                )
import           Data.Function                  ( fix )
import           Control.Concurrent.STM.TMVar   ( TMVar
                                                , newEmptyTMVarIO
                                                , putTMVar
                                                , readTMVar
                                                )
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar    ( readTVar
                                                , registerDelay
                                                )
import           Control.Exception              ( fromException
                                                , throwIO
                                                , catch
                                                )
import           Control.Monad                  ( forever
                                                , void
                                                , when
                                                )
import           Control.Monad.STM              ( atomically
                                                , check
                                                )
import           Data.Maybe

import           Network.SSH.Message
import           Network.SSH.Server.Internal
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport
import           Network.SSH.Server.Transport.KeyExchange
import           Network.SSH.Stream (DuplexStream ())
import qualified Network.SSH.Server.Service.UserAuth as U
import qualified Network.SSH.Server.Service.Connection as C

serve :: (DuplexStream stream) => Config identity -> stream -> IO ()
serve config stream = withDisconnectHandler config $ do
    -- Receive the client version and reject immediately if this
    -- is not an SSH connection attempt (before allocating
    -- any more resources); respond with the server version string.
    clientVersion <- receiveClientVersion stream
    serverVersion <- sendServerVersion stream
    -- Initialize a new transport object to keep track of
    -- packet sequence numbers and encryption contexts.
    -- The transport context has exclusive access to the stream handle.
    -- This assures that no plain text will ever be transmitted after
    -- an encryption context has been established.
    withTransport stream (serveTransport config clientVersion serverVersion)

serveTransport :: Config identity -> Version -> Version -> Transport -> IO Disconnect
serveTransport config cv sv transport = do
    -- The `sendMessage` operation on the `transport` is not thread-safe.
    -- A background thread is started to serialize writes from different
    -- threads.
    -- => `send` is a thread-safe variant of `sendMessage`.
    withAsyncSender config transport $ \send ->
        -- Perform the initial key exchange.
        -- This key exchange is handled separately as the key exchange protocol
        -- shall be followed strictly and no other messages shall be accepted
        -- until the connection is authenticated and encrypted.
        -- The kexNextStep handler is a state machine that keeps track of
        -- running key re-exchanges and all required context.
        -- Key re-exchanges may be interleaved with regular traffic and
        -- therefore cannot be performed synchronously.
        performInitialKeyExchange config transport send cv sv >>= \case
            Left disconnect -> pure disconnect
            Right (session, kexNextStep) ->
                -- Install a watchdog running in background that initiates
                -- a key re-exchange when necessary.
                withAsyncWatchdog config transport (kexNextStep KexStart) $ do
                    -- The authentication layer is (in this implementation) the
                    -- next higher layer. All other layers are on top of it
                    -- and all messages are passed through it (and eventually
                    -- rejected as long is the user is not authenticated).
                    -- withServiceLayer config session enqueue
                    -- The next call waits for incoming messages
                    -- and dispatches them either to the transport layer handling functions
                    -- or to the connection layer. It terminates when receiving a disconnect
                    -- message from the client or when an exception occurs.
                    processInboundMessages
                        kexNextStep $
                        U.dispatcher config session send $
                        C.dispatcher config send
  where
    processInboundMessages :: (KexStep -> IO ()) -> MessageDispatcher Disconnect -> IO Disconnect
    processInboundMessages kexNextStep = g
        where 
            g dispatch = do
                msg <- receiveMessage transport
                onReceive config msg
                case msg of
                    ----------------- transport layer messages -------------
                    MsgDisconnect x ->
                        pure x
                    MsgDebug {} ->
                        g dispatch
                    MsgIgnore {} ->
                        g dispatch
                    MsgUnimplemented {} ->
                        g dispatch
                    MsgKexInit kexInit -> do
                        kexNextStep (KexProcessInit kexInit)
                        g dispatch
                    MsgKexEcdhInit kexEcdhInit -> do
                        kexNextStep (KexProcessEcdhInit kexEcdhInit)
                        g dispatch
                    MsgKexNewKeys{} -> do
                        switchDecryptionContext transport
                        g dispatch
                    ----------------- higer layer messages ------------------
                    _ -> dispatch msg (Continuation g)

withAsyncWatchdog :: Config identity -> Transport -> IO () -> IO a -> IO a
withAsyncWatchdog config transport rekey run = withAsync runWatchdog
    $ \thread -> link thread >> run
  where
    runWatchdog = forever $ do
        required <- askRekeyingRequired config transport
        when required rekey
        threadDelay 1000000

withAsyncSender
    :: Config identity -> Transport -> ((Message -> IO ()) -> IO a) -> IO a
withAsyncSender config transport runWith = do
    -- This is a one-element queue that shall be used to pass
    -- a server disconnect message to the sender thread.
    -- The sender thread is supposed to treat this queue with
    -- highest priority and terminate right after having read
    -- successfully from this queue.
    outDisconnect <- newEmptyTMVarIO :: IO (TMVar Disconnect)
    outQueue      <- newTChanIO
    let enqueue = atomically . writeTChan outQueue
    let dequeue =
            atomically
                $   (MsgDisconnect <$> readTMVar outDisconnect)
                <|> readTChan outQueue
    withAsync (runSender dequeue) $ \thread ->
        link thread >> runWith enqueue `catch` \e -> do
        -- In case of an exception, the sender thread shall try to
        -- deliver a disconnect message to the client before terminating.
        -- It might happen that the message cannot be sent in time or
        -- the sending itself fails with an exception or the sender thread
        -- is already dead. All cases have been considered and are
        -- handled here: In no case does this procedure take longer than 1 second.
            atomically $ putTMVar outDisconnect $ fromMaybe
                (Disconnect DisconnectByApplication mempty mempty)
                (fromException e)
            timeout <- (\t -> readTVar t >>= check) <$> registerDelay 1000000
            atomically $ timeout <|> void (waitCatchSTM thread)
            throwIO e
  where
        -- The sender is an infinite loop that waits for messages to be sent
        -- from either the transport or the connection layer.
        -- The sender is also aware of switching the encryption context
        -- when encountering KexNewKeys messages.
    runSender dequeue = fix $ \continue -> do
        msg <- dequeue
        onSend config msg
        sendMessage transport msg
        case msg of
            -- This thread shall terminate gracefully in case the
            -- message was a disconnect message. By specification
            -- no other messages may follow after a disconnect message.
            MsgDisconnect d -> pure d
            -- A key re-exchange is taken into effect right after
            -- the MsgKexNewKey message.
            MsgKexNewKeys{} -> switchEncryptionContext transport >> continue
            _               -> continue

withDisconnectHandler :: Config identity -> IO Disconnect -> IO ()
withDisconnectHandler config run = action `catch` handler
  where
    action = run >>= (onDisconnect config . Right)
    handler e = onDisconnect config (Left e) >> throwIO e
