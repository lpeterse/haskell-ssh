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
import           Network.SSH.Server.Config
import           Network.SSH.Server.Connection
import           Network.SSH.Server.KeyExchange
import           Network.SSH.Server.Transport
import           Network.SSH.Stream

serve :: (DuplexStream stream) => Config identity -> stream -> IO ()
serve config stream = withDisconnectHandler config $ do
    -- Receive the client version and reject immediately if this
    -- is not an SSH connection attempt (before allocating
    -- any more resources); respond with the server version string.
    clientVersion <- receiveClientVersion stream
    serverVersion <- sendServerVersion stream
    -- Initialize a new transport state object to keep track of
    -- packet sequence numbers and encryption contexts.
    -- The transport context has exclusive access to the stream handle.
    -- This assures that no plain text will ever be transmitted after
    -- an encryption context has been established.
    withTransportState stream
                       (serveTransport config clientVersion serverVersion)

serveTransport
    :: Config identity -> Version -> Version -> TransportState -> IO Disconnect
serveTransport config clientVersion serverVersion state = do
    -- The `sendMessage` operation on the `state` is not thread-safe.
    -- A background thread is started to serialize writes from different
    -- threads.
    -- => `enqueue` is a thread-safe variant of `sendMessage`.
    withAsyncSender config state $ \enqueue -> do
        -- Perform the initial key exchange.
        -- This key exchange is handled separately as the key exchange protocol
        -- shall be followed strictly and no other messages shall be accepted
        -- until the connection is authenticated and encrypted.
        -- The kexNextStep handler is a state machine that keeps track of
        -- running key re-exchanges and all required context.
        -- Key re-exchanges may be interleaved with regular traffic and
        -- therefore cannot be performed synchronously.
        (session, kexNextStep) <- performInitialKeyExchange config
                                                            state
                                                            enqueue
                                                            clientVersion
                                                            serverVersion
        -- Install a watchdog running in background that initiates
        -- a key re-exchange when necessary.
        withAsyncWatchdog config state (kexNextStep KexStart) $ do
            -- The connection is essentially a state machine.
            -- It also contains resources that need to be freed on termination
            -- (like running threads), therefore the bracket pattern.
            withConnection config session enqueue
                -- The next call waits for incoming messages
                -- and dispatches them either to the transport layer handling functions
                -- or to the connection layer. It terminates when receiving a disconnect
                -- message from the client or when an exception occurs.
                $ processIncomingMessages kexNextStep
  where
    processIncomingMessages
        :: (KexStep -> IO ()) -> Connection identity -> IO Disconnect
    processIncomingMessages kexNextStep connection = fix $ \continue -> do
        msg <- receiveMessage state
        onReceive config msg
        case msg of
            MsgDisconnect x       -> pure x
            MsgKexInit    kexInit -> do
                kexNextStep (KexProcessInit kexInit)
                continue
            MsgKexEcdhInit kexEcdhInit -> do
                kexNextStep (KexProcessEcdhInit kexEcdhInit)
                continue
            MsgKexNewKeys{} -> do
                switchDecryptionContext state
                continue
            _ -> do
                pushMessage connection msg
                continue

withAsyncWatchdog :: Config identity -> TransportState -> IO () -> IO a -> IO a
withAsyncWatchdog config state rekey run = withAsync runWatchdog
    $ \thread -> link thread >> run
  where
    runWatchdog = forever $ do
        required <- askRekeyingRequired config state
        when required rekey
        threadDelay 1000000

withAsyncSender
    :: Config identity -> TransportState -> ((Message -> IO ()) -> IO a) -> IO a
withAsyncSender config state runWith = do
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
        sendMessage state msg
        case msg of
            -- This thread shall terminate gracefully in case the
            -- message was a disconnect message. By specification
            -- no other messages may follow after a disconnect message.
            MsgDisconnect d -> pure d
            -- A key re-exchange is taken into effect right after
            -- the MsgKexNewKey message.
            MsgKexNewKeys{} -> switchEncryptionContext state >> continue
            _               -> continue

withDisconnectHandler :: Config identity -> IO Disconnect -> IO ()
withDisconnectHandler config run = action `catch` handler
  where
    action = run >>= (onDisconnect config . Right)
    handler e = onDisconnect config (Left e) >> throwIO e
