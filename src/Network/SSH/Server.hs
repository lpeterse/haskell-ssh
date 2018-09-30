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
    withTransport config stream (serveTransport config clientVersion serverVersion)

serveTransport :: Config identity -> Version -> Version -> Transport -> IO Disconnect
serveTransport config cv sv transport =
    -- Perform the initial key exchange.
    -- This key exchange is handled separately as the key exchange protocol
    -- shall be followed strictly and no other messages shall be accepted
    -- until the connection is authenticated and encrypted.
    -- The kexNextStep handler is a state machine that keeps track of
    -- running key re-exchanges and all required context.
    -- Key re-exchanges may be interleaved with regular traffic and
    -- therefore cannot be performed synchronously.
    performInitialKeyExchange config transport (sendMessage transport) cv sv >>= \case
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
                    U.dispatcher config session (sendMessage transport) $
                    C.dispatcher config (sendMessage transport)
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

withDisconnectHandler :: Config identity -> IO Disconnect -> IO ()
withDisconnectHandler config run = action `catch` handler
  where
    action = run >>= (onDisconnect config . Right)
    handler e = onDisconnect config (Left e) >> throwIO e
