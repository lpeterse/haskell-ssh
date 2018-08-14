{-# LANGUAGE LambdaCase #-}
module Network.SSH.Server ( serve ) where

import           Control.Applicative            ((<|>))
import           Control.Concurrent             (threadDelay)
import           Control.Concurrent.Async       (Async, cancel, waitCatchSTM,
                                                 withAsync)
import           Control.Concurrent.MVar        (readMVar)
import           Control.Concurrent.STM.TMVar   (TMVar, newEmptyTMVarIO,
                                                 putTMVar, readTMVar)
import           Control.Concurrent.STM.TVar    (readTVar, registerDelay)
import           Control.Exception              (catch, fromException, throwIO,
                                                 toException)
import           Control.Monad                  (forever, join, void, when)
import           Control.Monad.STM              (STM, atomically, check)
import qualified Data.ByteString                as BS
import           Data.Function                  (fix)
import           Data.Monoid                    ((<>))

import           Network.SSH.Constants
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Connection
import           Network.SSH.Server.KeyExchange
import           Network.SSH.Server.Transport
import           Network.SSH.Stream

serve :: (DuplexStream stream) => Config identity -> stream -> IO ()
serve config stream = withHandledExceptions $ do
    -- Initialize a new transport state object to keep track of
    -- packet sequence numbers and encryption contexts.
    state <- newTransportState stream

    -- Perform the initial key exchange.
    -- This key exchange is handled separately as the key exchange protocol
    -- shall be followed strictly and no other messages shall be accepted
    -- until the connection is authenticated and encrypted.
    -- The kexNextStep handler is a state machine that keeps track of
    -- running key re-exchanges and all required context.
    -- Key re-exchanges may be interleaved with regular traffic and
    -- therefore cannot be performed synchronously.
    (session, kexOutput, kexNextStep) <- performInitialKeyExchange config state

    -- The connection is essentially a state machine.
    -- It also contains resources that need to be freed on termination
    -- (like running threads), therefore the bracket pattern.
    withConnection config session $ \connection-> do

        -- This is a one-element queue that shall be used to pass
        -- a server disconnect message to the sender thread.
        -- The sender thread is supposed to treat this queue with
        -- highest priority and terminate right after having read
        -- successfully from this queue.
        serverDisconnect <- newEmptyTMVarIO

        -- The sender is an infinite loop that waits for messages to be sent
        -- from either the transport or the connection layer.
        -- The sender is also aware of switching the encryption context
        -- when encountering KexNewKeys messages.
        let runSender = loop =<< readMVar (transportSender state)
                where
                    loop s = do
                        msg <- atomically readNextMessage
                        onSend config msg
                        s $ runPut $ put msg
                        case msg of
                            -- This thread shall terminate gracefully in case the
                            -- message was a disconnect message. By specification
                            -- no other messages may follow after a disconnect message.
                            MsgDisconnect d  -> pure d
                            -- A key re-exchange is taken into effect right after
                            -- the MsgKexNewKey message. The new cryptographic encoder
                            -- is loaded only once after sending this message and then
                            -- threaded through as a parameter of `loop`.
                            MsgKexNewKeys {} -> loop =<< readMVar (transportSender state)
                            _                -> loop s
                    -- An STM action that waits for next message with descending priority.
                    readNextMessage = (MsgDisconnect <$> readTMVar serverDisconnect)
                        <|> kexOutput
                        <|> pullMessageSTM connection

        -- The receiver is an infinite loop that waits for incoming messages
        -- and dispatches it either to the transport layer handling functions
        -- or to the connection layer.
        let runReceiver = loop =<< readMVar (transportReceiver state)
                where
                    loop r = r >>= runGet get >>= \msg-> onReceive config msg >> case msg of
                        MsgDisconnect x ->
                            pure x
                        MsgKexInit kexInit -> do
                            kexNextStep (KexProcessInit kexInit)
                            loop r
                        MsgKexEcdhInit kexEcdhInit -> do
                            kexNextStep (KexProcessEcdhInit kexEcdhInit)
                            loop r
                        MsgKexNewKeys {} ->
                            loop =<< readMVar (transportReceiver state)
                        _ -> do
                            pushMessage connection msg
                            loop r

        let runWatchdog = forever $ do
                required <- askRekeyingRequired config state
                when required (kexNextStep KexStart)
                threadDelay 1000000

        -- Two threads are necessary to process input and output concurrently.
        -- A third thread is used to initiate a rekeying after a certain amount of time
        -- or after exceeding transmission thresholds.
        withAsync runSender $ \senderAsync ->
            withAsync runReceiver $ \receiverAsync ->
                withAsync runWatchdog $ \watchdogAsync ->
                    waitForDisconnect serverDisconnect receiverAsync senderAsync watchdogAsync

    where
        withHandledExceptions :: IO () -> IO ()
        withHandledExceptions action = action `catch` \e -> do
            onDisconnect config (Left e)
            throwIO e

        waitForDisconnect
            :: TMVar Disconnect
            -> Async Disconnect
            -> Async Disconnect
            -> Async Disconnect
            -> IO ()
        waitForDisconnect serverDisconnect receiverAsync senderAsync watchdogAsync =
            join (atomically $ waitReceiver <|> waitSender <|> waitWatchdog) >>= \case
                Left  e -> throwIO e
                Right d -> do
                    cancel watchdogAsync
                    cancel receiverAsync
                    cancel senderAsync
                    onDisconnect config (Right d)
            where
                waitWatchdog = pure <$> waitCatchSTM watchdogAsync
                waitSender   = pure <$> waitCatchSTM senderAsync
                waitReceiver = waitCatchSTM receiverAsync >>= \case
                    -- Graceful client disconnect.
                    Right d -> pure $ pure $ Right d
                    -- When the receiver threw an exception this may either be
                    -- caused by invalid input, unexpected end of input or by program errors.
                    -- All cases are exceptional.
                    Left  e -> pure $ do
                        -- The sender thread shall be given one additional second to deliver the
                        -- disconnect message to the client. This may be unsucessful if the
                        -- connection is too slow or already closed. Delivery in this case
                        -- cannot be guaranteed when using TCP anyway (see SO_LINGER).
                        -- The server's main concern should be about freeing the resources as
                        -- fast as possible.
                        case fromException e of
                            Just d  -> do
                                timeout <- newTimer 1
                                atomically $ putTMVar serverDisconnect d
                                atomically $ void (waitCatchSTM senderAsync) <|> timeout
                            _ -> pure ()
                        pure $ Left e

                newTimer :: Int -> IO (STM ())
                newTimer i = registerDelay (i * 1000000) >>= \t-> pure (readTVar t >>= check)
