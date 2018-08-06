{-# LANGUAGE LambdaCase #-}
module Network.SSH.Server ( serve ) where

import           Control.Applicative            ((<|>))
import           Control.Concurrent.Async       (waitCatchSTM, withAsync)
import           Control.Concurrent.MVar        (readMVar)
import           Control.Concurrent.STM.TVar    (readTVar, registerDelay)
import           Control.Exception              (throwIO)
import           Control.Monad                  (join, void, when)
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
serve config stream = do
    -- Initialize a new transport state object to keep track of
    -- packet sequence numbers and encryption contexts.
    state <- newTransportState stream

    withExceptionsCaught state $ do
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

            -- The sender is an infinite loop that waits for messages to be sent
            -- from either the transport or the connection layer.
            -- The sender is also aware of switching the encryption context
            -- when encountering KexNewKeys messages.
            let runSender = loop =<< readMVar (transportSender state)
                    where
                        loop s = do
                            msg <- atomically $ kexOutput <|> pullMessageSTM connection
                            onSend config msg
                            s $ runPut $ put msg
                            -- This thread shall terminate gracefully in case the
                            -- message was a disconnect message. By specification
                            -- no other messages may follow after a disconnect message.
                            case msg of
                                MsgDisconnect d  -> throwIO d
                                MsgKexNewKeys {} -> loop =<< readMVar (transportSender state)
                                _                -> loop s

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
                            MsgKexNewKeys {} -> do
                                loop =<< readMVar (transportReceiver state)
                            _ -> do
                                pushMessage connection msg
                                loop r

            -- Two threads are necessary to process input and output concurrently.
            -- A third thread is used to initiate a rekeying after a certain amount of time
            -- or after exceeding transmission thresholds.
            withAsync runSender $ \senderAsync->
                withAsync runReceiver $ \receiverAsync-> fix $ \continue-> do

                    let waitSender = waitCatchSTM senderAsync >>= \case
                            Left  e -> pure $ pure () -- onDisconnect config (Left e)
                            Right _ -> undefined -- impossible

                    let waitReceiver = waitCatchSTM receiverAsync >>= \case
                            -- Handle graceful client disconnect (client sent disconnect message).
                            -- This is the only non-exceptional case.
                            Right d -> pure $ pure () -- onDisconnect config (Right d)
                            -- When the receiver threw an exception this may either be
                            -- caused by invalid input, unexpected end of input or by program errors.
                            -- All cases are exceptional.
                            -- The sender thread is given one additional second to deliver the
                            -- disconnect message to the client. This may be unsucessful if the
                            -- connection is too slow or already closed. Delivery in this case
                            -- cannot be guaranteed when using TCP anyway (see SO_LINGER).
                            -- The server's main concern should be about freeing the resources as
                            -- fast as possible.
                            Left  e -> pure $ do
                                timeout <- newTimer 1
                                atomically $ void (waitCatchSTM senderAsync) <|> timeout
                                -- onDisconnect config (Left  e)

                    let waitWatchdog delay = do
                            delay :: STM ()
                            pure $ do
                                required <- askRekeyingRequired config state
                                when required (kexNextStep KexStart)
                                continue :: IO ()

                    delay <- newTimer 1
                    join $ atomically $ waitReceiver <|> waitSender <|> waitWatchdog delay
    where
        newTimer :: Int -> IO (STM ())
        newTimer i = registerDelay (i * 1000000) >>= \t-> pure (readTVar t >>= check)

        withExceptionsCaught state action = action


