{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.Channel where

import           Control.Applicative
import           Control.Concurrent
import qualified Control.Concurrent.Async     as Async
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Concurrent.STM.TVar
import           Control.Exception
import           Control.Monad                (forever, join, unless, void,
                                               when)
import           Control.Monad.STM
import qualified Data.ByteArray               as BA
import qualified Data.ByteString              as BS
import           Data.Function                (fix)
import qualified Data.Map.Strict              as M
import           Data.Maybe
import           Data.Text                    as T
import           Data.Text.Encoding           as T
import           Data.Typeable
import           Data.Word
import           System.Exit

import           Network.SSH.Constants
import qualified Network.SSH.DuplexStream     as DS
import           Network.SSH.Exception
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport
import           Network.SSH.Server.Types

handleChannelOpen :: Connection identity -> ChannelOpen -> IO ()
handleChannelOpen connection (ChannelOpen channelType remoteChannelId initialWindowSize maxPacketSize) = atomically $ do
    channels <- readTVar (connChannels connection)
    case selectLocalChannelId channels of
        Nothing -> do
            send connection $ MsgChannelOpenFailure $
              ChannelOpenFailure remoteChannelId ChannelOpenResourceShortage mempty mempty
        Just localChannelId -> do
            application <- case channelType of
                  (ChannelType "session") -> do
                      env <- newTVar mempty
                      pty <- newTVar Nothing
                      pure $ ChannelApplicationSession Session {
                            sessEnvironment = env
                          , sessTerminal = pty
                          }
                  (ChannelType other) ->
                      pure (ChannelApplicationOther other)
            wsLocal  <- newTVar initialWindowSize
            wsRemote <- newTVar initialWindowSize
            closed   <- newTVar False
            let channel = Channel {
                    chanConnection          = connection
                  , chanApplication         = application
                  , chanIdLocal             = localChannelId
                  , chanIdRemote            = remoteChannelId
                  , chanMaxPacketSizeLocal  = maxPacketSize
                  , chanMaxPacketSizeRemote = maxPacketSize
                  , chanWindowSizeLocal     = wsLocal
                  , chanWindowSizeRemote    = wsRemote
                  , chanClosed              = closed
                  }
            writeTVar (connChannels connection) $! M.insert localChannelId channel channels
            send connection $ MsgChannelOpenConfirmation $ ChannelOpenConfirmation
                remoteChannelId
                localChannelId
                initialWindowSize
                maxPacketSize
    where
      selectLocalChannelId :: M.Map ChannelId a -> Maybe ChannelId
      selectLocalChannelId m
          | M.size m >= channelMaxCount (connConfig connection) = Nothing
          | otherwise = f (ChannelId 1) $ M.keys m
          where
              f i [] = Just i
              f (ChannelId i) (ChannelId k:ks)
                  | i == maxBound = Nothing
                  | i == k        = f (ChannelId $ i+1) ks
                  | otherwise     = Just (ChannelId i)

handleChannelClose :: Connection identtiy -> ChannelClose -> IO ()
handleChannelClose connection (ChannelClose localChannelId) = atomically $ do
    channels <- readTVar (connChannels connection)
    case M.lookup localChannelId channels of
        -- The client tries to close the same channel twice.
        -- This is a protocol error and the server shall disconnect.
        Nothing ->
            disconnectWith connection DisconnectProtocolError
        Just channel -> do
            writeTVar (connChannels connection) $! M.delete localChannelId channels
            alreadyClosed <- swapTVar (chanClosed channel) True
            -- When the channel is not marked as already closed then the close
            -- must have been initiated by the client and the server needs to send
            -- a confirmation.
            unless alreadyClosed $
                send connection $ MsgChannelClose $ ChannelClose $ chanIdRemote channel

handleChannelEof :: Connection identity -> ChannelEof -> IO ()
handleChannelEof = undefined

handleChannelData :: Connection identity -> ChannelData -> IO ()
handleChannelData = undefined

handleChannelExtendedData :: Connection identity -> ChannelExtendedData -> IO ()
handleChannelExtendedData = undefined

getChannel :: Connection identity -> ChannelId -> STM (Channel identity)
getChannel connection channelId = do
    channels <- readTVar (connChannels connection)
    case M.lookup channelId channels of
        Just channel -> pure channel
        Nothing      -> throwSTM (Disconnect DisconnectProtocolError "invalid channel id" "")

handleChannelWindowAdjust :: Connection identity -> ChannelWindowAdjust -> IO ()
handleChannelWindowAdjust connection (ChannelWindowAdjust channelId (ChannelWindowSize increase)) =
    atomically $ do
        channel <- getChannel connection channelId
        ChannelWindowSize ws <- readTVar (chanWindowSizeRemote channel)
        -- Conversion to Word64 necessary for overflow check.
        let ws' = fromIntegral ws + fromIntegral increase :: Word64
        when (ws' > 2 ^ 32 - 1) $
            throwSTM $ Disconnect DisconnectProtocolError "window size overflow" mempty
        writeTVar (chanWindowSizeRemote channel) $ ChannelWindowSize (fromIntegral ws')

handleChannelRequest :: Connection identity -> ChannelRequest -> IO ()
handleChannelRequest connection (ChannelRequest channelId request) =
    join $ atomically $ do
        channel <- getChannel connection channelId
        case chanApplication channel of
            ChannelApplicationSession session -> case request of
                ChannelRequestEnv wantReply name value -> do
                    env <- readTVar (sessEnvironment session)
                    writeTVar (sessEnvironment session) $! M.insert name value env
                    when wantReply (sendSuccess channel)
                    pass
                ChannelRequestExec wantReply command -> case onExecRequest (connConfig connection) of
                    Nothing -> do
                        when wantReply (sendFailure channel)
                        pass
                    Just exec -> readTVar (connIdentity connection) >>= \case
                        Nothing -> do
                          when wantReply (sendFailure channel)
                          pass
                        Just identity -> do
                          when wantReply (sendSuccess channel)
                          pure (sessionExec connection channel session (\s0 s1 s2-> exec identity s0 s1 s2 command))
                _ -> throwProtocolError "cannot dispatch channel request on session channel"
            _ -> throwProtocolError "cannot dispatch channel request"
    where
        pass                 = pure $ pure ()
        throwProtocolError e = throwSTM $ Disconnect DisconnectProtocolError e mempty
        sendSuccess channel  = send connection $ MsgChannelSuccess $ ChannelSuccess (chanIdRemote channel)
        sendFailure channel  = send connection $ MsgChannelFailure $ ChannelFailure (chanIdRemote channel)

-- Free all associated resources like threads etc.
free :: Channel identity -> IO ()
free channel = pure ()

close :: Channel identity -> STM ()
close channel = do
    alreadyClosed <- swapTVar (chanClosed channel) True
    unless alreadyClosed $
        send (chanConnection channel) $ MsgChannelClose $ ChannelClose $ chanIdRemote channel

sessionExec :: Connection identity -> Channel identity -> Session
            -> (stdin -> stdout -> stdout -> IO ExitCode) -> IO ()
sessionExec connection channel session handler =
    void $ forkIO $ Async.withAsync (handler undefined undefined undefined) wait
    where
      -- Waits for several event sources simultaneously, handles them
      -- loops until the session thread has terminated and exit has been signaled.
      wait :: Async.Async ExitCode ->IO ()
      wait thread = do
          exit <- atomically $ waitExit thread
          unless exit (wait thread)

      waitExit :: Async.Async ExitCode -> STM Bool
      waitExit thread = do
          Async.waitCatchSTM thread >>= \case
              Right c -> sendExit $ ChannelRequestExitStatus c
              Left  _ -> sendExit $ ChannelRequestExitSignal "ILL" False "" ""
          close channel
          pure True
          where
              sendExit :: ChannelRequestRequest -> STM ()
              sendExit = send connection . MsgChannelRequest
                  . ChannelRequest (chanIdRemote channel)

instance DS.OutputStream (BS.ByteString -> IO Int) where
  send stream ba = stream (BA.convert ba)

-- input lesen
-- output schreiben
-- windows size readjustment
-- close on exit

data TAccountingQueue
    = AccountingQueue
    { aqTaken   :: TVar Int
    , aqHead    :: TVar (BA.View BA.Bytes)
    , aqTail    :: TChan (BA.View BA.Bytes)
    , aqSize    :: TVar Int
    , aqMaxSize :: Int
    }

enqueue :: TAccountingQueue -> BA.Bytes -> STM Int
enqueue q ba = do
    queueSize <- readTVar (aqSize q)
    let len = BA.length ba
    let available = aqMaxSize q - queueSize
    if  | len == 0 -> pure 0
        | available > 0 -> do
            let n = min available len
            writeTChan (aqTail q) (BA.takeView ba n)
            writeTVar (aqSize q) (queueSize + n)
            pure n
        | otherwise -> retry

dequeue :: TAccountingQueue -> Int -> STM BA.Bytes
dequeue _ 0   = pure BA.empty
dequeue q len = do
    queueSize <- readTVar (aqSize q)
    check (queueSize > 0) -- retry when queue is empty
    h0 <- readTVar (aqHead q)
    h1 <- if BA.null h0 then readTChan (aqTail q) else pure h0
    let n = min (BA.length h1) len
    writeTVar (aqHead q) $ BA.dropView (BA.convert $ BA.dropView h1 n :: BA.Bytes) 0
    writeTVar (aqSize q) (queueSize - n)
    writeTVar (aqTaken q) . (+ n) =<< readTVar (aqTaken q)
    pure $ BA.convert $ BA.takeView h1 n

instance DS.OutputStream TAccountingQueue where
    send q ba = atomically $ enqueue q (BA.convert ba)

instance DS.InputStream TAccountingQueue where
    receive q i = atomically $ BA.convert <$> dequeue q i
