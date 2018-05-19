{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.Channel where

import           Control.Applicative
import           Control.Concurrent
import           Control.Concurrent.Async
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Concurrent.STM.TVar
import           Control.Exception
import           Control.Monad                (forever, unless, when)
import           Control.Monad.STM
import qualified Data.ByteString              as BS
import           Data.Function                (fix)
import qualified Data.Map.Strict              as M
import           Data.Maybe
import           Data.Text                    as T
import           Data.Text.Encoding           as T
import           Data.Typeable
import           System.Exit

import           Network.SSH.Constants
import           Network.SSH.Exception
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport
import           Network.SSH.Server.Types

data IncomingChannelMessage
  = IncomingChannelOpen         ChannelOpen
  | IncomingChannelEof          ChannelEof
  | IncomingChannelClose        ChannelClose
  | IncomingChannelData         ChannelData
  | IncomingChannelExtendedData ChannelExtendedData
  | IncomingChannelRequest      ChannelRequest
  deriving (Eq, Show)

handleIncomingChannelMessage :: Connection identity -> IncomingChannelMessage -> IO ()
handleIncomingChannelMessage connection = \case
    IncomingChannelOpen x         -> handleOpen x
    IncomingChannelEof x          -> error "FIXME"
    IncomingChannelClose x        -> handleClose x
    IncomingChannelData x         -> error "FIXME"
    IncomingChannelExtendedData x -> error "FIXME"
    IncomingChannelRequest x      -> error "FIXME"
    where
        handleOpen :: ChannelOpen -> IO ()
        handleOpen (ChannelOpen channelType remoteChannelId initialWindowSize maxPacketSize) = atomically $ do
            channels <- readTVar (connChannels connection)
            case selectLocalChannelId channels of
                Nothing -> do
                    send connection $ MsgChannelOpenFailure $
                      ChannelOpenFailure remoteChannelId ChannelOpenResourceShortage mempty mempty
                Just localChannelId -> do
                    wsLocal  <- newTVar initialWindowSize
                    wsRemote <- newTVar initialWindowSize
                    let channel = Channel {
                            chanConnection          = connection
                          , chanType                = channelType
                          , chanIdLocal             = localChannelId
                          , chanIdRemote            = remoteChannelId
                          , chanMaxPacketSizeLocal  = maxPacketSize
                          , chanMaxPacketSizeRemote = maxPacketSize
                          , chanWindowSizeLocal     = wsLocal
                          , chanWindowSizeRemote    = wsRemote
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

        handleClose :: ChannelClose -> IO ()
        handleClose (ChannelClose localChannelId) = atomically $ do
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

-- Free all associated resources like threads etc.
free :: Channel identity -> IO ()
free channel = pure ()

close :: Channel identity -> IO ()
close channel = atomically $ do
    alreadyClosed <- swapTVar (chanClosed channel) True
    unless alreadyClosed $
        send (chanConnection channel) $ MsgChannelClose $ ChannelClose $ chanIdRemote channel


{-

handleChannelData :: ChannelData -> IO ()
handleChannelData (ChannelData lid bs) = do
    undefined
    {-
    ch <- getChannel conn lid
    writeTChan (chanReadFd ch) bs -}

handleChannelExtendedData :: ChannelExtendedData -> IO ()
handleChannelExtendedData (ChannelExtendedData lid _ bs) = do
    undefined
    {-
    ch <- getChannel conn lid
    writeTChan (chanExtendedFd ch) bs -}

handleChannelRequest :: ChannelRequest -> IO ()
handleChannelRequest = \case
    ChannelRequestPty lid wantReply ts -> do
        undefined
        {-
        println conn $ show x
        ch <- getChannel conn lid
        writeTVar (chanPty ch) (Just ts)
        when wantReply $ do
            send $ MsgChannelSuccess $ ChannelSuccess $ chanRemoteId ch -}
    ChannelRequestShell lid wantReply -> undefined
      {-
      ch <- getChannel conn lid
      case onShellRequest config of
        Nothing ->
          when wantReply $
            send conn (MsgChannelFailure $ ChannelFailure $ chanRemoteId ch)
        Just runShell -> do
          when wantReply $
            send conn (MsgChannelSuccess $ ChannelSuccess $ chanRemoteId ch)
          mpty <- readTVar (chanPty ch)
          exec conn $ do
            let run = runShell mpty
                  (readTChan  $ chanReadFd ch)
                  (writeTChan $ chanWriteFd ch)
                  (writeTChan $ chanExtendedFd ch)
            withAsync run $ \asnc-> do
              closed <- atomically $ do
                closed <- readTVar (chanClosed ch)
                unless closed $ writeTVar (chanProc ch) (Just ProcRunning)
                pure closed
              -- `asnc` will be terminated as soon as the following block returns
              if closed
                then pure ()
                else let waitProcessTerm = waitCatchSTM asnc >>= \case
                          Left  e -> writeTVar (chanProc ch) $ Just $
                                      ProcExitSignal "ABRT" False (T.encodeUtf8 $ T.pack $ show e) ""
                          Right c -> writeTVar (chanProc ch) $ Just $
                                      ProcExitStatus c
                        waitChannelTerm = readTVar (chanClosed ch) >>= \case
                          True    -> pure ()
                          False   -> retry
                    in  atomically (waitProcessTerm `orElse` waitChannelTerm)
    -}
    ChannelRequestOther lid _ -> do
        undefined
        {-
        ch <- getChannel conn lid
        send (MsgChannelFailure $ ChannelFailure $ chanRemoteId ch) -}


handleChannels :: Connection -> STM ()
handleChannels conn =
  tryAny (\ch-> h1 ch `orElse` h2 ch `orElse` h3 ch) =<< readTVar (channels conn)
  where
    h1 Nothing = retry
    h1 (Just ch) = do
      bs <- readTChan (chanWriteFd ch)
      send conn (MsgChannelData $ ChannelData (chanRemoteId ch) bs)

    h2 Nothing = retry
    h2 (Just ch) = do
      bs <- readTChan (chanExtendedFd ch)
      send conn (MsgChannelExtendedData $ ChannelExtendedData (chanRemoteId ch) 1 bs)

    h3 Nothing = retry
    h3 (Just ch) = readTVar (chanProc ch) >>= \case
      Just (ProcExitStatus s) -> do
        send conn (MsgChannelRequest $ ChannelRequestExitStatus (chanRemoteId ch) s)
        closeChannel conn (chanLocalId ch)
      Just x@(ProcExitSignal s d m l) -> do
        send conn (MsgChannelRequest $ ChannelRequestExitSignal (chanRemoteId ch) s d m l)
        closeChannel conn (chanLocalId ch)
      _ -> retry

    tryAny :: (Maybe Channel -> STM ()) -> M.Map ChannelId (Maybe Channel) -> STM ()
    tryAny f m = M.foldr orElse retry (M.map f m)

getChannel :: Connection -> ChannelId -> STM Channel
getChannel conn l = do
  cs <- readTVar (channels conn)
  case M.lookup l cs of
    Nothing        -> throwSTM (ChannelDoesNotExist l)
    Just Nothing   -> throwSTM (ChannelIsClosing l)
    Just (Just ch) -> pure ch


-}


