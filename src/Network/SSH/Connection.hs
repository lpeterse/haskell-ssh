{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}
module Network.SSH.Connection where

import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Exception
import           Control.Monad                (forM_, forever, when)
import           Control.Monad.Reader
import           Control.Monad.State.Lazy
import           Control.Monad.STM
import qualified Data.Binary.Get              as B
import qualified Data.ByteArray               as BA
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Builder      as BS
import qualified Data.ByteString.Lazy         as LBS
import           Data.Function                (fix)
import qualified Data.Map.Strict              as M
import           Data.Monoid
import           Data.Typeable
import           Data.Word

import           Network.SSH

data Connection
  = Connection
  { receive  :: STM Message
  , send     :: Message -> STM ()
  , println  :: String -> STM ()
  , channels :: TVar (M.Map ChannelId (Maybe Channel))
  }

data Channel
  = Channel
  { chanType           :: ChannelType
  , chanLocalId        :: ChannelId
  , chanRemoteId       :: ChannelId
  , chanInitWindowSize :: InitWindowSize
  , chanMaxPacketSize  :: MaxPacketSize
  , chanReadFd         :: TChan BS.ByteString
  , chanWriteFd        :: TChan BS.ByteString
  , chanExtendedFd     :: TChan BS.ByteString
  }

data Pty
  = Pty
  { ptyStdin  :: TChan BS.ByteString
  , ptyStdout :: TChan BS.ByteString
  , ptyStderr :: TChan BS.ByteString
  }

data Process
  = Process
  { procKill  :: STM ()
  }

serve :: STM Message -> (Message -> STM ()) ->  IO ()
serve input output = do
  debug  <- newTChanIO
  chans  <- newTVarIO mempty
  let conn = Connection {
      receive  = input
    , send     = output
    , println  = writeTChan debug
    , channels = chans
    }
  runDebug conn debug `race_` runConnection conn
  where
    runDebug :: Connection -> TChan String -> IO ()
    runDebug conn ch = forever $
      atomically (readTChan ch) >>= putStr

    runConnection :: Connection -> IO ()
    runConnection conn = do
      (disconnect, isDisconnected) <- newTVarIO False >>= \d-> pure (writeTVar d True, readTVarIO d)
      fix $ \continue-> do
        atomically $ handleInput conn disconnect
          `orElse` handleChannelFds conn
        isDisconnected >>= \case
          True  -> pure ()  -- this is the only thread that may return
          False -> continue

handleInput :: Connection -> STM () -> STM ()
handleInput conn disconnect = receive conn >>= \case
  Disconnect {} ->
    disconnect
  ServiceRequest x ->
    send conn (ServiceAccept x)
  UserAuthRequest {} ->
    send conn UserAuthSuccess
  ChannelOpen t rid ws ps ->
    openChannel conn t rid ws ps >>= \case
      Nothing  -> send conn $ ChannelOpenFailure rid ResourceShortage "" ""
      Just ch  -> send conn $ ChannelOpenConfirmation
        (chanRemoteId ch)
        (chanLocalId ch)
        (chanInitWindowSize ch)
        (chanMaxPacketSize ch)
  ChannelData lid bs -> do
    ch <- getChannel conn lid
    writeTChan (chanWriteFd ch) bs
  ChannelDataExtended lid _ bs -> do
    ch <- getChannel conn lid
    writeTChan (chanExtendedFd ch) bs
  ChannelEof _ ->
    pure ()
  ChannelClose lid ->
    closeChannel conn lid >>= \case
      Nothing  -> pure () -- channel finally closed
      Just rid -> send conn (ChannelClose rid) -- channel semi-closed
  ChannelRequest lid x -> do
    ch <- getChannel conn lid
    case x of
      ChannelRequestPTY {} ->
        send conn (ChannelRequestSuccess $ chanRemoteId ch)
      ChannelRequestShell wantReply ->
        send conn (ChannelRequestSuccess $ chanRemoteId ch)
      ChannelRequestOther other ->
        send conn (ChannelRequestFailure $ chanRemoteId ch)

handleChannelFds :: Connection -> STM ()
handleChannelFds conn =
  tryAny (\ch-> h1 ch `orElse` h2 ch) =<< readTVar (channels conn)
  where
    h1 Nothing = retry
    h1 (Just ch) = do
      bs <- readTChan (chanWriteFd ch)
      send conn (ChannelData (chanRemoteId ch) bs)
    h2 Nothing = retry
    h2 (Just ch) = do
      bs <- readTChan (chanExtendedFd ch)
      send conn (ChannelDataExtended (chanRemoteId ch) 0 bs)

    tryAny :: (Maybe Channel -> STM ()) -> M.Map ChannelId (Maybe Channel) -> STM ()
    tryAny f m = M.foldr orElse retry (M.map f m)

openChannel :: Connection -> ChannelType -> ChannelId -> InitWindowSize -> MaxPacketSize -> STM (Maybe Channel)
openChannel conn t rid ws ps = do
  cs <- readTVar (channels conn)
  case freeLocalId cs of
    Nothing -> pure Nothing
    Just lid -> do
      ch <- Channel t lid rid ws ps <$> newTChan <*> newTChan <*> newTChan
      writeTVar (channels conn) (M.insert lid (Just ch) cs)
      pure (Just ch)
  where
    freeLocalId      :: M.Map ChannelId (Maybe Channel) -> Maybe ChannelId
    freeLocalId       = f (ChannelId 1) . M.keys
    f i []            = Just i
    f (ChannelId i) (ChannelId k:ks)
      | i == maxBound = Nothing
      | i == k        = f (ChannelId $ i+1) ks
      | otherwise     = Just (ChannelId i)

getChannel :: Connection -> ChannelId -> STM Channel
getChannel conn l = do
  cs <- readTVar (channels conn)
  case M.lookup l cs of
    Nothing        -> throwSTM (ChannelDoesNotExist l)
    Just Nothing   -> throwSTM (ChannelIsClosing l)
    Just (Just ch) -> pure ch

closeChannel :: Connection -> ChannelId -> STM (Maybe ChannelId)
closeChannel conn lid = do
  cs <- readTVar (channels conn)
  case M.lookup lid cs of
    Nothing           -> throwSTM (ChannelDoesNotExist lid)
    Just Nothing      -> writeTVar (channels conn) (M.delete lid cs) >> pure Nothing
    Just (Just ch) -> do
      -- TODO: free all resources!
      writeTVar (channels conn) (M.insert lid Nothing cs)
      pure (Just $ chanRemoteId ch)

data ProtocolException
  = ChannelDoesNotExist ChannelId
  | ChannelIsClosing    ChannelId
  deriving (Eq, Ord, Show, Typeable)

instance Exception ProtocolException
