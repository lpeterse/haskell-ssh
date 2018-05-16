{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.Connection
  ( serveConnection
   ) where

import           Control.Concurrent
import           Control.Concurrent.Async
import           Control.Concurrent.STM.TChan
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
import           Network.SSH.Message
import           Network.SSH.Server.Config

data Connection
  = Connection
  { sessionId :: SessionId
  , receive   :: STM Message
  , send      :: Message -> STM ()
  , println   :: String -> STM ()
  , exec      :: IO () -> STM ()
  , channels  :: TVar (M.Map ChannelId (Maybe Channel))
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
  , chanPty            :: TVar (Maybe PtySettings)
  , chanProc           :: TVar (Maybe ProcStatus)
  , chanClosed         :: TVar Bool
  }

data ProcStatus
  = ProcRunning
  | ProcExitStatus ExitCode
  | ProcExitSignal BS.ByteString Bool BS.ByteString BS.ByteString
  deriving (Eq, Ord, Show)

data ProtocolException
  = ChannelDoesNotExist ChannelId
  | ChannelIsClosing    ChannelId
  deriving (Eq, Ord, Show, Typeable)

instance Exception ProtocolException

serveConnection :: Config -> SessionId -> STM Message -> (Message -> STM ()) ->  IO ()
serveConnection config sid input output = do
  debug  <- newTChanIO
  chans  <- newTVarIO mempty
  (reqExec, runExec) <- setupExec
  let conn = Connection {
      sessionId = sid
    , receive  = input
    , send     = output
    , println  = writeTChan debug
    , exec     = reqExec
    , channels = chans
    }
  runConnection conn
     `race_` runDebug conn debug
     `race_` runExec
  where
    runDebug :: Connection -> TChan String -> IO ()
    runDebug _ ch = forever $ do
      s <- atomically (readTChan ch)
      putStrLn $ "DEBUG: " ++ s

    runConnection :: Connection -> IO ()
    runConnection conn = do
      (disconnect, isDisconnected) <- newTVarIO False >>= \d-> pure (writeTVar d True, readTVarIO d)
      fix $ \continue-> do
        atomically $ handleInput config conn disconnect
            `orElse` handleChannels conn
        isDisconnected >>= \case
          True  -> pure ()  -- this is the only thread that may return
          False -> continue

    setupExec :: IO (IO () -> STM (), IO ())
    setupExec = do
      ch <- newTChanIO
      let reqExec = writeTChan ch
      let runExec = forever $ do
            action <- atomically (readTChan ch)
            forkIO action
      pure (reqExec, runExec)

handleInput :: Config -> Connection -> STM () -> STM ()
handleInput config conn disconnect = receive conn >>= \case
  MsgDisconnect {} -> disconnect
  MsgIgnore {} -> pure ()
  MsgUnimplemented {} -> pure ()
  MsgServiceRequest (ServiceRequest x) -> do
    println conn (show x)
    send conn (MsgServiceAccept $ ServiceAccept x)
  MsgServiceAccept {} -> fail "FIXME"
  MsgUserAuthFailure {} -> fail "FIXME"
  MsgUserAuthSuccess {} -> fail "FIXME"
  MsgUserAuthBanner {} -> fail "FIXME"
  MsgUserAuthPublicKeyOk {} -> fail "FIXME"
  MsgChannelOpenConfirmation {} -> fail "FIXME"
  MsgChannelOpenFailure {} -> fail "FIXME"
  MsgChannelFailure {} -> fail "FIXME"
  MsgChannelSuccess {} -> fail "FIXME"
  x@(MsgUserAuthRequest (UserAuthRequest user service method)) -> do
    println conn (show x)
    case method of
      AuthNone        -> send conn (MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False)
      AuthHostBased   -> send conn (MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False)
      AuthPassword {} -> send conn (MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False)
      AuthPublicKey algo pk msig -> case msig of
        Nothing  -> send conn (MsgUserAuthPublicKeyOk $ UserAuthPublicKeyOk algo pk)
        Just sig -> if verifyAuthSignature (sessionId conn) user service algo pk sig
          then println conn "AUTHSUCCESS" >> send conn (MsgUserAuthSuccess $ UserAuthSuccess)
          else println conn "AUTHFAILURE" >> send conn (MsgUserAuthFailure $ UserAuthFailure [AuthMethodName "publickey"] False)
  MsgChannelOpen (ChannelOpen t rid ws ps) ->
    openChannel conn t rid ws ps >>= \case
      Nothing  -> send conn $ MsgChannelOpenFailure $ ChannelOpenFailure rid 4 "" ""
      Just ch  -> send conn $ MsgChannelOpenConfirmation $ ChannelOpenConfirmation
        (chanRemoteId ch)
        (chanLocalId ch)
        (chanInitWindowSize ch)
        (chanMaxPacketSize ch)
  MsgChannelData (ChannelData lid bs) -> do
    ch <- getChannel conn lid
    writeTChan (chanReadFd ch) bs
  MsgChannelExtendedData (ChannelExtendedData lid _ bs) -> do
    ch <- getChannel conn lid
    writeTChan (chanExtendedFd ch) bs
  MsgChannelEof (ChannelEof _) ->
    pure ()
  MsgChannelClose (ChannelClose lid) ->
    closeChannel conn lid
  MsgChannelRequest x -> case x of
      ChannelRequestPty lid wantReply ts -> do
        println conn $ show x
        ch <- getChannel conn lid
        writeTVar (chanPty ch) (Just ts)
        when wantReply $
          send conn (MsgChannelSuccess $ ChannelSuccess $ chanRemoteId ch)
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
        ch <- getChannel conn lid
        send conn (MsgChannelFailure $ ChannelFailure $ chanRemoteId ch)

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

openChannel :: Connection -> ChannelType -> ChannelId -> InitWindowSize -> MaxPacketSize -> STM (Maybe Channel)
openChannel conn t rid ws ps = do
  cs <- readTVar (channels conn)
  case freeLocalId cs of
    Nothing -> pure Nothing
    Just lid -> do
      ch <- Channel t lid rid ws ps
        <$> newTChan
        <*> newTChan
        <*> newTChan
        <*> newTVar Nothing
        <*> newTVar Nothing
        <*> newTVar False
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

closeChannel :: Connection -> ChannelId -> STM ()
closeChannel conn lid = do
  cs <- readTVar (channels conn)
  case M.lookup lid cs of
    Nothing        -> throwSTM (ChannelDoesNotExist lid)
    Just Nothing   -> writeTVar (channels conn) $! M.delete lid cs -- finaly closed
    Just (Just ch) -> do
      writeTVar (chanClosed ch) True
      writeTVar (channels conn) $! M.insert lid Nothing cs -- semi-closed
      send conn (MsgChannelClose $ ChannelClose $ chanRemoteId ch)
