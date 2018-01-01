{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Connection where

import           Control.Concurrent
import           Control.Concurrent.Async
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TVar
import           Control.Exception
import           Control.Monad                (forever)
import           Control.Monad.STM
import qualified Data.ByteString              as BS
import           Data.Function                (fix)
import qualified Data.Map.Strict              as M
import           Data.Typeable

import           Network.SSH
import           Network.SSH.Message

data Connection
  = Connection
  { sessionId :: SessionId
  , receive   :: STM Message
  , send      :: Message -> STM ()
  , println   :: String -> STM ()
  , exec      :: STM BS.ByteString -> (BS.ByteString -> STM ()) -> (BS.ByteString -> STM ()) -> STM () -> STM ()
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
  , chanClose          :: STM ()
  , chanWaitClosed     :: STM ()
  }

data ProtocolException
  = ChannelDoesNotExist ChannelId
  | ChannelIsClosing    ChannelId
  deriving (Eq, Ord, Show, Typeable)

instance Exception ProtocolException

serve :: SessionId -> STM Message -> (Message -> STM ()) ->  IO ()
serve sid input output = do
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
        atomically $ handleInput conn disconnect
          `orElse` handleChannelFds conn
        isDisconnected >>= \case
          True  -> pure ()  -- this is the only thread that may return
          False -> continue

    setupExec :: IO (STM BS.ByteString
              -> (BS.ByteString -> STM ())
              -> (BS.ByteString -> STM ())
              -> STM a0
              -> STM (), IO ())
    setupExec = do
      ch <- newTChanIO
      let reqExec rin wout werr wait' =
            writeTChan ch (rin, wout, werr, wait')
      let runExec = forever $ do
            (rin,wout,werr,wait') <- atomically (readTChan ch)
            forkIO $ atomically wait' `race_` runShell rin wout werr
      pure (reqExec, runExec)

runShell :: STM BS.ByteString -> (BS.ByteString -> STM ()) -> (BS.ByteString -> STM ()) -> IO ()
runShell readStdin writeStdout _writeStderr = forever $ do
  bs <- atomically $ readStdin `orElse` pure "X"
  threadDelay 1000000
  atomically $ writeStdout bs

handleInput :: Connection -> STM () -> STM ()
handleInput conn disconnect = receive conn >>= \case
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
  MsgChannelRequestFailure {} -> fail "FIXME"
  MsgChannelRequestSuccess {} -> fail "FIXME"
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
      Nothing  -> send conn $ MsgChannelOpenFailure $ ChannelOpenFailure rid (ChannelOpenFailureReason 4 "" "")
      Just ch  -> send conn $ MsgChannelOpenConfirmation $ ChannelOpenConfirmation
        (chanRemoteId ch)
        (chanLocalId ch)
        (chanInitWindowSize ch)
        (chanMaxPacketSize ch)
  MsgChannelData (ChannelData lid bs) -> do
    ch <- getChannel conn lid
    writeTChan (chanWriteFd ch) bs
  MsgChannelDataExtended (ChannelDataExtended lid _ bs) -> do
    ch <- getChannel conn lid
    writeTChan (chanExtendedFd ch) bs
  MsgChannelEof (ChannelEof _) ->
    pure ()
  MsgChannelClose (ChannelClose lid) ->
    closeChannel conn lid >>= \case
      Nothing  -> pure () -- channel finally closed
      Just rid -> send conn (MsgChannelClose $ ChannelClose rid) -- channel semi-closed
  MsgChannelRequest x -> case x of
      ChannelRequestPty lid _ _ _ _ _ _ _ -> do
        ch <- getChannel conn lid
        send conn (MsgChannelRequestSuccess $ ChannelRequestSuccess $ chanRemoteId ch)
      ChannelRequestShell lid wantReply -> do
        ch <- getChannel conn lid
        exec conn
          (readTChan  $ chanReadFd ch)
          (writeTChan $ chanWriteFd ch)
          (writeTChan $ chanExtendedFd ch)
          (chanWaitClosed ch)
        send conn (MsgChannelRequestSuccess $ ChannelRequestSuccess $ chanRemoteId ch)
      ChannelRequestOther lid _ -> do
        ch <- getChannel conn lid
        send conn (MsgChannelRequestFailure $ ChannelRequestFailure $ chanRemoteId ch)

handleChannelFds :: Connection -> STM ()
handleChannelFds conn =
  tryAny (\ch-> h1 ch `orElse` h2 ch) =<< readTVar (channels conn)
  where
    h1 Nothing = retry
    h1 (Just ch) = do
      bs <- readTChan (chanWriteFd ch)
      send conn (MsgChannelData $ ChannelData (chanRemoteId ch) bs)
    h2 Nothing = retry
    h2 (Just ch) = do
      bs <- readTChan (chanExtendedFd ch)
      send conn (MsgChannelDataExtended $ ChannelDataExtended (chanRemoteId ch) 0 bs)

    tryAny :: (Maybe Channel -> STM ()) -> M.Map ChannelId (Maybe Channel) -> STM ()
    tryAny f m = M.foldr orElse retry (M.map f m)

openChannel :: Connection -> ChannelType -> ChannelId -> InitWindowSize -> MaxPacketSize -> STM (Maybe Channel)
openChannel conn t rid ws ps = do
  cs <- readTVar (channels conn)
  case freeLocalId cs of
    Nothing -> pure Nothing
    Just lid -> do
      isClosed <- newTVar False
      ch <- Channel t lid rid ws ps
        <$> newTChan
        <*> newTChan
        <*> newTChan
        <*> pure (writeTVar isClosed True)
        <*> pure (readTVar isClosed >>= \x-> if x then pure () else retry)
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
