{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ExistentialQuantification #-}
module Network.SSH.Server.Switchboard where

import Control.Concurrent.STM
import Control.Exception
import Data.Map.Strict                 as M

import Network.SSH.Message
import Network.SSH.Address
import Network.SSH.Stream
import Network.SSH.Name

---------------------------------------------------------------------------------------------------
-- SWITCHBOARD
---------------------------------------------------------------------------------------------------

data S = forall stream. DuplexStream stream => S stream

instance DuplexStream S where

instance InputStream S where
    peek (S s) = peek s
    receive (S s) = receive s
    receiveUnsafe (S s) = receiveUnsafe s

instance OutputStream S where
    send (S s) = send s
    sendUnsafe (S s) = sendUnsafe s

newtype Switchboard = Switchboard (TVar (M.Map (UserName, Address) StreamServer))

newtype StreamHandler a = StreamHandler (forall stream. DuplexStream stream => stream -> IO a)

newtype StreamServer = StreamServer (forall a. Address -> StreamHandler a -> IO (Maybe a))

data SwitchboardException
    = ConnectionRefused
    deriving (Eq, Ord, Show)

instance Exception SwitchboardException where

newSwitchboard :: IO Switchboard
newSwitchboard = Switchboard <$> newTVarIO mempty

requestForwarding :: Switchboard -> Name -> Address -> StreamServer -> IO Bool
requestForwarding (Switchboard sb) user addr server = do
    atomically do
        m <- readTVar sb
        case M.lookup (user, addr) m of
            Just {} -> pure False
            Nothing -> do
                writeTVar sb $! M.insert (user, addr) server m
                pure True

cancelForwarding :: Switchboard -> Name -> Address -> IO ()
cancelForwarding (Switchboard sb) user addr = do
    putStrLn $ "CANCEL ------------------------------------------------: " ++ show user ++ show addr
    atomically do
        n <- readTVar sb
        writeTVar sb $! M.delete (user, addr) n

getForwardings :: Switchboard -> IO [(Name, Address)]
getForwardings (Switchboard sb) =
    M.keys <$> readTVarIO sb

connect :: Switchboard -> Name -> Address -> Address -> StreamHandler a -> IO a
connect (Switchboard sb) user destAddr origAddr handler = do
    m <- readTVarIO sb
    case M.lookup (user, destAddr) m of
        Nothing  -> throwIO ConnectionRefused
        Just (StreamServer serve) -> maybe (throwIO ConnectionRefused) pure =<< serve origAddr handler
