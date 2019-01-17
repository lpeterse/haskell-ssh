{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ExistentialQuantification #-}
module Network.SSH.Server.Switchboard where

import Control.Concurrent.STM
import Control.Concurrent.STM.TVar
import Control.Exception
import Data.Map.Strict                 as M

import Network.SSH.Message
import Network.SSH.HostAddress
import Network.SSH.Stream

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

data Switchboard
    = Switchboard
    { crFoo :: TVar (M.Map (UserName, HostAddress) (HostAddress -> IO (Maybe S)))
    }

newtype StreamHandler a = StreamHandler (forall stream. DuplexStream stream => stream -> IO a)

data SwitchboardException
    = ConnectionRefused
    deriving (Eq, Ord, Show)

instance Exception SwitchboardException where

newSwitchboard :: IO Switchboard
newSwitchboard = Switchboard <$> newTVarIO mempty

requestForwarding :: DuplexStream stream =>
    Switchboard -> UserName -> HostAddress -> (HostAddress -> IO (Maybe stream)) -> IO Bool
requestForwarding sb user addr getStream = do
    atomically do
        m <- readTVar (crFoo sb)
        case M.lookup (user, addr) m of
            Just {} -> pure False
            Nothing -> do
                writeTVar (crFoo sb) $! M.insert (user, addr) (\oa -> (S <$>) <$> getStream oa) m
                pure True

cancelForwarding :: Switchboard -> UserName -> HostAddress -> IO ()
cancelForwarding sb user addr = atomically do
    n <- readTVar (crFoo sb)
    writeTVar (crFoo sb) $! M.delete (user, addr) n

connect :: Switchboard -> UserName -> HostAddress -> HostAddress -> StreamHandler a -> IO a
connect sb user destAddr origAddr (StreamHandler run) = do
    m <- readTVarIO (crFoo sb)
    case M.lookup (user, destAddr) m of
        Nothing -> throwIO ConnectionRefused
        Just getStream -> maybe (throwIO ConnectionRefused) (\(S s)-> run s) =<< getStream origAddr
