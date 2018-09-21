{-# LANGUAGE OverloadedStrings, ExistentialQuantification #-}
module Network.SSH.Server.Transport
    ( TransportState ()
    , withTransportState
    , sendMessage
    , receiveMessage
    , switchEncryptionContext
    , switchDecryptionContext
    ) where

import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TVar
import           Control.Concurrent.STM.TMVar
import           Control.Exception            (throwIO)
import           Control.Monad                (when, void)
import           Control.Monad.STM            (atomically)
import qualified Data.ByteString              as BS
import           Data.Word
import           System.Clock

import           Network.SSH.Constants
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Stream
import           Network.SSH.Server.Transport.Internal
import           Network.SSH.Server.Transport.Encryption

withTransportState :: DuplexStream stream => stream -> (TransportState -> IO a) -> IO a
withTransportState stream runWith = do
    state <- TransportState stream
        <$> newTVarIO 0
        <*> newTVarIO 0
        <*> newTVarIO 0
        <*> newTVarIO 0
        <*> (newTVarIO =<< fromIntegral . sec <$> getTime Monotonic)
        <*> newTVarIO 0
        <*> newTVarIO 0
        <*> newTVarIO noEncryption
        <*> newTVarIO noEncryption
        <*> newTVarIO noDecryption
        <*> newTVarIO noDecryption
    runWith state

switchEncryptionContext :: TransportState -> IO ()
switchEncryptionContext state = atomically $ do
    writeTVar (transportEncryptionContext state) =<< readTVar (transportEncryptionContextNext state)

switchDecryptionContext :: TransportState -> IO ()
switchDecryptionContext state = atomically $ do
    writeTVar (transportDecryptionContext state) =<< readTVar (transportDecryptionContextNext state)

sendMessage :: (Show msg, Encoding msg) => TransportState -> msg -> IO ()
sendMessage state@TransportState { transportStream = stream } msg = do
    let plainText = runPut (put msg) :: BS.ByteString
    encrypt     <- readTVarIO  (transportEncryptionContext state)
    bytesSent   <- readTVarIO  (transportBytesSent state)
    packetsSent <- readTVarIO  (transportPacketsSent state)
    atomically $ modifyTVar' (transportPacketsSent state) (+1)
    let cipherText = encrypt (packetsSent) plainText
    void $ sendAll stream cipherText

receiveMessage :: Encoding msg => TransportState -> IO msg
receiveMessage state@TransportState { transportStream = stream } = do
    packetsReceived <- readTVarIO (transportPacketsReceived state)
    atomically $ modifyTVar' (transportPacketsReceived state) (+1)
    decrypt    <- readTVarIO (transportDecryptionContext state)
    plainText  <- decrypt packetsReceived receiveAll'
    runGet get plainText
    where
        receiveAll' i = do
            bs <- receiveAll stream i
            atomically $ modifyTVar' (transportBytesReceived state) (+ fromIntegral (BS.length bs))
            pure bs
