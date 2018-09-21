{-# LANGUAGE ExistentialQuantification #-}
module Network.SSH.Server.Transport
    ( TransportState()
    , withTransportState
    , sendMessage
    , receiveMessage
    , switchEncryptionContext
    , switchDecryptionContext
    )
where

import           Control.Concurrent.STM.TVar
import           Control.Monad.STM              ( atomically )
import           Control.Monad                  ( void )
import qualified Data.ByteString               as BS
import           System.Clock

import           Network.SSH.Encoding
import           Network.SSH.Stream
import           Network.SSH.Server.Transport.Internal

withTransportState
    :: DuplexStream stream => stream -> (TransportState -> IO a) -> IO a
withTransportState stream runWith = do
    state <-
        TransportState stream
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
    writeTVar (transportEncryptionContext state)
        =<< readTVar (transportEncryptionContextNext state)

switchDecryptionContext :: TransportState -> IO ()
switchDecryptionContext state = atomically $ do
    writeTVar (transportDecryptionContext state)
        =<< readTVar (transportDecryptionContextNext state)

sendMessage :: (Show msg, Encoding msg) => TransportState -> msg -> IO ()
sendMessage state@TransportState { transportStream = stream } msg = do
    let plainText = runPut (put msg) :: BS.ByteString
    encrypt     <- readTVarIO (transportEncryptionContext state)
    packetsSent <- readTVarIO (transportPacketsSent state)
    cipherText  <- encrypt packetsSent plainText
    atomically $ modifyTVar' (transportBytesSent state) (+ fromIntegral (BS.length cipherText))
    atomically $ modifyTVar' (transportPacketsSent state) (+ 1)
    void $ sendAll stream cipherText

receiveMessage :: Encoding msg => TransportState -> IO msg
receiveMessage state@TransportState { transportStream = stream } = do
    packetsReceived <- readTVarIO (transportPacketsReceived state)
    atomically $ modifyTVar' (transportPacketsReceived state) (+ 1)
    decrypt   <- readTVarIO (transportDecryptionContext state)
    plainText <- decrypt packetsReceived receiveAll'
    runGet get plainText
  where
    receiveAll' i = do
        bs <- receiveAll stream i
        atomically $ modifyTVar' (transportBytesReceived state)
                                 (+ fromIntegral (BS.length bs))
        pure bs
