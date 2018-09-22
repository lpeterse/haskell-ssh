{-# LANGUAGE ExistentialQuantification #-}
module Network.SSH.Server.Transport.Internal where

import           Control.Concurrent.STM.TVar
import qualified Data.ByteString               as BS
import           Data.Word

import           Network.SSH.Stream

data Transport
    = forall stream. (DuplexStream stream) => Transport
    {   transportStream                   :: stream
    ,   transportPacketsReceived          :: TVar Word64
    ,   transportBytesReceived            :: TVar Word64
    ,   transportPacketsSent              :: TVar Word64
    ,   transportBytesSent                :: TVar Word64
    ,   transportLastRekeyingTime         :: TVar Word64
    ,   transportLastRekeyingDataSent     :: TVar Word64
    ,   transportLastRekeyingDataReceived :: TVar Word64
    ,   transportEncryptionContext        :: TVar EncryptionContext
    ,   transportEncryptionContextNext    :: TVar EncryptionContext
    ,   transportDecryptionContext        :: TVar DecryptionContext
    ,   transportDecryptionContextNext    :: TVar DecryptionContext
    }

type DecryptionContext  = Word64 -> (Int -> IO BS.ByteString) -> IO BS.ByteString
type EncryptionContext  = Word64 -> BS.ByteString -> IO BS.ByteString
