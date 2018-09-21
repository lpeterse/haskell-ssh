{-# LANGUAGE ExistentialQuantification, OverloadedStrings #-}
module Network.SSH.Server.Transport.Internal where

import           Control.Concurrent.STM.TVar
import qualified Data.ByteString               as BS
import           Data.Word
import           Control.Monad                  ( when )
import           Control.Exception              ( throwIO )

import           Network.SSH.Stream
import           Network.SSH.Encoding
import           Network.SSH.Message
import           Network.SSH.Constants

data TransportState
    = forall stream. (DuplexStream stream) => TransportState
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

noEncryption :: EncryptionContext
noEncryption _ plainText = pure $ runPut (putPacked plainText)

noDecryption :: DecryptionContext
noDecryption _ getCipherText = do
    paclen <- runGet getWord32 =<< getCipherText 4
    when (paclen > maxPacketLength) $ throwIO $ Disconnect
        DisconnectProtocolError
        "max packet length exceeded"
        ""
    BS.drop 1 <$> getCipherText (fromIntegral paclen)
