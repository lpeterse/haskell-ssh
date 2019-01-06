{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent             ( threadDelay )
import           Control.Exception              ( bracket
                                                , bracketOnError
                                                , handle
                                                , throwIO
                                                )
import           Control.Monad.STM
import qualified Data.ByteArray                 as BA
import qualified Data.ByteString                as BS
import           Data.Default
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S
import qualified System.Socket.Unsafe           as S

import           Network.SSH
import           Network.SSH.Client

main :: IO ()
main = do
    ai <- getAddressInfo
    bracket open close $ \stream -> do
        let config = def
                { transportConfig = def { onReceive = print }
                , userAuthConfig  = def { getAgent  = Just <$> getAgent, userName = "lpetersen" }
                }
        S.connect stream (S.socketAddress ai)
        handle config stream
    where
        open  = S.socket :: IO (S.Socket S.Inet6 S.Stream S.Default)
        close = S.close

        getAddressInfo :: IO (S.AddressInfo S.Inet6 S.Stream S.Default)
        getAddressInfo =
            head <$> S.getAddressInfo
                (Just "localhost") (Just "22")
                (S.aiAddressConfig <> S.aiV4Mapped <> S.aiAll)

        getAgent :: IO KeyPair
        getAgent = do
            file                <- BS.readFile "./resources/id_ed25519"
            (privateKey, _) : _ <- decodePrivateKeyFile BS.empty file :: IO [(KeyPair, BA.Bytes)]
            pure privateKey

        handle :: (DuplexStream stream) => Config -> stream -> IO ()
        handle config stream = withClientConnection config stream $ \c -> do
            print "connection established"
            runExec c (Command "ls") $ SessionHandler $ \stdin stdout stderr exit -> do
                receive stdout 4096 >>= print
                atomically exit >>= print
            threadDelay 1000000
            pure ()

-------------------------------------------------------------------------------
-- Instances for use with the socket library
-------------------------------------------------------------------------------

instance DuplexStream (S.Socket f S.Stream p) where

instance OutputStream  (S.Socket f S.Stream p) where
    send stream bytes =
        handle f $ S.send stream bytes S.msgNoSignal
        where
            f e
                | e == S.ePipe = pure 0
                | otherwise    = throwIO e
    sendUnsafe stream (BA.MemView ptr n) = fromIntegral <$>
        handle f (S.unsafeSend stream ptr (fromIntegral n) S.msgNoSignal)
        where
            f e
                | e == S.ePipe = pure 0
                | otherwise    = throwIO e

instance InputStream  (S.Socket f S.Stream p) where
    peek stream len = S.receive stream len (S.msgNoSignal <> S.msgPeek)
    receive stream len = S.receive stream len S.msgNoSignal
    receiveUnsafe stream (BA.MemView ptr n) = fromIntegral <$>
        S.unsafeReceive stream ptr (fromIntegral n) S.msgNoSignal
