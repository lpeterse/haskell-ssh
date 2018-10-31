{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent             ( forkIO
                                                , threadDelay
                                                )
import           Control.Concurrent.STM.TVar
import           Control.Exception              ( bracket
                                                , bracketOnError
                                                , finally
                                                , handle
                                                , throwIO
                                                )
import           Control.Monad                  ( forM_
                                                , void
                                                , forever
                                                )
import           Control.Monad.STM
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import           System.Exit
import qualified System.Socket                 as S
import qualified System.Socket.Family.Inet6    as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream     as S
import qualified System.Socket.Unsafe          as S
import           Data.Default

import           Network.SSH
import qualified Network.SSH.Server            as Server

main :: IO ()
main = do
    file                <- BS.readFile "./resources/id_ed25519"
    (privateKey, _) : _ <-
        decodePrivateKeyFile BS.empty file :: IO [(KeyPair, BA.Bytes)]
    bracket open close (accept config privateKey)
  where
    config = def
        { Server.transportConfig = def
            {- tOnSend = \raw -> case tryParse raw of
                Nothing -> putStrLn ("sent: " ++ show raw)
                Just msg -> putStrLn ("sent: " ++ show (msg :: Message))
            , tOnReceive = \raw -> case tryParse raw of
                Nothing -> putStrLn ("received: " ++ show raw)
                Just msg -> putStrLn ("received: " ++ show (msg :: Message))
            -}
        , Server.userAuthConfig    = def
            { Server.onAuthRequest = \username _ _ -> pure (Just username)
            }
        , Server.connectionConfig  = def
            { Server.onSessionRequest     = handleSessionRequest
            , Server.onDirectTcpIpRequest = serveHttp
            }
        }
    open  = S.socket :: IO (S.Socket S.Inet6 S.Stream S.Default)
    close = S.close
    accept config agent s = do
        S.setSocketOption s (S.ReuseAddress True)
        S.setSocketOption s (S.V6Only False)
        S.bind s (S.SocketAddressInet6 S.inet6Any 22 0 0)
        S.listen s 5
        forever $ bracketOnError (S.accept s) (S.close . fst) $ \(stream, _) ->
            do
                ownershipTransferred <- newTVarIO False
                let serveStream = do
                        atomically $ writeTVar ownershipTransferred True
                        Server.serve config agent stream >>= print
                void $ forkIO $ (serveStream `finally` S.close stream)
                atomically $ check =<< readTVar ownershipTransferred

serveHttp :: identity -> Server.DirectTcpIpRequest -> IO (Maybe Server.DirectTcpIpHandler)
serveHttp idnt req = pure $ Just $ Server.DirectTcpIpHandler $ \stream-> do
    bs <- receive stream 4096
    sendAll stream "HTTP/1.1 200 OK\n"
    sendAll stream "Content-Type: text/plain\n\n"
    sendAll stream $! BS.pack $ fmap (fromIntegral . fromEnum) $ show req
    sendAll stream "\n\n"
    sendAll stream bs
    print bs

handleSessionRequest :: identity -> Server.SessionRequest -> IO (Maybe Server.SessionHandler)
handleSessionRequest idnt req = pure $ Just $ Server.SessionHandler $ \env pty command stdin stdout stderr -> do
    forM_ [1 ..  ] $ \i -> do
        sendAll stdout abc
        threadDelay 1000
    pure (ExitFailure 23)

abc :: BS.ByteString
abc = "ABC"

instance DuplexStream (S.Socket f S.Stream p) where

instance OutputStream  (S.Socket f S.Stream p) where
    send stream bytes = S.send stream bytes S.msgNoSignal
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
