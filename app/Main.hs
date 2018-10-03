{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings, LambdaCase #-}
module Main where

import           Control.Concurrent             ( forkIO
                                                , threadDelay
                                                )
import           Control.Concurrent.STM.TVar
import           Control.Exception              ( bracket
                                                , bracketOnError
                                                , finally
                                                )
import           Control.Monad                  ( forM_
                                                , void
                                                , forever
                                                )
import           Control.Concurrent.Async
import           Control.Monad.STM
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import           System.Exit
import qualified System.Socket                 as S
import qualified System.Socket.Family.Inet6    as S
import qualified System.Socket.Protocol.Default
                                               as S
import qualified System.Socket.Type.Stream     as S
import           System.Mem

import           Network.SSH.Constants
import           Network.SSH.Key
import qualified Network.SSH.Server            as Server
import qualified Network.SSH.Server.Config     as Server
import           Network.SSH.Stream
import           Network.SSH.Message
import           Network.SSH.Encoding

main :: IO ()
main = do
    print version
    file                <- BS.readFile "./resources/id_ed25519"
    (privateKey, _) : _ <-
        decodePrivateKeyFile BS.empty file :: IO [(KeyPair, BA.Bytes)]

    c <- Server.newDefaultConfig
    let
        config = c
            { Server.hostKeys           = pure privateKey
            , Server.onAuthRequest      = \username _ _ -> pure (Just username)
            , Server.onExecRequest      = Just runExec
            , Server.onSend = \raw -> case tryParse raw of
                Nothing -> putStrLn ("sent: " ++ show raw)
                Just msg -> putStrLn ("sent: " ++ show (msg :: Message))
            , Server.onReceive = \raw -> case tryParse raw of
                Nothing -> putStrLn ("received: " ++ show raw)
                Just msg -> putStrLn ("received: " ++ show (msg :: Message))
            , Server.onDisconnect       = \dis -> putStrLn
                                              ("disconnect: " ++ show dis)
            , Server.channelMaxQueueSize = 1024
            , Server.maxTimeBeforeRekey = 60
            , Server.maxDataBeforeRekey = 1024 * 1024
            }
    withAsync gc $ \_ ->
        bracket open close (accept config)
  where
    gc = forever $ threadDelay 60000000 >> performGC
    open  = S.socket :: IO (S.Socket S.Inet6 S.Stream S.Default)
    close = S.close
    accept config s = do
        S.setSocketOption s (S.ReuseAddress True)
        S.setSocketOption s (S.V6Only False)
        S.bind s (S.SocketAddressInet6 S.inet6Any 22 0 0)
        S.listen s 5
        forever $ bracketOnError (S.accept s) (S.close . fst) $ \(stream, _) ->
            do
                ownershipTransferred <- newTVarIO False
                let serveStream = do
                        atomically $ writeTVar ownershipTransferred True
                        Server.serve config stream
                void $ forkIO $ serveStream `finally` S.close stream
                atomically $ check =<< readTVar ownershipTransferred

runExec :: Server.Session identity -> BS.ByteString -> IO ExitCode
runExec (Server.Session identity pty env stdin stdout stderr) _command = withAsync receiver $ const $ do
    forM_ [1 ..] $ \i -> do
        void $ sendAll stdout $!
            (BS.pack (map (fromIntegral . fromEnum) (show (i :: Int))) `mappend` "\n" :: BS.ByteString)
        threadDelay 1000
    pure (ExitFailure 23)
    where
        receiver = forever $ do
            bs <- receive stdin 200
            print (BS.length bs)
            threadDelay 1000000

instance DuplexStream (S.Socket f S.Stream p) where

instance InputStream  (S.Socket f S.Stream p) where
    receive stream len = S.receive stream len S.msgNoSignal

instance OutputStream  (S.Socket f S.Stream p)  where
    send stream bytes = S.send stream bytes S.msgNoSignal
