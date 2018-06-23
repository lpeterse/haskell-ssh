{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent             (forkIO, threadDelay)
import           Control.Concurrent.MVar
import           Control.Exception              (SomeException, bracket, catch,
                                                 finally)
import           Control.Monad                  (forM_, forever)
import           Control.Monad.STM
import qualified Data.ByteArray                 as BA
import qualified Data.ByteString                as BS
import           System.Exit
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S

import           Network.SSH.Constants
import           Network.SSH.Key
import qualified Network.SSH.Server             as Server
import qualified Network.SSH.Server.Config      as Server
import qualified Network.SSH.Server.Types       as Server
import           Network.SSH.Stream

main :: IO ()
main = do
    print version
    file <- BS.readFile "./resources/id_ed25519"
    (privateKey, _):_ <- decodePrivateKeyFile BS.empty file :: IO [(KeyPair, BA.Bytes)]

    c <- Server.newDefaultConfig
    let config = c {
          Server.hostKeys       = pure privateKey
        , Server.onAuthRequest  = \username _ _ -> pure (Just username)
        , Server.onExecRequest  = Just runExec
        , Server.onSend         = \msg-> putStrLn ("sent: " ++ show msg)
        , Server.onReceive      = \msg-> putStrLn ("received: " ++ show msg)
        , Server.onDisconnect   = \dis-> putStrLn ("disconnect: " ++ show dis)
        , Server.maxTimeBeforeRekey = 120
        , Server.maxDataBeforeRekey = 1024 * 10
        }
    bracket open close (accept config)
  where
    open        = S.socket :: IO (S.Socket S.Inet6 S.Stream S.Default)
    close       = S.close
    send    s x = S.sendAll s x S.msgNoSignal >> pure ()
    receive s i = S.receive s i S.msgNoSignal
    accept config s = do
      S.setSocketOption s (S.ReuseAddress True)
      S.setSocketOption s (S.V6Only False)
      S.bind s (S.SocketAddressInet6 S.inet6Any 22 0 0)
      S.listen s 5
      token <- newEmptyMVar
      forever $ do
        forkIO $ bracket
          (S.accept s `finally` putMVar token ())
          (S.close . fst)
          (\(stream,_)-> Server.serve config stream)
        takeMVar token

runExec :: (OutputStream stdout) => identity -> stdin -> stdout -> stderr -> command -> IO ExitCode
runExec identity stdin stdout stderr command = do
    forM_ [1..] $ \i-> do
        send stdout (BS.pack (map (fromIntegral . fromEnum) (show i)) `mappend` "\n" :: BS.ByteString)
        threadDelay 100000
    pure (ExitFailure 23)

instance DuplexStream (S.Socket f S.Stream p) where

instance InputStream  (S.Socket f S.Stream p) where
    receive stream len = BA.convert <$> S.receive stream len S.msgNoSignal

instance OutputStream  (S.Socket f S.Stream p)  where
    send stream bytes = S.send stream (BA.convert bytes) S.msgNoSignal
