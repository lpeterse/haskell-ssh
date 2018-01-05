{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent                          (forkIO,
                                                              threadDelay)
import           Control.Concurrent.MVar
import           Control.Exception                           (bracket, finally)
import           Control.Monad                               (forever)
import           Control.Monad.STM
import           Control.Monad.Trans
import qualified Data.ByteString                             as BS
import qualified Data.ByteString.Char8                       as BS8
import           Data.Char
import qualified System.Console.Haskeline                    as H
import qualified System.Console.Haskeline.Backend.PseudoTerm as H
import           System.Exit
import qualified System.Socket                               as S
import qualified System.Socket.Family.Inet6                  as S
import qualified System.Socket.Protocol.Default              as S
import qualified System.Socket.Type.Stream                   as S

import           Network.SSH
import           Network.SSH.Config
import           Network.SSH.Constants

main :: IO ()
main = bracket open close accept
  where
    open        = S.socket :: IO (S.Socket S.Inet6 S.Stream S.Default)
    close       = S.close
    send    s x = S.sendAll s x S.msgNoSignal >> pure ()
    receive s i = S.receive s i S.msgNoSignal
    accept s = do
      S.setSocketOption s (S.ReuseAddress True)
      S.setSocketOption s (S.V6Only False)
      S.bind s (S.SocketAddressInet6 S.inet6Any 22 0 0)
      S.listen s 5
      token <- newEmptyMVar
      forever $ do
        forkIO $ bracket
          (S.accept s `finally` putMVar token ())
          (S.close . fst)
          (\(x,_)-> serve config (send x) (receive x))
        takeMVar token

    config = ServerConfig {
        scHostKey  = exampleHostKey
      , scRunShell = Just runShell
      }

runShell :: STM BS.ByteString -> (BS.ByteString -> STM ()) -> (BS.ByteString -> STM ()) -> IO ExitCode
runShell readStdin writeStdout _writeStderr = do
  let rd = BS8.unpack <$> atomically readStdin
  let wt = atomically . writeStdout . BS8.pack
  H.runInputTBehavior (H.usePseudoTerm rd wt) H.defaultSettings cli
  where
    cli = do
      H.outputStrLn "PSEUDO SHELL RUNNING!"
      H.getInputLine "fnord $ " >>= \case
        Nothing -> pure (ExitFailure 2)
        Just s  -> do
          H.outputStrLn (fmap toUpper s)
          pure ExitSuccess
