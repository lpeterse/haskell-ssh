module Main where

import           Control.Concurrent             (forkIO, threadDelay)
import           Control.Concurrent.MVar
import           Control.Exception              (SomeException, bracket, catch,
                                                 finally)
import           Control.Monad                  (forever)
import           Control.Monad.STM
import qualified Data.ByteString                as BS
import qualified Data.Text                      as T
import qualified Data.Text.Encoding             as T
import           System.Exit
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S

import           Network.SSH
import           Network.SSH.Config
import           Network.SSH.Constants
import           Network.SSH.Message

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

runShell :: Maybe PtySettings -> STM BS.ByteString -> (BS.ByteString -> STM ()) -> (BS.ByteString -> STM ()) -> IO ExitCode
runShell mPty readStdin writeStdout writeStderr =
  forever $ threadDelay 1000000
