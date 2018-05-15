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

import           Control.Monad.Replique
import           Control.Monad.Terminal

import           Network.SSH
import qualified Network.SSH.Server             as Server

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
          (\(x,_)-> withConnection x)
        takeMVar token

    config = Server.Config {
        Server.hostKey  = exampleHostKey
      , Server.runWithShell = Just runShell
      }

withConnection :: S.Socket S.Inet6 S.Stream S.Default -> IO ()
withConnection socket = do
    config <- Server.newDefaultConfig { onShellRequest = Just serveShellRequest }
    serve socket config

serveShellRequest :: Terminal -> IO ExitCode
serveShellRequest term = do
    runTerminalT $ runRepliqueT repl 0
    pure (ExitFailure 1)

repl :: (MonadTerminal m, MonadColorPrinter m, MonadMask m, MonadIO m) => RepliqueT Int m ()
repl = readLine prompt >>= \case
    ""           -> pure ()
    "quit"       -> quit
    "fail"       -> fail "abcdef"
    "failIO"     -> liftIO $ E.throwIO $ E.userError "Exception thrown in IO."
    "throwM"     -> throwM $ E.userError "Exception thrown in RepliqueT."
    "liftThrowM" -> lift $ throwM $ E.userError "Exception thrown within the monad transformer."
    "load"       -> load >>= pprint
    "inc"        -> load >>= store . succ
    "dec"        -> load >>= store . pred
    "loop"       -> forM_ [1..100000] $ \i-> store i >> putString (' ':show i)
    "finally"    -> fail "I am failing, I am failing.." `finally` putStringLn "FINALLY"
    "clear"      -> clearScreen
    "screen"     -> getScreenSize >>= \p-> putStringLn (show p) >> flush
    "cursor"     -> getCursorPosition >>= \p-> putStringLn (show p) >> flush
    "home"       -> setCursorPosition (0,0)
    "progress"   -> void $ runWithProgressBar $ \update-> (`finally` threadDelay 3000000) $ forM_ [1..1000] $ \i-> do
                      threadDelay 10000
                      update $ fromIntegral i / 1000
    "colors"     -> undefined
    "normal"     -> useAlternateScreenBuffer False
    "alternate"  -> useAlternateScreenBuffer True
    line         -> putStringLn (show (line :: String))
