{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent             (forkIO, threadDelay)
import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Exception              (SomeException (), bracket,
                                                 catch, finally)
import           Control.Monad                  (forever)
import           Control.Monad.STM
import           Control.Monad.Trans
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Char8          as BS8
import           Data.Char
import           Data.IORef
import           Data.Maybe
import qualified Data.Text                      as T
import qualified Data.Text.Encoding             as T
import           GHC.IO.Buffer
import           GHC.IO.BufferedIO
import           GHC.IO.Device
import           GHC.IO.Handle.Types
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
{-runShell mPty readStdin writeStdout writeStderr = do
  let env    = fromMaybe "xterm"  $  T.unpack . T.decodeUtf8 . ptyEnv <$> mPty
  let layout = H.Layout (fromMaybe 80 $ fromIntegral . ptyWidthCols <$> mPty) (fromMaybe 80 $ fromIntegral . ptyHeightRows <$> mPty)
  H.runInputTBehavior (H.usePseudoTerm env layout readStdin writeStdout) H.defaultSettings cli
    `catch` \e-> do
      atomically $ writeStderr $ T.encodeUtf8 $ T.pack $ "\r\n" ++ show (e :: SomeException) ++ "\r\n"
      pure (ExitFailure 1)
  where
    cli = do
      H.outputStrLn "PSEUDO SHELL RUNNING!"
      forever $ do
        H.getInputLine "fnord $ " >>= \case
          Nothing -> H.outputStr ['Y']
          Just c  -> H.outputStr c
-}
runShell mPty readStdin writeStdout writeStderr =
  forever $ do
    threadDelay 1000000
{-
readHandle :: TChan BS.ByteString -> IO Handle
readHandle x = do
  let dev = StreamDevice x
  bb <- newIORef =<< newByteBuffer 4096 ReadBuffer
  cb <- newIORef =<< newCharBuffer 4096 ReadBuffer
  sp <- newIORef BufferListNil
  let h' = Handle__ {
    haDevice      = dev,
    haType        = ReadHandle,
    haByteBuffer  = bb,
    haBufferMode  = NoBuffering,
    haLastDecode  = undefined, -- we're not decoding
    haCharBuffer  = cb,
    haBuffers     = sb,
    haEncoder     = Nothing,
    haDecoder     = Nothing,
    haCodec       = Nothing,
    haInputNL     = CRLF,
    haOutputNL    = CRLF,
    haOtherSide   = Nothing
  }
  undefined

newtype StreamDevice = StreamDevice (TChan BS.ByteString)

instance IODevice StreamDevice where
  ready (StreamDevice ch) isWrite timeout
    | isWrite = pure True
    | otherwise = atomically $ not <$> isEmptyTChan ch
  close = undefined
  isTerminal = False
  isSeekable = False
  devType = pure Stream

instance BufferedIO StreamDevice where
  newBuffer dev = newByteBuffer 4096
  fillReadBuffer = undefined
  fillReadBuffer0 = undefined
  emptyWriteBuffer = undefined
  flushWriteBuffer = undefined
  flushWriteBuffer0 = undefined
-}
