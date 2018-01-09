{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}
module Main where

import           Control.Concurrent           (forkIO, threadDelay)
import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Concurrent.STM.TVar
import           Control.Exception            (AsyncException (..),
                                               SomeException (), bracket, catch,
                                               finally, throwIO)
import           Control.Monad                (forever)
import           Control.Monad.Reader
import           Control.Monad.STM
import           Control.Monad.Trans
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Char8        as BS8
import           Data.Function                (fix)
import           GHC.Conc.Signal
import           System.Console.ANSI
import           System.IO
import           System.Posix.Signals
import qualified Text.PrettyPrint.ANSI.Leijen as P

newtype InputT m a
  = InputT (ReaderT (InputState m) m a)
  deriving (Functor, Applicative, Monad, MonadIO)

data InputState m
  = InputState
  { isGetChar   :: IO Char
  , isGetLine   :: m String
  , isPutStr    :: String -> m ()
  , isFlush     :: m ()
  , isInterrupt :: TMVar Char
  }

main :: IO ()
main = runInputT $ fix $ \proceed->
  getInputLine "foobar $ " >>= \case
    Nothing -> pure ()
    Just ['a'] -> putDocLine (show [1..]) >> putDocLine "HERE" >> proceed
    Just ss -> putDocLine (show ss) >> proceed

runInputT :: InputT IO a -> IO a
runInputT (InputT r) = do
  interrupt <- newEmptyTMVarIO
  withRawMode $
    withHookedSignals $ \waitSignal->
      withAsync (action interrupt) $ \actionT-> fix $ \proceed-> do
        let waitAction = Just <$> waitSTM actionT
        let waitInterrupt = waitSignal >> tryPutTMVar interrupt '\ETX' >>= \case
              True -> pure Nothing
              False -> throwSTM UserInterrupt
        atomically (waitAction `orElse` waitInterrupt) >>= \case
          Just a  -> pure a
          Nothing -> proceed
  where
    withHookedSignals :: (STM () -> IO a) -> IO a
    withHookedSignals action = do
      sig <- newTVarIO False
      bracket
        (flip (installHandler sigINT) Nothing  $ Catch $ atomically $ writeTVar sig True)
        (flip (installHandler sigINT) Nothing) $ const $ action (readTVar sig >>= check >> writeTVar sig False)

    withRawMode :: IO a -> IO a
    withRawMode = bracket
      (hGetBuffering stdin >>= \b-> hSetBuffering stdin NoBuffering >> pure b)
      (hSetBuffering stdin) . const

    action interrupt = runReaderT r InputState {
          isGetChar  = hGetChar stdin
        , isGetLine  = liftIO $ hGetLine stdin
        , isPutStr   = liftIO . hPutStr stdout
        , isFlush    = liftIO $ hFlush stdout
        , isInterrupt = interrupt
        }

getInputLine :: MonadIO m => P.Doc -> InputT m (Maybe String)
getInputLine prompt = do
  putDoc $ show prompt
  c <- InputT $ do
    st <- ask
    liftIO $ withAsync (isGetChar st) $ \t->
      atomically $ waitSTM t `orElse` takeTMVar (isInterrupt st)
  case c of
    '\ETX' -> putDoc "\r\n" >> getInputLine prompt
    '\EOT' -> pure Nothing
    _      -> pure (Just [c])

putDoc :: MonadIO m => String -> InputT m ()
putDoc doc = InputT $ do
  st <- ask
  putChunked st doc
  where
    putChunked st [] = pure ()
    putChunked st xs = liftIO (atomically $ tryTakeTMVar $ isInterrupt st) >>= \case
      Nothing -> do
        let (ys,zs) = splitAt 100 xs
        lift $ isPutStr st ys
        lift $ isFlush st
        putChunked st zs
      Just _ -> do
        lift $ isPutStr st "\r\nInterrupted.\r\n"
        lift $ isFlush st

putDocLine :: MonadIO m => String -> InputT m ()
putDocLine doc = putDoc doc >> putDoc "\r\n"

