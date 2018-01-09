{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}
module Main where

import           Control.Concurrent           (forkIO, threadDelay)
import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
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
import           System.Console.ANSI
import           System.IO
import qualified Text.PrettyPrint.ANSI.Leijen as P

newtype InputT m a
  = InputT (ReaderT (InputState m) m a)
  deriving (Functor, Applicative, Monad)

data InputState m
  = InputState
  { isGetChar   :: m Char
  , isGetLine   :: m String
  , isPutStr    :: String -> m ()
  , isFlush     :: m ()
  , isInterrupt :: TMVar Char
  }

main :: IO ()
main = runInputT $ forever $ do
  getInputLine "foobar $ " >>= \case
    Nothing -> putDocLine "Nothing"
    Just ss -> putDocLine $ show [1..]

runInputT :: InputT IO a -> IO a
runInputT (InputT r) = withRawMode $ do
  interrupt <- newEmptyTMVarIO
  withAsync (action interrupt) $ \actionT-> fix $ \proceed-> do
    x <- (Right <$> wait actionT) `catch` \case
      UserInterrupt -> atomically (Left <$> tryPutTMVar interrupt '\ETX')
      e             -> throwIO e
    case x of
      Right a    -> pure a
      Left True  -> proceed
      Left False -> throwIO UserInterrupt
  where
    withRawMode :: IO a -> IO a
    withRawMode = bracket
      (hGetBuffering stdin >>= \b-> hSetBuffering stdin NoBuffering >> pure b)
      (hSetBuffering stdin) . const

    action interrupt = runReaderT r InputState {
          isGetChar  = liftIO $ hGetChar stdin
        , isGetLine  = liftIO $ hGetLine stdin
        , isPutStr   = liftIO . hPutStr stdout
        , isFlush    = liftIO $ hFlush stdout
        , isInterrupt = interrupt
        }

getInputLine :: MonadIO m => P.Doc -> InputT m (Maybe String)
getInputLine prompt = do
  putDoc $ show prompt
  InputT $ do
    st <- ask
    lift $ Just . pure <$> isGetChar st

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

