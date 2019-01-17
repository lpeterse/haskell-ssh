{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent             ( threadDelay )
import           Control.Concurrent.Async
import           Control.Exception              ( bracket
                                                , bracketOnError
                                                , catch
                                                , handle
                                                , throwIO
                                                )
import           Control.Monad.STM
import qualified Data.ByteArray                 as BA
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Char8          as BS8
import           Data.List.NonEmpty             ( NonEmpty (..) )
import           Data.Default

import           Network.SSH
import           Network.SSH.Client

main :: IO ()
main = do
    runClient config def (HostAddress "localhost" 22) $ \c ->
        runExec c (Command "ls") $ SessionHandler $ \stdin stdout stderr exit -> do
            receive stdout 4096 >>= print
            atomically exit >>= print
    where
        config = def
            { transportConfig = def {
                onSend = \x -> putStrLn ("CLIENT: " ++ show x),
                onReceive = \x -> putStrLn ("SERVER: " ++ show x)
              }
            , hostKeyVerifier = \_ _ -> pure VerificationPassed
            }
