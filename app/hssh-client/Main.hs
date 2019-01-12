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
import           Data.List.NonEmpty             ( NonEmpty (..) )
import           Data.Default

import           Network.SSH
import           Network.SSH.Client

main :: IO ()
main = do
    agent <- getAgent
    let config = def
            { transportConfig = def { onReceive = print, onSend = print }
            }
    withClientConnection config (userPassword "lpetersen" "foobar") (HostAddress "localhost" 22)  handleConnection
    where
        getAgent :: IO KeyPair
        getAgent = do
            file                <- BS.readFile "./resources/id_ed25519"
            (privateKey, _) : _ <- decodePrivateKeyFile BS.empty file :: IO [(KeyPair, BA.Bytes)]
            pure privateKey

        handleConnection :: Connection -> IO ()
        handleConnection c = do
            runExec c (Command "ls") $ SessionHandler $ \stdin stdout stderr exit -> do
                receive stdout 4096 >>= print
                atomically exit >>= print
            threadDelay 1000000
            pure ()

