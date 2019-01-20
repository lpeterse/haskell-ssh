{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent             ( threadDelay )
import           Control.Concurrent.Async
import           Control.Exception              ( bracket
                                                , bracketOnError
                                                , handle
                                                , throwIO
                                                )
import           Control.Monad                  ( forever
                                                , void
                                                )
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import           Data.Default
import           System.Exit

import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S
import qualified System.Socket.Unsafe           as S

import           Network.SSH
import qualified Network.SSH.Server            as Server

main :: IO ()
main = do
    file                <- BS.readFile "./resources/id_ed25519"
    (privateKey, _) : _ <- decodePrivateKeyFile BS.empty file :: IO [(KeyPair, BA.Bytes)]
    sb <- Server.newSwitchboard
    _ <- async (foo sb)
    Server.runServer (config sb) privateKey
  where
    foo sb = forever do
        threadDelay 10000000
        print "NOW"
        a <- async $ Server.connect sb "FIXME" (Address "localhost" 22) (Address "127.0.0.1" 1234) $ Server.StreamHandler $ \s -> do
            threadDelay 10000
            pure ()
        waitCatch a >>= print 
        
    config sb = def
        { Server.socketConfig             = def { Server.socketBindAddresses = pure (Address "*" 22)}
        , Server.transportConfig          = def {
                onSend = \x -> putStrLn ("CLIENT: " ++ show x),
                onReceive = \x -> putStrLn ("SERVER: " ++ show x)
            }
        , Server.userAuthConfig           = def
            { Server.onAuthRequest        = \_ addr username _ _ -> pure (Just username)
            }
        , Server.connectionConfig         = def
            { Server.onSessionRequest     = handleSessionRequest
            , Server.onDirectTcpIpRequest = handleDirectTcpIpRequest
            , Server.switchboard          = Just sb
            }
        , Server.onConnect                = \ha -> do
            print ha
            pure (Just ())
        , Server.onDisconnect             = \ha st user d -> do
            print ha
            print st
            print user
            print d
        }

handleDirectTcpIpRequest :: state -> user -> SourceAddress -> DestinationAddress -> IO (Maybe Server.DirectTcpIpHandler)
handleDirectTcpIpRequest state user src dst = pure $ Just $ Server.DirectTcpIpHandler $ \stream-> do
    bs <- receive stream 4096
    sendAll stream "HTTP/1.1 200 OK\n"
    sendAll stream "Content-Type: text/plain\n\n"
    sendAll stream "Hello world!\n"
    sendAll stream "\n\n"
    sendAll stream bs
    print bs

handleSessionRequest :: state -> user -> IO (Maybe Server.SessionHandler)
handleSessionRequest state user = pure $ Just $ Server.SessionHandler $ \_ _ _ _ stdout _ -> do
    sendAll stdout "Hello world!\n"
    pure ExitSuccess
