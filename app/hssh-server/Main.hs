{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent             ( forkFinally
                                                )
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
    bracket open close (accept config privateKey)
  where
    config = def
        { Server.transportConfig          = def
        , Server.userAuthConfig           = def
            { Server.onAuthRequest        = \username _ _ -> pure (Just username)
            }
        , Server.connectionConfig         = def
            { Server.onSessionRequest     = handleSessionRequest
            , Server.onDirectTcpIpRequest = handleDirectTcpIpRequest
            }
        }
    open  = S.socket :: IO (S.Socket S.Inet6 S.Stream S.Default)
    close = S.close
    accept config agent s = do
        S.setSocketOption s (S.ReuseAddress True)
        S.setSocketOption s (S.V6Only False)
        S.bind s (S.SocketAddressInet6 S.inet6Any 22 0 0)
        S.listen s 5
        forever $ bracketOnError (S.accept s) (S.close . fst) $ \(stream, peer) -> do
            putStrLn $ "Connection from " ++ show peer
            void $ forkFinally
                (Server.serve config agent stream >>= print)
                (const $ S.close stream)

handleDirectTcpIpRequest :: identity -> Server.DirectTcpIpRequest -> IO (Maybe Server.DirectTcpIpHandler)
handleDirectTcpIpRequest idnt req = pure $ Just $ Server.DirectTcpIpHandler $ \stream-> do
    bs <- receive stream 4096
    sendAll stream "HTTP/1.1 200 OK\n"
    sendAll stream "Content-Type: text/plain\n\n"
    sendAll stream $! BS.pack $ fmap (fromIntegral . fromEnum) $ show req
    sendAll stream "\n\n"
    sendAll stream bs
    print bs

handleSessionRequest :: identity -> Server.SessionRequest -> IO (Maybe Server.SessionHandler)
handleSessionRequest idnt req = pure $ Just $ Server.SessionHandler $ \_ _ _ _ stdout _ -> do
    sendAll stdout "Hello world!\n"
    pure ExitSuccess
