hssh - Haskell SSH [![Hackage](https://img.shields.io/github/release/lpeterse/haskell-ssh.svg)](https://github.com/lpeterse/haskell-ssh/releases) [![Travis](https://img.shields.io/travis/lpeterse/haskell-ssh.svg)](https://travis-ci.org/lpeterse/haskell-ssh)
=======================

## Introduction

This library is a pure-Haskell implementation of the SSH2 protocol.

## Features

By now, only the server part has been implemented. It can be used
to embed SSH servers into Haskell applications.

Transport layer:

- `ssh-ed25519` host keys.
- Key exchange using the `curve25519-sha256@libssh.org` algorithm.
- Encryption using the  `chacha20-poly1305@openssh.com` algorithm.
- Rekeying fully supported and compatible with OpenSSH.

Authentication layer:

- User authentication with `ssh-ed25519` public keys.

Connection layer:

- Connection multiplexing.
- Serving session requests (shell and exec) with user-supplied handlers.
- Serving direct-tcpip requests with user-supplied handlers.

Misc:

- SSH private key file import (not encrypted yet).

## Dependencies

- async
- base
- bytestring
- cereal
- containers
- cryptonite
- memory
- stm
- data-default

## Example server application

```hs
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

-------------------------------------------------------------------------------
-- Instances for use with the socket library
-------------------------------------------------------------------------------

instance DuplexStream (S.Socket f S.Stream p) where

instance OutputStream  (S.Socket f S.Stream p) where
    send stream bytes =
        handle f $ S.send stream bytes S.msgNoSignal
        where
            f e
                | e == S.ePipe = pure 0
                | otherwise    = throwIO e
    sendUnsafe stream (BA.MemView ptr n) = fromIntegral <$>
        handle f (S.unsafeSend stream ptr (fromIntegral n) S.msgNoSignal)
        where
            f e
                | e == S.ePipe = pure 0
                | otherwise    = throwIO e

instance InputStream  (S.Socket f S.Stream p) where
    peek stream len = S.receive stream len (S.msgNoSignal <> S.msgPeek)
    receive stream len = S.receive stream len S.msgNoSignal
    receiveUnsafe stream (BA.MemView ptr n) = fromIntegral <$>
        S.unsafeReceive stream ptr (fromIntegral n) S.msgNoSignal
```