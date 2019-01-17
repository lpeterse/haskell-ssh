{-# LANGUAGE FlexibleContexts #-}
module Network.SSH.Server.Server where

import           Control.Applicative
import           Control.Concurrent.STM
import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad
import qualified Data.ByteString.Char8          as BS8
import           Data.Default
import           Data.List                      (nub)
import           Data.List.NonEmpty             (NonEmpty (..), toList)
import qualified Data.Set                       as Set
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S

import           Network.SSH.Agent
import           Network.SSH.Name
import           Network.SSH.Server.Connection
import           Network.SSH.Server.UserAuth
import           Network.SSH.Stream
import           Network.SSH.Transport
import           Network.SSH.HostAddress
import           Network.SSH.Exception

-- | The server configuration.
--
--   * The type variable `state` represents the return type of
--     the user authentication process. It may be chosen freely.
--     The state object will be supplied to all subsequent
--     service handler functions associated with the connection.
data ServerConfig state user
    = ServerConfig
        { socketConfig     :: SocketConfig
        , transportConfig  :: TransportConfig
        , userAuthConfig   :: UserAuthConfig state user
        , connectionConfig :: ConnectionConfig user
        , onConnect        :: HostAddress -> IO (Maybe state)
        , onDisconnect     :: HostAddress -> Maybe state -> Maybe user -> Disconnect -> IO ()
        }

-- | The listening socket configuration.
data SocketConfig
    = SocketConfig
        { socketBindAddresses :: NonEmpty HostAddress
          -- ^ The addresses to listen on (default "*:2200").
          --
          --   This will listen on IPv4 and IPv6 when available. Use "0.0.0.0:2200"
          --   or "[::]:2200 to specifically select one of the protocols.
          --
          --   Note that your service needs `CAP_NET_BIND_SERVICE` to run on port 22
          --   and it is not a good idea run the process as root.
          --   The best way to do it is to use `setcap` on the binary.
        , socketBacklog       :: Int
          -- ^ The number of not-yet-accepted connections the OS will queue
          --   before rejecting further requests (default: 1024).
        } deriving (Eq, Ord, Show)

instance Default (ServerConfig state user) where
    def = ServerConfig
        { socketConfig     = def
        , transportConfig  = def
        , userAuthConfig   = def
        , connectionConfig = def
        , onConnect        = \_ -> pure Nothing
        , onDisconnect     = \_ _ _ _ -> pure ()
        }

instance Default SocketConfig where
    def = SocketConfig
        { socketBindAddresses = pure (HostAddress "*" 2200)
        , socketBacklog       = 1024
        }

-- | Listen for connections and serve them.
--
--   (1) The actual server behaviour is only determined by its configuration.
--       The default configuration rejects all authentication and service requests,
--       so you will need to adapt it to your use-case.
--   (2) The `Agent` will be used to authenticate to the client.
--       It is usually sufficient to use a `Network.SSH.KeyPair` as agent.
--   (3) This operation never returns.
--   (4) In order to shutdown the server, it is sufficient to throw an asynchronuous
--       exception to this thread. All depdendant threads and resources will be
--       properly freed.
--       It is a good idea to have `runServer` wrapped in an 
--       `Control.Concurrent.Async.Async` which can be canceled on when necessary.
--
-- Example:
--
-- @
-- runServer :: IO ()
-- runServer sock = do
--     keyPair <- `Network.SSH.newKeyPair`
--     runServer conf keyPair
--     where
--         conf = `def` { userAuthConfig   = `def` { `onAuthRequest`         = handleAuthRequest }
--                    , connectionConfig = `def` { `onSessionRequest`      = handleSessionRequest
--                                             , `onDirectTcpIpRequest`  = handleDirectTcpIpRequest
--                                             }
--                    }
--
-- handleAuthRequest :: `Network.SSH.UserName` -> `Network.SSH.ServiceName` -> `Network.SSH.PublicKey` -> IO (Maybe `Network.SSH.UserName`)
-- handleAuthRequest user service pubkey = case user of
--   "simon" -> pure (Just user)
--   _       -> pure Nothing
--
-- handleSessionRequest :: state -> `SessionRequest` -> IO (Maybe `SessionHandler`)
-- handleSessionRequest _ _ = pure $ Just $ SessionHandler $ \env mterm mcmd stdin stdout stderr -> do
--     `sendAll` stdout "Hello, world!\\n"
--     pure `System.Exit.ExitSuccess`
--
-- handleDirectTcpIpRequest :: state -> `DirectTcpIpRequest` -> IO (Maybe DirectTcpIpHandler)
-- handleDirectTcpIpRequest _ req =
--     | port (dstPort req) == 80 = pure $ Just $ DirectTcpIpHandler $ \stream -> do
--           bs <- `receive` stream 4096
--           `sendAll` stream "HTTP/1.1 200 OK\\n"
--           sendAll stream "Content-Type: text/plain\\n\\n"
--           sendAll stream "Hello, world!\\n"
--           sendAll stream "\\n"
--           sendAll stream bs
--           pure ()
--     | otherwise = pure Nothing
-- @
runServer :: IsAgent agent => ServerConfig state user -> agent -> IO ()
runServer config agent = do
    addrs <- nub . fmap S.socketAddress <$> getAddressInfos
    bracket newAsyncSet cancelAsyncSet $ \tas ->
        -- Open one listening socket and acceptor thread for each address.
        forConcurrently_ addrs $ bracket open close . accept tas
    where
        getAddressInfos :: IO [S.AddressInfo S.Inet6 S.Stream S.Default]
        getAddressInfos = concat <$> forM
            (toList $ socketBindAddresses $ socketConfig config)
            (\(HostAddress (Host h) (Port p)) -> S.getAddressInfo (Just h) (Just $ BS8.pack $ show p) flags)
            -- Return both IPv4 and/or IPv6 addresses, but only when configured on the system.
            -- IPv4 addresses appear as IPv6 (IPv6-mapped), but they are perfectly reachable via IPv4.
            where flags = S.aiAll <> S.aiNumericService <> S.aiPassive <> S.aiV4Mapped <> S.aiAddressConfig

        serve :: (DuplexStream stream) => S.SocketAddress S.Inet6 -> stream -> IO ()
        serve peerAddr stream = do
            tIdentity <- newTVarIO Nothing
            ha <- toHostAddress <$> S.getNameInfo peerAddr (S.niNumericHost <> S.niNumericService)
            onConnect config ha >>= \case
                Nothing -> onDisconnect config ha Nothing Nothing disconnectNotAllowed
                Just st -> foobar tIdentity st ha >>= \case
                    Right () -> pure () -- FIXME
                    Left disconnect -> do
                        identity <- readTVarIO tIdentity
                        onDisconnect config ha (Just st) identity disconnect
            where
                toHostAddress ni = HostAddress
                    (Host $ S.hostName ni)
                    (Port $ fromIntegral $ S.inet6Port peerAddr)
                foobar tIdentity st ha =
                    withServerTransport (transportConfig config) stream (Agent agent) $ \transport session ->
                    withAuthentication (userAuthConfig config) transport st ha session $ \case
                        Name "ssh-connection" -> Just $ \identity -> do
                            atomically $ writeTVar tIdentity (Just identity)
                            serveConnection (connectionConfig config) transport identity
                        _ -> Nothing
                disconnectNotAllowed = Disconnect Local DisconnectHostNotAllowedToConnect mempty

        open  = S.socket :: IO (S.Socket S.Inet6 S.Stream S.Default)
        close = S.close
        accept tas addr s = do
            S.setSocketOption s (S.ReuseAddress True)
            S.setSocketOption s (S.V6Only False)
            S.bind s addr
            S.listen s (socketBacklog $ socketConfig config)
            forever $
                bracketOnError (S.accept s) (S.close . fst) $ \(stream, peerAddr) ->
                bracketOnError newAsyncToken failAsyncToken $ \tma -> do
                    -- The acceptor thread starts an async with the handler function.
                    -- The acceptor thread is responsible for the socket until
                    -- it has passed the token to the thread within the async.
                    a <- async $ atomically (readTMVar tma) >>= \case
                        -- Do not run: Acceptor thread closes socket.
                        Nothing -> pure ()
                        -- Start running: This thread is responsible for closing socket.
                        Just t  -> serve peerAddr stream `finally` do
                            S.close stream
                            atomically (deleteFromAsyncSet tas t)
                    atomically do
                        putTMVar tma (Just a)
                        insertIntoAsyncSet tas a
        newAsyncToken            = newEmptyTMVarIO
        failAsyncToken mt        = atomically $ putTMVar mt Nothing <|> pure ()
        newAsyncSet              = newTVarIO mempty
        cancelAsyncSet ts        = readTVarIO ts >>= mapM_ cancel
        insertIntoAsyncSet tas a = readTVar tas >>= \as -> writeTVar tas $! Set.insert a as
        deleteFromAsyncSet tas a = readTVar tas >>= \as -> writeTVar tas $! Set.delete a as
