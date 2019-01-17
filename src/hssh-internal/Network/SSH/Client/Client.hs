{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts          #-}
module Network.SSH.Client.Client where

import           Control.Concurrent             ( threadDelay )
import           Control.Concurrent.Async       ( withAsync, waitCatch, race )
import           Control.Exception              ( Exception, bracket, bracketOnError, catch, throwIO )
import qualified Data.ByteString.Char8          as BS8
import           Data.Default
import           Data.List.NonEmpty             ( NonEmpty (..) )
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S

import           Network.SSH.Client.Connection
import           Network.SSH.Client.HostKeyVerifier
import           Network.SSH.Client.UserAuth
import           Network.SSH.Duration
import           Network.SSH.Exception
import           Network.SSH.HostAddress
import           Network.SSH.Name
import           Network.SSH.Stream
import           Network.SSH.Transport

data ClientConfig
    = ClientConfig
    { socketConfig      :: SocketConfig
    , transportConfig   :: TransportConfig
    , connectionConfig  :: ConnectionConfig
    , hostKeyVerifier   :: HostKeyVerifier
    }

instance Default ClientConfig where
    def = ClientConfig
        { socketConfig      = def
        , transportConfig   = def
        , connectionConfig  = def
        , hostKeyVerifier   = acceptKnownHostsFromFile "~/.ssh/known_hosts"
        }

data SocketConfig
    = SocketConfig
    { socketConnectionTimeout :: Duration
    } deriving (Eq, Ord, Show)

instance Default SocketConfig where
    def = SocketConfig
        { socketConnectionTimeout = seconds (10 :: Int)
        }

data ClientException
    = NameResolutionFailed String
    | ConnectFailed        String
    | DisconnectByClient   DisconnectReason DisconnectMessage
    | DisconnectByServer   DisconnectReason DisconnectMessage
    deriving (Eq, Ord, Show)

instance Exception ClientException where

runClient :: ClientConfig -> ClientIdentity -> HostAddress -> (Connection -> IO a) -> IO a
runClient config identity addr@(HostAddress (Host host) (Port port)) handler = do
    addresses <- getAddresses
    bracket (connectAny addresses) S.close (handleStream handler)
    where
        getAddresses :: IO (NonEmpty (S.SocketAddress S.Inet6))
        getAddresses = do
            (a:as) <- S.getAddressInfo hostName portName flags `catch` \e ->
                    throwIO $ NameResolutionFailed $ show (e :: S.AddressInfoException)
                   :: IO [S.AddressInfo S.Inet6 S.Stream S.Default]
            pure (S.socketAddress a :| fmap S.socketAddress as)
            where
                hostName = Just host
                portName = Just (BS8.pack $ show port)
                flags    = S.aiAddressConfig <> S.aiV4Mapped <> S.aiAll

        connectAny :: NonEmpty (S.SocketAddress S.Inet6) -> IO (S.Socket S.Inet6 S.Stream S.Default)
        connectAny (a :| as) = connectWithTimeout a `catch` connectOther as
            where
                connectOther []     e = throwIO $ ConnectFailed $ show (e :: S.SocketException)
                connectOther (b:bs) e = connectWithTimeout b `catch` \e2 ->
                    connectOther bs (e `asTypeOf` e2)

        connectWithTimeout :: S.SocketAddress S.Inet6 -> IO (S.Socket S.Inet6 S.Stream S.Default)
        connectWithTimeout a = bracketOnError S.socket S.close $ \s -> race
                (threadDelay (fromIntegral timeout) >> throwIO S.eTimedOut) 
                (S.connect s a) >> pure s
            where
                Duration timeout = socketConnectionTimeout (socketConfig config)

        handleStream :: DuplexStream stream => (Connection -> IO a) -> stream -> IO a
        handleStream h stream = do
            ea <- withClientTransport (transportConfig config) stream $ \transport sessionId hostKey -> do
                -- Validate the host key with user supplied function.
                -- Run this as an async in order not to loose control.
                withAsync (hostKeyVerifier config addr hostKey) $ \thread ->
                    waitCatch thread >>= \case
                        Right VerificationPassed -> pure () -- host key verified
                        Right (VerificationFailed e) -> throwIO (exceptionHostKeyNotVerifiable $ DisconnectMessage e)
                        Left e -> throwIO (exceptionHostKeyNotVerifiable $ DisconnectMessage $ BS8.pack $ show e)
                -- Authenticate against the server
                requestServiceWithAuthentication identity transport sessionId (Name "ssh-connection")
                -- Start the connection layer protocol
                withConnection (connectionConfig config) transport h
            case ea of
                Left (Disconnect Local  reason msg) -> throwIO (DisconnectByClient reason msg)
                Left (Disconnect Remote reason msg) -> throwIO (DisconnectByServer reason msg)
                Right a -> pure a
