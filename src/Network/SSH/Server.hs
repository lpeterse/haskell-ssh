{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server ( serve ) where

import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Exception
import           Control.Monad
import           Control.Monad.IO.Class
import           Control.Monad.STM
import qualified Crypto.Cipher.ChaCha          as ChaCha
import qualified Crypto.Hash                   as Hash
import qualified Crypto.MAC.Poly1305           as Poly1305
import qualified Crypto.PubKey.Curve25519      as Curve25519
import qualified Crypto.PubKey.Ed25519         as Ed25519
import           Crypto.Random.Types           (MonadRandom)
import           Data.Bits
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Lazy          as LBS
import           Data.Monoid                   ((<>))
import qualified Data.Serialize                as B
import qualified Data.Serialize.Get            as B
import qualified Data.Serialize.Get            as C
import qualified Data.Serialize.Put            as B
import qualified Data.Serialize.Put            as C
import           Data.Stream
import           Data.Typeable
import           Data.Word

import           Network.SSH.Constants
import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Key
import           Network.SSH.KeyExchange
import           Network.SSH.Message
import           Network.SSH.Server.Coding
import           Network.SSH.Server.Config
import           Network.SSH.Server.Connection
import qualified Network.SSH.Server.Connection as Connection
import           Network.SSH.Server.Types
import qualified Network.SSH.Server.Types      as Config

data TransportState stream
    = TransportState
    {   transportBytesReceived   :: MVar Word64
    ,   transportPacketsReceived :: MVar Word64
    ,   transportBytesSent       :: MVar Word64
    ,   transportPacketsSent     :: MVar Word64
    ,   transportDecoder         :: MVar (Decoder2 stream)
    ,   transportEncoder         :: MVar (Encoder2 stream)
    ,   transportKeyExchange     :: MVar (Maybe KeyExchangeState)
    }

data KeyExchangeState
    = WaitingForKexInit      (KexInit -> IO KeyExchangeState)
    | WaitingForKexEcdhInit  (KexEcdhInit -> IO KeyExchangeState)
    | WaitingForKexNewKeys   (IO ())

type Encoder2 stream = ()
type Decoder2 stream = ()

newTransportState :: IO (TransportState stream)
newTransportState = TransportState
    <$> newMVar 0
    <*> newMVar 0
    <*> newMVar 0
    <*> newMVar 0
    <*> newMVar ()
    <*> newMVar ()
    <*> newMVar Nothing

serve :: (DuplexStream stream) => Config identity -> stream -> IO ()
serve config stream = do
    -- Receive the client version string and immediately reply
    -- with the server version string if the client version string is valid.
    clientVersion <- receiveVersion stream
    sendAll stream $ runPut $ put version

    -- Initialize a new transport state object to keep track of
    -- packet sequence numbers and encryption contexts.
    state <- newTransportState

    -- Send KexInit to client and expect KexInit reply.
    serverKexInit <- kexInit <$> newCookie
    sendPacket state stream serverKexInit
    clientKexInit <- receivePacket state stream

    -- Perform a key exchange based on the algorithm negotiation.
    keys <- exchangeKeys
        config state stream
        serverKexInit version
        clientKexInit clientVersion

    -- Derive the required encryption/decryption keys.
    -- The integrity keys etc. are not needed with chacha20.
    let session                 = keysSession keys
    let mainKeyCS:headerKeyCS:_ = keysClientToServer keys
        mainKeySC:headerKeySC:_ = keysServerToClient keys

    -- Initialize cryptographic encoder/decoder.
    let encode = chacha20Poly1305Encode headerKeySC mainKeySC
        decode = (f .) . chacha20Poly1305Decoder headerKeyCS mainKeyCS
            where
                f (DecoderDone p c) = pure (p, c)
                f (DecoderFail e)   = throwIO (SshCryptoErrorException e)
                f (DecoderMore c)   = do
                    cipher <- receive stream (fromIntegral $ transportBufferSize config)
                    when (BA.null cipher) (throwIO SshUnexpectedEndOfInputException)
                    f (c cipher)

    -- The connection is essentially a state machine.
    -- It also contains resources that need to be freed on termination
    -- (like running threads), therefore the bracket pattern.
    withConnection config session $ \connection-> do
        -- The sender is an infinite loop that pulls messages from the connection
        -- object. Produced messages are encoded and sent.
        let sender = do
                seqnr <- modifyMVar
                    (transportPacketsSent state)
                    (\i-> let j=i+1 in j `seq` pure (j,j - 1 .&. 0xffffffff))
                msg <- pullMessage connection
                let plain  = C.runPut $ put msg
                    cipher = encode seqnr (plain `asTypeOf` cipher)
                sendAll stream cipher
                -- This thread shall terminate gracefully in case the
                -- message was a disconnect message. Per specification
                -- no other messages may follow after a disconnect message.
                case msg of
                    MsgDisconnect {} -> pure ()
                    _                -> sender

        -- The receiver is an infinite loop that waits for input on the stream,
        -- decodes and parses it and pushes it into the connection state object.
        let receiver initial = do
                -- The sequence number is always the lower 32 bits of the number of
                -- packets received - 1. By specification, it wraps around every 2^32 packets.
                -- Special care must be taken wrt to rekeying as the sequence number
                -- is used as nonce in the ChaCha20Poly1305 encryption mode.
                seqnr <- modifyMVar
                    (transportPacketsReceived state)
                    (\i-> let j=i+1 in j `seq` pure (j,j - 1 .&. 0xffffffff))
                print seqnr
                (plain, remainder) <- decode seqnr initial
                case C.runGet get plain of
                    -- There is nothing that can be done but stop when the input received
                    -- from the client is syntactically invalid.
                    Left e -> pure ()
                    -- Stop reading input when the client sends disconnect.
                    Right (MsgDisconnect x) ->
                        onDisconnect config x
                    -- Pass the message to the connection handler and proceed.
                    Right msg -> do
                        pushMessage connection msg
                        receiver remainder

        -- Exactly two threads are necessary to process input and output concurrently.
        sender `race_` receiver mempty

    where
        recvGetter :: B.Get a -> BS.ByteString -> IO (a, BS.ByteString)
        recvGetter getter initial
            | BA.null initial = f . B.runGetPartial getter =<< receive stream bufferSize
            | otherwise       = f $ B.runGetPartial getter initial
            where
                bufferSize             = fromIntegral $ transportBufferSize config
                f (B.Done a remainder) = pure (a, remainder)
                f (B.Fail e _        ) = throwIO (SshSyntaxErrorException e)
                f (B.Partial continue) = f =<< (continue <$> receive stream bufferSize)

data Keys
    = Keys
    { keysSession        :: SessionId
    , keysClientToServer :: [BA.ScrubbedBytes]
    , keysServerToClient :: [BA.ScrubbedBytes]
    }

exchangeKeys :: (DuplexStream stream)
    => Config identity
    -> TransportState stream
    -> stream
    -> KexInit -> Version
    -> KexInit -> Version
    -> IO Keys
exchangeKeys config state stream serverKexInit serverVersion clientKexInit clientVersion
    = curve25519sh256atLibSshOrg
    -- | "curve25519-sha256@libssh.org" ->
    -- | _                              -> error "FIXME"
    where
        serverPrivateKey = case hostKey config of
            Ed25519PrivateKey _ sk -> sk
        serverPublicKey  = case hostKey config of
            Ed25519PrivateKey pk _ -> pk

        curve25519sh256atLibSshOrg = do
            -- Generate an Ed25519 keypair for elliptic curve Diffie-Hellman
            -- key exchange.
            serverEphemeralSecretKey <- Curve25519.generateSecretKey
            serverEphemeralPublicKey <- pure $ Curve25519.toPublic serverEphemeralSecretKey
            -- Receive KexEcdhInit from client.
            KexEcdhInit clientEphemeralPublicKey <- receivePacket state stream
            -- Compute and perform the Diffie-Helman key exchange.
            let dhSecret = Curve25519.dh
                        clientEphemeralPublicKey
                        serverEphemeralSecretKey
            let hash = exchangeHash
                        clientVersion
                        serverVersion
                        clientKexInit
                        serverKexInit
                        (PublicKeyEd25519 serverPublicKey)
                        clientEphemeralPublicKey
                        serverEphemeralPublicKey
                        dhSecret
            let signature = SignatureEd25519 $ Ed25519.sign
                        serverPrivateKey
                        serverPublicKey
                        hash
            let kexEcdhReply = KexEcdhReply {
                        kexServerHostKey      = PublicKeyEd25519 serverPublicKey
                    ,   kexServerEphemeralKey = serverEphemeralPublicKey
                    ,   kexHashSignature      = signature
                    }
            let session = SessionId $ BA.convert hash

            -- Complete the key exchange and wait for the client to confirm
            -- with a KexNewKeys msg.
            sendPacket state stream kexEcdhReply
            sendPacket state stream KexNewKeys
            KexNewKeys <- receivePacket state stream

            pure Keys {
                    keysSession        = session
                ,   keysClientToServer = deriveKeys dhSecret hash "C" session
                ,   keysServerToClient = deriveKeys dhSecret hash "D" session
                }

-- The maximum length of the version string is 255 chars including CR+LF.
-- The version string is usually short and transmitted within
-- a single TCP segment. The concatenation is therefore unlikely to happen
-- for regular use cases, but nonetheless required for correctness.
-- It is furthermore assumed that the client does not send any more data
-- after the version string before having received a response from the server;
-- otherwise parsing will fail. This is done in order to not having to deal with leftovers.
receiveVersion :: (InputStream stream) => stream -> IO Version
receiveVersion stream = receive stream 255 >>= f
    where
        f bs
            | BS.last bs == 0x0a  = runGet get bs
            | BS.length bs == 255 = throwIO $ SshSyntaxErrorException "invalid version string"
            | otherwise           = receive stream (255 - BS.length bs) >>= f . (bs <>)

receivePacket :: (InputStream stream, Encoding msg) => TransportState stream -> stream -> IO msg
receivePacket state stream = do
    len <- runGet getWord32 =<< receiveAll stream 4
    when (len > maxPacketLength) $
        throwIO SshMaxPacketLengthExceededException
    msg <- runGet (skip 1 >> get) =<< receiveAll stream (fromIntegral len)
    modifyMVar_ (transportBytesReceived state) (\i-> pure $! i + 4 + fromIntegral len)
    modifyMVar_ (transportPacketsReceived state) (\i-> pure $! i + 1)
    pure msg

sendPacket :: (OutputStream stream, Encoding msg) => TransportState stream -> stream -> msg -> IO ()
sendPacket state stream msg = do
    sent <- sendAll stream $ runPut $ putPacked msg
    modifyMVar_ (transportBytesSent state) (\i-> pure $! i + fromIntegral sent)
    modifyMVar_ (transportPacketsSent state) (\i-> pure $! i + 1)
