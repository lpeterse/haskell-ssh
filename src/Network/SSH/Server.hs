{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server ( serve ) where

import           Control.Concurrent.Async
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

serve :: (DuplexStream stream) => Config identity -> stream -> IO ()
serve config stream = do
    -- The maximum length of the version string is 255 chars including CR+LF.
    -- Parsing in chunks of 32 bytes in order to not allocate unnecessarly
    -- much memory. The version string is usually short and transmitted within
    -- a single TCP segment.
    (clientVersion, rem1) <- recvGetter get BS.empty

    -- Reply by sending the server version string.
    sendPutter $ put version

    -- Send KexInit to client.
    serverKexInit <- kexInit <$> newCookie
    sendPutter $ putPacked serverKexInit

    -- Receive KexInit from client.
    (clientKexInit, rem2) <- recvGetter getUnpacked rem1

    keys <- exchangeKeys
                config stream
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
        let sender seqnr = do
                msg <- pullMessage connection
                let plain  = C.runPut $ put msg
                    cipher = encode seqnr (plain `asTypeOf` cipher)
                sendAll stream cipher
                -- This thread shall terminate gracefully in case the
                -- message was a disconnect message. Per specification
                -- no other messages may follow after a disconnect message.
                case msg of
                    MsgDisconnect {} -> pure ()
                    _                -> sender (seqnr + 1)

        -- The receiver is an infinite loop that waits for input on the stream,
        -- decodes and parses it and pushes it into the connection state object.
        let receiver seqnr initial = do
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
                        receiver (seqnr + 1) remainder

        -- Exactly two threads are necessary to process input and output concurrently.
        sender 3 `race_` receiver 3 mempty -- rem4

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

        sendPutter :: Put -> IO ()
        sendPutter = sendAll stream . runPut

data Keys
    = Keys
    { keysSession        :: SessionId
    , keysClientToServer :: [BA.ScrubbedBytes]
    , keysServerToClient :: [BA.ScrubbedBytes]
    }

exchangeKeys :: (DuplexStream stream)
    => Config identity
    -> stream
    -> KexInit -> Version
    -> KexInit -> Version
    -> IO Keys
exchangeKeys config stream serverKexInit serverVersion clientKexInit clientVersion
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
            KexEcdhInit clientEphemeralPublicKey <- receivePacket stream
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
            sendPacket stream kexEcdhReply
            sendPacket stream KexNewKeys
            KexNewKeys <- receivePacket stream

            pure Keys {
                    keysSession        = session
                ,   keysClientToServer = deriveKeys dhSecret hash "C" session
                ,   keysServerToClient = deriveKeys dhSecret hash "D" session
                }

receivePacket :: (InputStream stream, Encoding a) => stream -> IO a
receivePacket = undefined

sendPacket :: (OutputStream stream, Encoding a) => stream -> a -> IO ()
sendPacket = undefined
