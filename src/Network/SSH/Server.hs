{-# LANGUAGE ExplicitForAll    #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
module Network.SSH.Server ( serve ) where

import           Control.Applicative
import           Control.Concurrent
import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
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
import           Network.SSH.Server.Config
import           Network.SSH.Server.Connection
import qualified Network.SSH.Server.Connection as Connection
import           Network.SSH.Server.Types
import qualified Network.SSH.Server.Types      as Config

data TransportState stream
    = TransportState
    {   transportStream          :: stream
    ,   transportBytesReceived   :: MVar Word64
    ,   transportPacketsReceived :: MVar Word64
    ,   transportBytesSent       :: MVar Word64
    ,   transportPacketsSent     :: MVar Word64
    ,   transportSender          :: MVar (BS.ByteString -> IO ())
    ,   transportReceiver        :: MVar (IO BS.ByteString)
    }

data KeyExchangeState
    = WaitingForRekeying
    | WaitingForKexInit      (KexInit -> IO KeyExchangeState)
    | WaitingForKexEcdhInit  (KexEcdhInit -> IO KeyExchangeState)

newTransportState :: DuplexStream stream => stream -> IO (TransportState stream)
newTransportState stream = do
    s <- newEmptyMVar
    r <- newEmptyMVar
    state <- TransportState stream
        <$> newMVar 0
        <*> newMVar 0
        <*> newMVar 0
        <*> newMVar 0
        <*> pure s
        <*> pure r
    putMVar s (sendPlain state)
    putMVar r (receivePlain state)
    pure state

serve :: (DuplexStream stream) => Config identity -> stream -> IO ()
serve config stream = do
    -- Receive the client version string and immediately reply
    -- with the server version string if the client version string is valid.
    clientVersion <- receiveVersion stream
    sendAll stream $ runPut $ put version

    -- Initialize a new transport state object to keep track of
    -- packet sequence numbers and encryption contexts.
    state <- newTransportState stream

    -- Send KexInit to client and expect KexInit reply.
    serverKexInit <- kexInit <$> newCookie
    sendPlain state serverKexInit
    clientKexInit <- receivePlain state

    -- Perform a key exchange based on the algorithm negotiation.
    keys <- exchangeKeys
        config state
        serverKexInit version
        clientKexInit clientVersion

    -- Derive the required encryption/decryption keys.
    -- The integrity keys etc. are not needed with chacha20.
    let session                 = keysSession keys
    let mainKeyCS:headerKeyCS:_ = keysClientToServer keys
        mainKeySC:headerKeySC:_ = keysServerToClient keys

    swapMVar (transportSender state) $
        sendEncrypted state headerKeySC mainKeySC

    swapMVar (transportReceiver state) $ do
        receiveEncrypted state headerKeyCS mainKeyCS

    -- The connection is essentially a state machine.
    -- It also contains resources that need to be freed on termination
    -- (like running threads), therefore the bracket pattern.
    withConnection config session $ \connection-> do
        -- This variable shall be used to interleave the sending
        -- of transport messages with high priority with the regular output
        -- from higher layers.
        priorityOutput <- newEmptyTMVarIO
        -- The kex handler is a state machine that keeps track of
        -- running key exchanges and all required context.
        -- Key re-exchanges may be interleaved with regular traffic and
        -- therefore cannot be performed synchronously.
        handleKexStep <- newKexStepHandler config state (atomically . putTMVar priorityOutput)

        -- The sender is an infinite loop that pulls messages from the connection
        -- object. Produced messages are encoded and sent.
        let sender = loop =<< readMVar (transportSender state)
                where
                    loop s = do
                        msg <- atomically $ takeTMVar priorityOutput <|> pullMessageSTM connection
                        s $ runPut $ put msg
                        -- This thread shall terminate gracefully in case the
                        -- message was a disconnect message. By specification
                        -- no other messages may follow after a disconnect message.
                        case msg of
                            MsgDisconnect {} -> pure ()
                            MsgKexNewKeys {} -> loop =<< readMVar (transportSender state)
                            _                -> loop s

        -- The receiver is an infinite loop that waits for input on the stream,
        -- parses it and pushes it into the connection state object.
        let receiver = loop =<< readMVar (transportReceiver state)
                where
                    loop r = r >>= runGet get >>= \case
                        MsgDisconnect x -> onDisconnect config x
                        MsgKexInit kexInit -> do
                            handleKexStep (KexProcessInit kexInit)
                            loop r
                        MsgKexEcdhInit kexEcdhInit -> do
                            handleKexStep (KexProcessEcdhInit kexEcdhInit)
                            loop r
                        MsgKexNewKeys {} -> do
                            print "NEW"
                            loop =<< readMVar (transportReceiver state)
                        msg -> do
                            print msg
                            pushMessage connection msg
                            loop r

        let rekeyingWatchdog = countDown interval
                where
                    interval = 3600
                    countDown 0 = do
                        handleKexStep KexStart
                        countDown interval
                    countDown t = do
                        threadDelay 1000000
                        countDown (t - 1)

        -- Two threads are necessary to process input and output concurrently.
        -- A third thread is used to initiate a rekeying after a certain amount of time.
        sender `race_` receiver `race_` rekeyingWatchdog

data KexStep
    = KexStart
    | KexProcessInit KexInit
    | KexProcessEcdhInit KexEcdhInit

newKexStepHandler :: Config identity -> TransportState stream -> (Message -> IO ()) -> IO (KexStep -> IO ())
newKexStepHandler config state sendMsg = do
    continuation <- newEmptyMVar

    let noKexInProgress = \case
            KexStart -> do
                ski <- kexInit <$> newCookie
                sendMsg (MsgKexInit ski)
                void $ swapMVar continuation (waitingForKexInit ski)
            KexProcessInit cki -> do
                ski <- kexInit <$> newCookie
                sendMsg (MsgKexInit ski)
                void $ swapMVar continuation (waitingForKexEcdhInit ski cki)
            KexProcessEcdhInit {} ->
                throwIO $ SshProtocolErrorException "unexpected KexEcdhInit"

        waitingForKexInit ski = \case
            KexStart ->
                pure () -- already in progress
            KexProcessInit cki ->
                void $ swapMVar continuation (waitingForKexEcdhInit ski cki)
            KexProcessEcdhInit {} ->
                throwIO $ SshProtocolErrorException "unexpected KexEcdhInit"

        waitingForKexEcdhInit ski cki = \case
            KexStart ->
                pure () -- already in progress
            KexProcessInit {} ->
                throwIO $ SshProtocolErrorException "unexpected KexInit"
            KexProcessEcdhInit ecdhi ->
                undefined

    putMVar continuation noKexInProgress
    pure $ \step-> do
        handle <- readMVar continuation
        handle step

data Keys
    = Keys
    { keysSession        :: SessionId
    , keysClientToServer :: [BA.ScrubbedBytes]
    , keysServerToClient :: [BA.ScrubbedBytes]
    }

exchangeKeys :: (DuplexStream stream)
    => Config identity
    -> TransportState stream
    -> KexInit -> Version
    -> KexInit -> Version
    -> IO Keys
exchangeKeys config state serverKexInit serverVersion clientKexInit clientVersion
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
            KexEcdhInit clientEphemeralPublicKey <- receivePlain state
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
            sendPlain state kexEcdhReply
            sendPlain state KexNewKeys
            MsgKexNewKeys {} <- receivePlain state

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

sendPlain :: (OutputStream stream, Encoding msg) => TransportState stream -> msg -> IO ()
sendPlain state msg = do
    sent <- sendAll (transportStream state) $ runPut $ putPacked msg
    modifyMVar_ (transportBytesSent state) (\i-> pure $! i + fromIntegral sent)
    modifyMVar_ (transportPacketsSent state) (\i-> pure $! i + 1)

receivePlain :: (InputStream stream, Encoding msg) => TransportState stream -> IO msg
receivePlain state = do
    let stream = transportStream state
    len <- runGet getWord32 =<< receiveAll stream 4
    when (len > maxPacketLength) $
        throwIO SshMaxPacketLengthExceededException
    msg <- runGet (skip 1 >> get) =<< receiveAll stream (fromIntegral len)
    modifyMVar_ (transportBytesReceived state) (\i-> pure $! i + 4 + fromIntegral len)
    modifyMVar_ (transportPacketsReceived state) (\i-> pure $! i + 1)
    pure msg

sendEncrypted :: (OutputStream stream, BA.ByteArrayAccess headerKey, BA.ByteArrayAccess mainKey)
    => TransportState stream -> headerKey -> mainKey -> BS.ByteString -> IO ()
sendEncrypted state headerKey mainKey plain = do
    seqnr <- readMVar (transportPacketsSent state)
    sent  <- sendAll (transportStream state) (encode seqnr)
    modifyMVar_ (transportBytesSent state) (\i-> pure $! i + fromIntegral sent)
    modifyMVar_ (transportPacketsSent state) (\i-> pure $! i + 1)
    where
        encode seqnr = ciph3 <> mac
            where
                plainlen      = BA.length plain                :: Int
                padlen        = let p = 8 - ((1 + plainlen) `mod` 8)
                                in  if p < 4 then p + 8 else p :: Int
                paclen        = 1 + plainlen + padlen          :: Int
                padding       = BA.replicate padlen 0
                padlenBA      = BA.singleton (fromIntegral padlen)
                paclenBA      = BA.pack
                    [ fromIntegral $ paclen `shiftR` 24
                    , fromIntegral $ paclen `shiftR` 16
                    , fromIntegral $ paclen `shiftR`  8
                    , fromIntegral $ paclen `shiftR`  0
                    ]
                nonceBA = BA.pack
                    [ 0
                    , 0
                    , 0
                    , 0
                    , fromIntegral $ seqnr  `shiftR` 24
                    , fromIntegral $ seqnr  `shiftR` 16
                    , fromIntegral $ seqnr  `shiftR`  8
                    , fromIntegral $ seqnr  `shiftR`  0
                    ] :: BA.Bytes
                st1           = ChaCha.initialize 20 mainKey nonceBA
                st2           = ChaCha.initialize 20 headerKey nonceBA
                (poly, st3)   = ChaCha.generate st1 64
                ciph1         = fst $ ChaCha.combine st2 paclenBA
                ciph2         = fst $ ChaCha.combine st3 $ padlenBA <> plain <> padding
                ciph3         = ciph1 <> ciph2
                mac           = BA.convert (Poly1305.auth (BS.take 32 poly) ciph3)

receiveEncrypted :: (InputStream stream, BA.ByteArrayAccess headerKey, BA.ByteArrayAccess mainKey)
    => TransportState stream -> headerKey -> mainKey -> IO BS.ByteString
receiveEncrypted state headerKey mainKey = do
    -- The sequence number is always the lower 32 bits of the number of
    -- packets received - 1. By specification, it wraps around every 2^32 packets.
    -- Special care must be taken wrt to rekeying as the sequence number
    -- is used as nonce in the ChaCha20Poly1305 encryption mode.
    seqnr <- readMVar (transportPacketsReceived state)
    let nonce = BA.pack
            [ 0
            , 0
            , 0
            , 0
            , fromIntegral $ seqnr  `shiftR` 24
            , fromIntegral $ seqnr  `shiftR` 16
            , fromIntegral $ seqnr  `shiftR`  8
            , fromIntegral $ seqnr  `shiftR`  0
            ] :: BA.Bytes

    paclenCiph <- receiveAll (transportStream state) 4
    let ccMain          = ChaCha.initialize 20 mainKey   nonce
    let ccHeader        = ChaCha.initialize 20 headerKey nonce
    let (poly, ccMain') = ChaCha.generate ccMain 64
    let paclenPlain = fst $ ChaCha.combine ccHeader paclenCiph
    let maclen = 16
    let paclen = fromIntegral (BA.index paclenPlain 0) `shiftL` 24
            .|.  fromIntegral (BA.index paclenPlain 1) `shiftL` 16
            .|.  fromIntegral (BA.index paclenPlain 2) `shiftL`  8
            .|.  fromIntegral (BA.index paclenPlain 3) `shiftL`  0

    pac <- receiveAll (transportStream state) paclen
    mac <- receiveAll (transportStream state) maclen

    modifyMVar_ (transportBytesReceived state) (\i-> pure $! i + 4 + fromIntegral paclen + fromIntegral maclen)
    modifyMVar_ (transportPacketsReceived state) (\i-> pure $! i + 1)

    let authTagReceived = Poly1305.Auth $ BA.convert mac
    let authTagExpected = Poly1305.auth (BS.take 32 poly) (paclenCiph <> pac)

    if authTagReceived /= authTagExpected
        then throwIO $ SshCryptoErrorException "mac mismatch"
        else do
            let plain = fst (ChaCha.combine ccMain' pac)
            case BS.uncons plain of
                Nothing    -> throwIO $ SshSyntaxErrorException "packet structure"
                Just (h,t) -> pure $ BS.take (BS.length t - fromIntegral h) t
