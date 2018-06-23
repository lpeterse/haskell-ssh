{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.KeyExchange where

import           Control.Concurrent           (threadDelay)
import           Control.Concurrent.MVar
import           Control.Concurrent.STM.TChan
import           Control.Concurrent.STM.TMVar
import           Control.Exception            (throwIO)
import           Control.Monad                (void)
import           Control.Monad.STM            (STM, atomically)
import qualified Crypto.Cipher.ChaCha         as ChaCha
import qualified Crypto.Hash                  as Hash
import qualified Crypto.MAC.Poly1305          as Poly1305
import qualified Crypto.PubKey.Curve25519     as Curve25519
import qualified Crypto.PubKey.Ed25519        as Ed25519
import           Data.Bits
import qualified Data.ByteArray               as BA
import qualified Data.ByteString              as BS
import           Data.Monoid                  ((<>))
import           Data.Word

import           Network.SSH.Constants
import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Key
import           Network.SSH.Message
import           Network.SSH.Server.Config
import           Network.SSH.Server.Transport
import           Network.SSH.Server.Types
import           Network.SSH.Stream

data KexStep
    = KexStart
    | KexProcessInit KexInit
    | KexProcessEcdhInit KexEcdhInit

performInitialKeyExchange :: (DuplexStream stream) => Config identity -> TransportState stream -> IO (SessionId, STM Message, KexStep -> IO ())
performInitialKeyExchange config state = do
    out <- newTChanIO
    msid <- newEmptyMVar
    handle <- newKexStepHandler config state (atomically . writeTChan out) msid
    handle KexStart
    sendPlain state =<< atomically (readTChan out)
    clientKexInit <- receivePlain state
    handle (KexProcessInit clientKexInit)
    clientKexEcdhInit <- receivePlain state
    handle (KexProcessEcdhInit clientKexEcdhInit)
    sendPlain state =<< atomically (readTChan out) -- KexEcdhReply
    sendPlain state =<< atomically (readTChan out) -- KexNewKeys
    KexNewKeys <- receivePlain state
    session <- readMVar msid
    pure (session, readTChan out, handle)

-- The rekeying watchdog is an inifinite loop that initiates
-- a key re-exchange when either a certain amount of time has passed or
-- when either the input or output stream has exceeded its threshold
-- of bytes sent/received.
runRekeyingWatchdog :: Config identity -> TransportState stream -> IO () -> IO ()
runRekeyingWatchdog config state rekey = countDown interval
    where
        -- For reasons of fool-proofness the rekeying interval/threshold
        -- shall never be greater than 1 hour or 1GB.
        -- NB: This is security critical as some algorithms like ChaCha20
        -- use the packet counter as nonce and an overflow will lead to
        -- nonce reuse!
        interval = min (rekeyingAfterSeconds config) 3600
        threshold = min (fromIntegral $ rekeyingAfterBytes config) (1024 * 1024 * 1024)
        countDown 0 = do
            rekey
            countDown interval
        countDown t = do
            threadDelay 1000000
            s  <- readMVar (transportBytesSent state)
            s0 <- readMVar (transportBytesSentOnLastRekeying state)
            r  <- readMVar (transportBytesReceived state)
            r0 <- readMVar (transportBytesReceivedOnLastRekeying state)
            if | thresholdExceeded s s0 -> rekey >> countDown interval
               | thresholdExceeded r r0 -> rekey >> countDown interval
               | otherwise              -> countDown (t - 1)
            where
                thresholdExceeded x x0 = x > x0 && x - x0 > threshold

newKexStepHandler :: (DuplexStream stream) => Config identity -> TransportState stream -> (Message -> IO ()) -> MVar SessionId -> IO (KexStep -> IO ())
newKexStepHandler config state sendMsg msid = do
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
          KexProcessEcdhInit (KexEcdhInit clientEphemeralPublicKey) -> do
              completeEcdhExchange ski cki clientEphemeralPublicKey
              void $ swapMVar continuation noKexInProgress

  putMVar continuation noKexInProgress
  pure $ \step-> do
      handle <- readMVar continuation
      handle step

  where
      completeEcdhExchange serverKexInit clientKexInit clientEphemeralPublicKey = do
          -- Generate an Ed25519 keypair for elliptic curve Diffie-Hellman
          -- key exchange.
          serverEphemeralSecretKey <- Curve25519.generateSecretKey
          serverEphemeralPublicKey <- pure $ Curve25519.toPublic serverEphemeralSecretKey

          let serverPrivateKey = case hostKey config of
                  Ed25519PrivateKey _ sk -> sk
          let serverPublicKey  = case hostKey config of
                  Ed25519PrivateKey pk _ -> pk

          -- Compute and perform the Diffie-Helman key exchange.
          let secret = Curve25519.dh
                  clientEphemeralPublicKey
                  serverEphemeralSecretKey
          let hash = exchangeHash
                  (transportClientVersion state)
                  (transportServerVersion state)
                  clientKexInit
                  serverKexInit
                  (PublicKeyEd25519 serverPublicKey)
                  clientEphemeralPublicKey
                  serverEphemeralPublicKey
                  secret
          let signature = SignatureEd25519 $ Ed25519.sign
                  serverPrivateKey
                  serverPublicKey
                  hash

          -- The reply is shall be sent with the old encryption context.
          -- This is the case as long as the KexNewKeys message has not
          -- been transmitted.
          sendMsg $ MsgKexEcdhReply KexEcdhReply {
                  kexServerHostKey      = PublicKeyEd25519 serverPublicKey
              ,   kexServerEphemeralKey = serverEphemeralPublicKey
              ,   kexHashSignature      = signature
              }

          session <- tryReadMVar msid >>= \case
              Just s -> pure s
              Nothing -> do
                  let s = SessionId $ BA.convert hash
                  putMVar msid s
                  pure s

          -- Derive the required encryption/decryption keys.
          -- The integrity keys etc. are not needed with chacha20.
          let mainKeyCS:headerKeyCS:_ = deriveKeys secret hash "C" session
              mainKeySC:headerKeySC:_ = deriveKeys secret hash "D" session

          void $ swapMVar (transportSender state) $
              sendEncrypted state headerKeySC mainKeySC

          void $ swapMVar (transportReceiver state) $ do
              receiveEncrypted state headerKeyCS mainKeyCS

          void $ swapMVar (transportBytesSentOnLastRekeying state) =<< readMVar (transportBytesSent state)
          void $ swapMVar (transportBytesReceivedOnLastRekeying state) =<< readMVar (transportBytesReceived state)

          -- The encryption context shall be switched no earlier than
          -- before the new keys message has been transmitted.
          -- It's the sender's thread responsibility to switch the context.
          sendMsg (MsgKexNewKeys KexNewKeys)

exchangeHash ::
    Version ->               -- client version string
    Version ->               -- server version string
    KexInit ->               -- client kex init msg
    KexInit ->               -- server kex init msg
    PublicKey ->             -- server host key
    Curve25519.PublicKey ->  -- client ephemeral key
    Curve25519.PublicKey ->  -- server ephemeral key
    Curve25519.DhSecret ->   -- dh secret
    Hash.Digest Hash.SHA256
exchangeHash (Version vc) (Version vs) ic is ks qc qs k
    = Hash.hash $ runPut $ do
        putString vc
        putString vs
        putWord32 (len ic)
        put       ic
        putWord32 (len is)
        put       is
        put       ks
        put       qc
        put       qs
        putAsMPInt k

deriveKeys :: Curve25519.DhSecret -> Hash.Digest Hash.SHA256 -> BS.ByteString -> SessionId -> [BA.ScrubbedBytes]
deriveKeys sec hash i (SessionId sess) = BA.convert <$> k1 : f [k1]
    where
    k1   = Hash.hashFinalize    $
        flip Hash.hashUpdate sess $
        Hash.hashUpdate st i :: Hash.Digest Hash.SHA256
    f ks = kx : f (ks ++ [kx])
        where
        kx = Hash.hashFinalize (foldl Hash.hashUpdate st ks)
    st =
        flip Hash.hashUpdate hash $
        Hash.hashUpdate Hash.hashInit (runPut $ putAsMPInt sec)

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
