{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent.Async
import           Control.Concurrent.STM.TChan
import           Control.Exception              (bracket)
import           Control.Monad                  (forM_, forever, when)
import           Control.Monad.Reader
import           Control.Monad.State.Lazy
import           Control.Monad.STM
import qualified Crypto.Cipher.ChaCha           as ChaCha
import qualified Crypto.Cipher.ChaChaPoly1305   as ChaChaPoly1305
import           Crypto.Error
import qualified Crypto.Hash                    as Hash
import qualified Crypto.Hash.Algorithms         as Hash
import qualified Crypto.MAC.Poly1305            as Poly1305
import qualified Crypto.PubKey.Curve25519       as Curve25519
import qualified Crypto.PubKey.Ed25519          as Ed25519
import qualified Data.Binary                    as B
import qualified Data.Binary.Get                as B
import qualified Data.Binary.Put                as B
import qualified Data.ByteArray                 as BA
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Lazy           as LBS
import           Data.Function                  (fix)
import qualified Data.Map.Strict                as M
import           Data.Monoid
import           Data.Word
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S

import           Network.SSH
import           Network.SSH.Connection
import           Network.SSH.Constants
import           Network.SSH.Message

main :: IO ()
main = bracket open close accept
  where
    open = S.socket :: IO (S.Socket S.Inet6 S.Stream S.Default)
    close = S.close
    accept s = do
      S.setSocketOption s (S.ReuseAddress True)
      S.setSocketOption s (S.V6Only False)
      S.bind s (S.SocketAddressInet6 S.inet6Any 22 0 0)
      S.listen s 5
      bracket (S.accept s) (S.close . fst) serve
    serve (s,addr) = do
      serverSecretKey <- Ed25519.generateSecretKey
      serverPublicKey <- pure $ Ed25519.toPublic serverSecretKey
      serverEphemeralSecretKey <- Curve25519.generateSecretKey
      serverEphemeralPublicKey <- pure $ Curve25519.toPublic serverEphemeralSecretKey

      bs <- S.receive s 4096 S.msgNoSignal
      let clientVersion = B.runGet B.get (LBS.fromStrict bs)
      print clientVersion

      S.sendAllLazy s (B.runPut $ B.put version) S.msgNoSignal

      bs  <- S.receive s 32000 S.msgNoSignal
      let clientKexInit = B.runGet (unpacketize $ B.getWord8 >> B.get) (LBS.fromStrict bs)
      print clientKexInit
      cookie <- newCookie
      let serverKexInit = kexInit cookie
      S.sendAllLazy s (B.runPut $ packetize $ B.putWord8 20 <> B.put serverKexInit) S.msgNoSignal
      bs <- S.receive s 32000 S.msgNoSignal

      let KexEcdhInit clientEphemeralPublicKey = B.runGet (unpacketize B.get) (LBS.fromStrict bs)
      let dhSecret = Curve25519.dh clientEphemeralPublicKey serverEphemeralSecretKey
      let hash = exchangeHash
            clientVersion            -- check
            version                  -- check
            clientKexInit            -- check
            serverKexInit            -- check
            serverPublicKey          -- check
            clientEphemeralPublicKey -- check
            serverEphemeralPublicKey -- check
            dhSecret                 -- check (client pubkey + server seckey)
      let sess      = SessionId (BS.pack $ BA.unpack hash)
      let signature = Ed25519.sign serverSecretKey serverPublicKey hash
      let reply     = KexEcdhReply {
          kexServerHostKey      = serverPublicKey
        , kexServerEphemeralKey = serverEphemeralPublicKey
        , kexHashSignature      = signature
        }

      S.sendAllLazy s (B.runPut $ packetize $ B.put reply) S.msgNoSignal
      S.sendAllLazy s (B.runPut $ packetize $ B.putWord8 21) S.msgNoSignal
      void $ S.receive s 32000 S.msgNoSignal -- newkeys

      let ekCS_K1:ekCS_K2:_ = deriveKeys dhSecret hash "C" sess
      let ekSC_K1:ekSC_K2:_ = deriveKeys dhSecret hash "D" sess

      serveConnection sess $ ConnectionConfig
        (\b-> S.sendAll s b S.msgNoSignal >> pure ())
        (\i-> S.receive s i S.msgNoSignal)
        ekCS_K2 ekCS_K1 ekSC_K2 ekSC_K1

data ConnectionConfig
  = ConnectionConfig
  { sendBS    :: BS.ByteString -> IO ()
  , receiveBS :: Int -> IO BS.ByteString
  , ekCS_K2   :: Hash.Digest Hash.SHA256
  , ekCS_K1   :: Hash.Digest Hash.SHA256
  , ekSC_K2   :: Hash.Digest Hash.SHA256
  , ekSC_K1   :: Hash.Digest Hash.SHA256
  }

serveConnection :: SessionId -> ConnectionConfig -> IO ()
serveConnection sess cfg = do
  input <- newTChanIO
  output <- newTChanIO
  serve sess (readTChan input) (writeTChan output)
    `race_` runSender output 3
    `race_` runReceiver input 3
  where
    runSender q i = do
      msg <- atomically $ readTChan q
      sendBS cfg $ encrypt i (ekSC_K2 cfg) (ekSC_K1 cfg) (B.put msg)
      runSender q (i + 1)
    runReceiver q i = do
      bs <- decrypt i (ekCS_K2 cfg) (ekCS_K1 cfg) (receiveBS cfg)
      atomically $ writeTChan q $! B.runGet B.get (LBS.fromStrict bs)
      runReceiver q (i + 1)

unpacket :: BS.ByteString -> Maybe BS.ByteString
unpacket bs = do
  (h,ts) <- BS.uncons bs
  pure $ BS.take (BS.length ts - fromIntegral h) ts

encrypt :: (BA.ByteArrayAccess ba) => Int -> ba -> ba -> B.Put -> BS.ByteString
encrypt seqnr headerKey mainKey dat = ciph3 <> mac
  where
    build         = LBS.toStrict . B.runPut

    datlen        = BS.length datBS                :: Int
    padlen        = let p = 8 - ((1 + datlen) `mod` 8)
                    in  if p < 4 then p + 8 else p :: Int
    paclen        = 1 + datlen + padlen            :: Int

    datBS         = build dat
    padBS         = BS.replicate padlen 0
    padlenBS      = build $ B.putWord8    (fromIntegral padlen)
    paclenBS      = build $ B.putWord32be (fromIntegral paclen)
    nonceBS       = build $ B.putWord64be (fromIntegral seqnr)

    st1           = ChaCha.initialize 20 mainKey nonceBS
    st2           = ChaCha.initialize 20 headerKey nonceBS
    (poly, st3)   = ChaCha.generate st1 64
    ciph1         = fst $ ChaCha.combine st2 paclenBS
    ciph2         = fst $ ChaCha.combine st3 $ padlenBS <> datBS <> padBS
    ciph3         = ciph1 <> ciph2
    mac           = let Poly1305.Auth auth = Poly1305.auth (BS.take 32 poly) ciph3
                    in  BS.pack (BA.unpack auth)

decrypt :: (BA.ByteArrayAccess ba) => Int -> ba -> ba -> (Int -> IO BS.ByteString) -> IO BS.ByteString
decrypt seqnr headerKey mainKey receive = do
  ciph1            <- receive 4
  let paclenBS      = fst $ ChaCha.combine st1 ciph1
  let paclen        = fromIntegral $ B.runGet B.getWord32be (LBS.fromStrict paclenBS)
  ciph2            <- receive paclen
  let expectedMAC   = Poly1305.auth (BS.take 32 poly) (ciph1 <> ciph2)
  actualMAC        <- Poly1305.Auth . BA.pack . BS.unpack <$> receive maclen
  when (actualMAC /= expectedMAC) (fail "MAC MISMATCH")
  let pacBS        = fst $ ChaCha.combine st3 ciph2
  case unpacket pacBS of
    Nothing  -> fail "PADDING ERROR"
    Just msg -> pure msg
  where
    build         = LBS.toStrict . B.runPut
    maclen        = 16
    nonceBS       = build $ B.putWord64be (fromIntegral seqnr)
    st1           = ChaCha.initialize 20 headerKey nonceBS
    st2           = ChaCha.initialize 20 mainKey   nonceBS
    (poly, st3)   = ChaCha.generate st2 64
