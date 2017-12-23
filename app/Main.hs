{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent.STM.TChan
import           Control.Exception              (bracket)
import           Control.Monad                  (forM_, forever, when)
import           Control.Monad.Reader
import           Control.Monad.State.Lazy
import qualified Crypto.PubKey.Curve25519       as DH
import qualified Data.Binary.Get                as B
import qualified Data.ByteArray                 as BA
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Builder        as BS
import qualified Data.ByteString.Lazy           as LBS
import           Data.Function                  (fix)
import qualified Data.Map.Strict                as M
import           Data.Monoid
import           Data.Word
import           Network.SSH
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S

import           Control.Concurrent.Async
import           Control.Concurrent.MVar
import qualified Crypto.Cipher.ChaCha           as ChaCha
import qualified Crypto.Cipher.ChaChaPoly1305   as ChaChaPoly1305
import           Crypto.Error
import qualified Crypto.Hash                    as Hash
import qualified Crypto.Hash.Algorithms         as Hash
import qualified Crypto.MAC.Poly1305            as Poly1305
import qualified Crypto.PubKey.Curve25519       as Curve25519
import qualified Crypto.PubKey.Ed25519          as Ed25519

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
      let clientVersionString = B.runGet versionParser (LBS.fromStrict bs)
      print clientVersionString

      S.sendAllBuilder s 4096 serverVersionBuilder S.msgNoSignal

      bs  <- S.receive s 32000 S.msgNoSignal
      let clientKexInit = B.runGet (unpacketize kexInitParser) (LBS.fromStrict bs)
      print clientKexInit

      S.sendAllBuilder s 4096 (packetize $ BS.word8 20 <> kexInitBuilder serverKexInit) S.msgNoSignal
      bs <- S.receive s 32000 S.msgNoSignal

      let clientEphemeralPublicKey = B.runGet (unpacketize kexRequestParser) (LBS.fromStrict bs)
      let dhSecret = Curve25519.dh clientEphemeralPublicKey serverEphemeralSecretKey
      let hash = exchangeHash
            clientVersionString      -- check
            serverVersionString      -- check
            clientKexInit            -- check
            serverKexInit            -- check
            serverPublicKey          -- check
            clientEphemeralPublicKey -- check
            serverEphemeralPublicKey -- check
            dhSecret                 -- check (client pubkey + server seckey)
      let sess      = hash
      let signature = Ed25519.sign serverSecretKey serverPublicKey hash
      let reply     = KexReply {
          serverPublicHostKey      = serverPublicKey
        , serverPublicEphemeralKey = serverEphemeralPublicKey
        , exchangeHashSignature    = signature
        }

      S.sendAllBuilder s 4096 (packetize $ kexReplyBuilder reply) S.msgNoSignal
      S.sendAllBuilder s 4096 (packetize newKeysBuilder) S.msgNoSignal
      void $ S.receive s 32000 S.msgNoSignal -- newkeys

      let ekCS_K1:ekCS_K2:_ = deriveKeys dhSecret hash "C" sess
      let ekSC_K1:ekSC_K2:_ = deriveKeys dhSecret hash "D" sess

      serveConnection $ ConnectionConfig
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

serveConnection :: ConnectionConfig -> IO ()
serveConnection cfg = do
  input <- newTChanIO
  output <- newTChanIO
  serve (readTChan input) (writeTChan output)
    `race_` runSender output 3
    `race_` runReceiver input 3
  where
    runSender q i = do
      msg <- takeMVar q
      sendBS cfg $ encrypt i (ekSC_K2 cfg) (ekSC_K1 cfg) (messageBuilder msg)
      runSender q (i + 1)
    runReceiver q i = do
      bs <- decrypt i (ekCS_K2 cfg) (ekCS_K1 cfg) (receiveBS cfg)
      putMVar q $ B.runGet messageParser (LBS.fromStrict bs)
      runReceiver q (i + 1)

unpacket :: BS.ByteString -> Maybe BS.ByteString
unpacket bs = do
  (h,ts) <- BS.uncons bs
  pure $ BS.take (BS.length ts - fromIntegral h) ts

encrypt :: (BA.ByteArrayAccess ba) => Int -> ba -> ba -> BS.Builder -> BS.ByteString
encrypt seqnr headerKey mainKey dat = ciph3 <> mac
  where
    build         = LBS.toStrict . BS.toLazyByteString

    datlen        = BS.length datBS                :: Int
    padlen        = let p = 8 - ((1 + datlen) `mod` 8)
                    in  if p < 4 then p + 8 else p :: Int
    paclen        = 1 + datlen + padlen            :: Int

    datBS         = build dat
    padBS         = BS.replicate padlen 0
    padlenBS      = build $ BS.word8    (fromIntegral padlen)
    paclenBS      = build $ BS.word32BE (fromIntegral paclen)
    nonceBS       = build $ BS.word64BE (fromIntegral seqnr)

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
    build         = LBS.toStrict . BS.toLazyByteString
    maclen        = 16
    nonceBS       = build $ BS.word64BE (fromIntegral seqnr)
    st1           = ChaCha.initialize 20 headerKey nonceBS
    st2           = ChaCha.initialize 20 mainKey   nonceBS
    (poly, st3)   = ChaCha.generate st2 64
