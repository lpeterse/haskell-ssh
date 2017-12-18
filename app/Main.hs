{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Exception              (bracket)
import           Control.Monad                  (forever)
import           Control.Monad                  (forM_, when)
import qualified Crypto.PubKey.Curve25519       as DH
import qualified Data.Binary.Get                as B
import qualified Data.ByteArray                 as BA
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Builder        as BS
import qualified Data.ByteString.Lazy           as LBS
import           Data.Monoid
import           Network.SSH
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S

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
      let sess = hash

      let signature = Ed25519.sign serverSecretKey serverPublicKey hash
      let reply = KexReply {
          serverPublicHostKey      = serverPublicKey
        , serverPublicEphemeralKey = serverEphemeralPublicKey
        , exchangeHashSignature    = signature
        }
      print reply
      S.sendAllBuilder s 4096 (packetize $ kexReplyBuilder reply) S.msgNoSignal

      S.sendAllBuilder s 4096 (packetize $ newKeysBuilder) S.msgNoSignal

      let ivCS_K1:ivCS_K2:_ = deriveKeys dhSecret hash "A" sess
      let ivSC_K1:ivSC_K2:_ = deriveKeys dhSecret hash "B" sess
      let ekCS_K1:ekCS_K2:_ = deriveKeys dhSecret hash "C" sess
      let ekSC_K1:ekSC_K2:_ = deriveKeys dhSecret hash "D" sess
      let ikCS_K1:ikCS_K2:_ = deriveKeys dhSecret hash "E" sess
      let ikSC_K1:ikSC_K2:_ = deriveKeys dhSecret hash "F" sess

      bs <- S.receive s 32000 S.msgNoSignal
      print "NEWKEYS"
      print bs

      -- Packet length deciphering with plain chacha20
      ciph1 <- S.receive s 4 S.msgNoSignal
      print "ENCRYPTED PACKET LEN:"
      print ciph1
      let nonce1 = BS.pack [0,0,0,0, 0,0,0,3]
      let st1 = ChaCha.initialize 20 ekCS_K2 nonce1
      let (plain1,_) = ChaCha.combine st1 ciph1
      let len = B.runGet B.getWord32be (LBS.fromStrict plain1)
      print "DECRYPTED PACKET LEN:"
      print len

      -- Packet payload deciphering
      ciph2 <- S.receive s (fromIntegral len) S.msgNoSignal
      print "ENCRYPTED PACKET PAYLOAD:"
      print ciph2
      let CryptoPassed nonce2 = ChaChaPoly1305.nonce8 (BS.pack [0,0,0,0]) (BS.pack [0,0,0,0, 0,0,0,3])
      let CryptoPassed st2 = ChaChaPoly1305.initialize ekCS_K1 nonce2
      let st3 = ChaChaPoly1305.appendAAD ciph1 st2
      let (plain2,st4) = ChaChaPoly1305.decrypt ciph2 st3
      print "DECRYPTED PACKET PAYLOAD:"
      print plain2
      let Poly1305.Auth auth = ChaChaPoly1305.finalize st4
      print "POLY AUTH TAG:"
      print auth

      print "MAC:"
      bs <- S.receive s 512 S.msgNoSignal
      print bs

      --forever $ do
      --  bs <- S.receive s 32000 S.msgNoSignal
      --  print bs

poly1305KeyLen :: Int
poly1305KeyLen = 32

poly1305TagLen :: Int
poly1305TagLen = 16
