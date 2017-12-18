{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Exception              (bracket)
import           Control.Monad                  (forever)
import qualified Crypto.PubKey.Curve25519       as DH
import qualified Data.Binary.Get                as B
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Builder        as BS
import qualified Data.ByteString.Lazy           as LBS
import           Data.Monoid
import           Network.SSH
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S

import qualified Crypto.Cipher.ChaChaPoly1305   as ChaChaPoly1305
import qualified Crypto.Hash                    as Hash
import qualified Crypto.Hash.Algorithms         as Hash
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
      forever $ bracket (S.accept s) (S.close . fst) serve
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

      let signature = Ed25519.sign serverSecretKey serverPublicKey hash
      let reply = KexReply {
          serverPublicHostKey      = serverPublicKey
        , serverPublicEphemeralKey = serverEphemeralPublicKey
        , exchangeHashSignature    = signature
        }
      print reply
      S.sendAllBuilder s 4096 (packetize $ kexReplyBuilder reply) S.msgNoSignal

      S.sendAllBuilder s 4096 (packetize $ newKeysBuilder) S.msgNoSignal

      let ivCS_1    = deriveKey  dhSecret hash hash "A"
      let ivCS_2    = deriveKey' dhSecret hash ivCS_1
      let ivSC_1    = deriveKey  dhSecret hash hash "B"
      let ivSC_2    = deriveKey' dhSecret hash ivSC_1
      let ekCS      = deriveKey  dhSecret hash hash "C"
      let ekSC      = deriveKey  dhSecret hash hash "D"
      let ikCS      = deriveKey  dhSecret hash hash "E"
      let ikSC      = deriveKey  dhSecret hash hash "F"

      --nonce        <- ChaChaPoly1305.nonce12
      --cryptoState1 <- ChaChaPoly1305.initialize dhSecret

      forever $ do
        bs <- S.receive s 32000 S.msgNoSignal
        print bs
