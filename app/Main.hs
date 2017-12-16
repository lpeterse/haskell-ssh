module Main where

import           Control.Exception              (bracket)
import           Control.Monad                  (forever)
import qualified Crypto.PubKey.Curve25519       as DH
import qualified Data.Binary.Get                as B
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Lazy           as LBS
import           Data.Monoid
import           Network.SSH
import qualified System.Socket                  as S
import qualified System.Socket.Family.Inet6     as S
import qualified System.Socket.Protocol.Default as S
import qualified System.Socket.Type.Stream      as S

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
      S.bind s (S.SocketAddressInet6 S.inet6Any 8080 0 0)
      S.listen s 5
      forever $ bracket (S.accept s) (S.close . fst) serve
    serve (s,addr) = do
      serverSecretKey <- Ed25519.generateSecretKey
      serverPublicKey <- pure $ Ed25519.toPublic serverSecretKey
      ephemeralSecretKey <- Curve25519.generateSecretKey
      ephemeralPublicKey <- pure $ Curve25519.toPublic ephemeralSecretKey

      bs <- S.receive s 4096 S.msgNoSignal
      print $ B.runGet versionParser (LBS.fromStrict bs)
      S.sendAllBuilder s 4096 versionBuilder S.msgNoSignal
      bs <- S.receive s 32000 S.msgNoSignal
      print $ B.runGet (packetParser kexMsgParser) (LBS.fromStrict bs)
      S.sendAllBuilder s 4096 (kexMsgBuilder kexMsg) S.msgNoSignal
      bs <- S.receive s 32000 S.msgNoSignal
      let pubkey = B.runGet (dhKeyExchangeInitParser) (LBS.fromStrict bs)
      print pubkey
      let signature = Ed25519.sign serverSecretKey serverPublicKey (mempty :: BS.ByteString)
      let reply = KexReply {
          serverPublicHostKey      = serverPublicKey
        , serverPublicEphemeralKey = ephemeralPublicKey
        , exchangeHashSignature    = signature
        }
      print reply

      S.sendAllBuilder s 4096 (kexReplyBuilder reply) S.msgNoSignal
      bs <- S.receive s 32000 S.msgNoSignal
      print bs
