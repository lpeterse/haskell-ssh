{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Concurrent.Async
import           Control.Concurrent.STM.TChan
import           Control.Exception              (bracket, throwIO)
import           Control.Monad.STM
import qualified Crypto.Cipher.ChaCha           as ChaCha
import qualified Crypto.MAC.Poly1305            as Poly1305
import qualified Crypto.PubKey.Curve25519       as Curve25519
import qualified Crypto.PubKey.Ed25519          as Ed25519
import qualified Data.Binary                    as B
import qualified Data.Binary.Get                as B
import qualified Data.Binary.Put                as B
import qualified Data.ByteArray                 as BA
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Lazy           as LBS
import           Data.Monoid
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
    open        = S.socket :: IO (S.Socket S.Inet6 S.Stream S.Default)
    close       = S.close
    send    s x = S.sendAll s x S.msgNoSignal >> pure ()
    receive s i = S.receive s i S.msgNoSignal
    accept s = do
      S.setSocketOption s (S.ReuseAddress True)
      S.setSocketOption s (S.V6Only False)
      S.bind s (S.SocketAddressInet6 S.inet6Any 22 0 0)
      S.listen s 5
      bracket (S.accept s) (S.close . fst) (\(x,_)-> run exampleHostKey (send x) (receive x))

run :: Ed25519.SecretKey -> (BS.ByteString -> IO ()) -> (Int -> IO BS.ByteString) -> IO ()
run serverSecretKey send receive = do
  let sendPut         = send . LBS.toStrict . B.runPut
  let serverPublicKey = Ed25519.toPublic serverSecretKey

  -- Generate an Ed25519 keypair for elliptic curve Diffie-Hellman
  -- key exchange.
  serverEphemeralSecretKey <- Curve25519.generateSecretKey
  let serverEphemeralPublicKey = Curve25519.toPublic serverEphemeralSecretKey

  -- The maximum length of the version string is 255 chars including CR+LF.
  -- Parsing in chunks of 32 bytes in order to not allocate unnecessarly
  -- much memory. The version string is usually short and transmitted within
  -- a single TCP segment.
  (clientVersion, rem1) <- runGetIncremental B.get (receive 32) mempty

  -- Reply by sending the server version string.
  sendPut $ B.put version

  -- Send KexInit to client.
  serverKexInit <- kexInit <$> newCookie
  sendPut $ packetize $ B.putWord8 20 <> B.put serverKexInit

  -- Receive KexInit from client.
  (clientKexInit, rem2) <- runGetIncremental (unpacketize $ B.getWord8 >> B.get) (receive 4096) rem1

  -- Receive KexEcdhInit from client.
  (KexEcdhInit clientEphemeralPublicKey, rem3) <- runGetIncremental (unpacketize B.get) (receive 4096) rem2

  -- Compute and perform the Diffie-Helman key exchange.
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
  let session = SessionId (BS.pack $ BA.unpack hash)
  let signature = Ed25519.sign serverSecretKey serverPublicKey hash
  let kexEcdhReply = KexEcdhReply {
        kexServerHostKey      = serverPublicKey
      , kexServerEphemeralKey = serverEphemeralPublicKey
      , kexHashSignature      = signature
      }
  sendPut $ packetize $ B.put kexEcdhReply
  sendPut $ packetize $ B.put NewKeys
  (NewKeys, _) <- runGetIncremental (unpacketize B.get) (receive 1) rem3

  -- Derive the required encryption/decryption keys.
  -- The integrity keys etc. are not needed with chacha20.
  let mainKeyCS:headerKeyCS:_ = deriveKeys dhSecret hash "C" session
  let mainKeySC:headerKeySC:_ = deriveKeys dhSecret hash "D" session

  -- Proceed serving the connection in encrypted mode.
  input  <- newTChanIO
  output <- newTChanIO
  let runSender i = do
        msg <- atomically $ readTChan output
        let plain = LBS.toStrict $ B.runPut $ B.put msg
        encryptAndSend i headerKeySC mainKeySC send plain
        runSender (i + 1)
  let runReceiver i = do
        plain <- receiveAndDecrypt i headerKeyCS mainKeyCS receive
        case B.runGetOrFail B.get (LBS.fromStrict plain) of
          Left (_,_,e) -> throwIO (SshSyntaxErrorException e)
          Right (_,_,msg) -> do
            atomically $ writeTChan input msg
            runReceiver (i + 1)
  serve session (readTChan input) (writeTChan output)
    `race_` runSender 3
    `race_` runReceiver 3

runGetIncremental :: B.Get a -> IO BS.ByteString -> BS.ByteString -> IO (a, BS.ByteString)
runGetIncremental getter more initial = case B.runGetIncremental getter of
  B.Done _ _ a       -> pure (a, initial)
  B.Fail _ _ e       -> throwIO (SshSyntaxErrorException e)
  B.Partial continue -> f (continue $ Just initial)
  where
  f (B.Done remainder _ a) = pure (a, remainder)
  f (B.Fail _ _ e        ) = throwIO (SshSyntaxErrorException e)
  f (B.Partial continue  ) = f =<< (continue . nothingIfEmpty <$> more)
  nothingIfEmpty bs
    | BS.null bs = Nothing
    | otherwise  = Just bs

encryptAndSend :: (BA.ByteArrayAccess ba) => Int -> ba -> ba -> (BS.ByteString -> IO ()) -> BS.ByteString -> IO ()
encryptAndSend seqnr headerKey mainKey send datBS = send ciph3 >> send mac
  where
  build         = LBS.toStrict . B.runPut

  datlen        = BS.length datBS                :: Int
  padlen        = let p = 8 - ((1 + datlen) `mod` 8)
                  in  if p < 4 then p + 8 else p :: Int
  paclen        = 1 + datlen + padlen            :: Int

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

receiveAndDecrypt :: (BA.ByteArrayAccess ba) => Int -> ba -> ba -> (Int -> IO BS.ByteString) -> IO BS.ByteString
receiveAndDecrypt seqnr headerKey mainKey receive = do
  ciph1          <- receiveExactly 4
  let paclen      = sizeFromBS (fst $ ChaCha.combine st1 ciph1)
  ciph2          <- receiveExactly paclen
  ciph3          <- receiveExactly maclen
  let actualMAC   = Poly1305.Auth (BA.pack $ BS.unpack ciph3)
  let expectedMAC = Poly1305.auth (BS.take 32 poly) (ciph1 <> ciph2)
  if actualMAC /= expectedMAC
    then throwIO SshMacMismatchException
    else pure $ unpacket $ fst $ ChaCha.combine st3 ciph2
  where
  build         = LBS.toStrict . B.runPut
  sizeFromBS    = fromIntegral . B.runGet B.getWord32be. LBS.fromStrict
  maclen        = 16
  nonceBS       = build $ B.putWord64be (fromIntegral seqnr)
  st1           = ChaCha.initialize 20 headerKey nonceBS
  st2           = ChaCha.initialize 20 mainKey   nonceBS
  (poly, st3)   = ChaCha.generate st2 64

  unpacket :: BS.ByteString -> BS.ByteString
  unpacket bs = case BS.uncons bs of
    Nothing    -> bs
    Just (h,t) -> BS.take (BS.length t - fromIntegral h) t

  receiveExactly :: Int -> IO BS.ByteString
  receiveExactly i = f mempty
    where
    f acc
      | BS.length acc >= i = pure acc
      | otherwise = do
          bs <- receive (i - BS.length acc)
          if BS.null bs
            then throwIO SshUnexpectedEndOfInputException
            else f $! acc <> bs
