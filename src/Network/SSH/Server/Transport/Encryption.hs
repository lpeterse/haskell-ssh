{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Server.Transport.Encryption where

import           Control.Concurrent.STM.TVar
import           Control.Exception              ( throwIO )
import           Control.Monad                  ( when )
import           Control.Monad.STM              ( atomically )
import qualified Crypto.Cipher.ChaCha          as ChaCha
import qualified Crypto.MAC.Poly1305           as Poly1305
import           Data.Bits
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS
import           Data.Monoid                    ( (<>) )

import           Network.SSH.Message
import           Network.SSH.Server.Transport.Internal
import           Network.SSH.Encoding
import           Network.SSH.Constants

setCryptoContexts
    :: Transport -> (EncryptionContext, DecryptionContext) -> IO ()
setCryptoContexts state (encryptionContext, decryptionContext) =
    atomically $ do
        writeTVar (transportEncryptionContextNext state) encryptionContext
        writeTVar (transportDecryptionContextNext state) decryptionContext

plainEncryptionContext :: EncryptionContext
plainEncryptionContext _ plainText = pure $ runPut (putPacked plainText)

plainDecryptionContext :: DecryptionContext
plainDecryptionContext _ getCipherText = do
    paclen <- runGet getWord32 =<< getCipherText 4
    when (paclen > maxPacketLength) $ throwIO $ Disconnect
        DisconnectProtocolError
        "max packet length exceeded"
        mempty
    BS.drop 1 <$> getCipherText (fromIntegral paclen)

chacha20poly1305Context
    :: (BA.ByteArrayAccess key)
    => (BS.ByteString -> [key])
    -> (EncryptionContext, DecryptionContext)
chacha20poly1305Context deriveKeys = (encryptionContext, decryptionContext)
  where
        -- Derive the required encryption/decryption keys.
        -- The integrity keys etc. are not needed with chacha20.
    mainKeyCS : headerKeyCS : _ = deriveKeys "C"
    mainKeySC : headerKeySC : _ = deriveKeys "D"

    -- The sequence number is always the lower 32 bits of the number of
    -- packets received - 1. By specification, it wraps around every 2^32 packets.
    -- Special care must be taken wrt to rekeying as the sequence number
    -- is used as nonce in the ChaCha20Poly1305 encryption mode.
    nonce i =
        BA.pack
            [ 0
            , 0
            , 0
            , 0
            , fromIntegral $ i `shiftR` 24
            , fromIntegral $ i `shiftR` 16
            , fromIntegral $ i `shiftR` 8
            , fromIntegral $ i `shiftR` 0
            ] :: BA.Bytes

    encryptionContext packetsSent plain = pure $ ciph3 <> mac
      where
        plainlen = BA.length plain :: Int
        padlen =
            let p = 8 - ((1 + plainlen) `mod` 8)
            in  if p < 4 then p + 8 else p :: Int
        paclen   = 1 + plainlen + padlen :: Int
        padding  = BA.replicate padlen 0
        padlenBA = BA.singleton (fromIntegral padlen)
        paclenBA = BA.pack
            [ fromIntegral $ paclen `shiftR` 24
            , fromIntegral $ paclen `shiftR` 16
            , fromIntegral $ paclen `shiftR` 8
            , fromIntegral $ paclen `shiftR` 0
            ]
        nonceBA     = nonce packetsSent
        st1         = ChaCha.initialize 20 mainKeySC nonceBA
        st2         = ChaCha.initialize 20 headerKeySC nonceBA
        (poly, st3) = ChaCha.generate st1 64
        ciph1       = fst $ ChaCha.combine st2 paclenBA
        ciph2       = fst $ ChaCha.combine st3 $ padlenBA <> plain <> padding
        ciph3       = ciph1 <> ciph2
        mac         = BA.convert (Poly1305.auth (BS.take 32 poly) ciph3)

    decryptionContext packetsReceived getCipher = do
        paclenCiph <- getCipher 4

        let nonceBA         = nonce packetsReceived
        let ccMain = ChaCha.initialize 20 mainKeyCS nonceBA
        let ccHeader = ChaCha.initialize 20 headerKeyCS nonceBA
        let (poly, ccMain') = ChaCha.generate ccMain 64
        let paclenPlain = fst $ ChaCha.combine ccHeader paclenCiph
        let maclen          = 16
        let paclen =
                fromIntegral (BA.index paclenPlain 0)
                    `shiftL` 24
                    .|.      fromIntegral (BA.index paclenPlain 1)
                    `shiftL` 16
                    .|.      fromIntegral (BA.index paclenPlain 2)
                    `shiftL` 8
                    .|.      fromIntegral (BA.index paclenPlain 3)
                    `shiftL` 0

        pac <- getCipher paclen
        mac <- getCipher maclen

        let authTagReceived = Poly1305.Auth $ BA.convert mac
        let authTagExpected =
                Poly1305.auth (BS.take 32 poly) (paclenCiph <> pac)

        if authTagReceived /= authTagExpected
            then throwIO $ Disconnect DisconnectMacError "" ""
            else do
                let plain = fst (ChaCha.combine ccMain' pac)
                case BS.uncons plain of
                    Nothing -> throwIO $ Disconnect DisconnectProtocolError
                                                    "packet structure"
                                                    ""
                    Just (h, t) ->
                        pure $ BS.take (BS.length t - fromIntegral h) t
