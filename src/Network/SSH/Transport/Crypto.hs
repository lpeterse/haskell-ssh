{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE MultiWayIf                #-}
{-# LANGUAGE LambdaCase                #-}
module Network.SSH.Transport.Crypto
    ( KeyStreams (..)
    , EncryptionContext
    , DecryptionContext
    , plainEncryptionContext
    , plainDecryptionContext
    , newChaCha20Poly1305EncryptionContext
    , newChaCha20Poly1305DecryptionContext
    )
where

import           Control.Exception              ( throwIO )
import           Control.Monad                  ( when )
import           Data.Bits                      ( unsafeShiftL, (.|.) )
import           Data.Memory.PtrMethods         ( memCopy, memConstEqual )
import           Data.Monoid                    ( (<>) )
import           Data.Word
import           Foreign.Marshal.Alloc          ( allocaBytes )
import           Foreign.Ptr
import           Foreign.Storable               ( peekByteOff )
import qualified Data.ByteArray                as BA
import qualified Data.ByteString               as BS

import           Network.SSH.Constants
import           Network.SSH.Encoding
import           Network.SSH.Exception
import           Network.SSH.Stream
import qualified Network.SSH.Builder                   as B
import qualified Network.SSH.Transport.Crypto.ChaCha   as ChaChaM
import qualified Network.SSH.Transport.Crypto.Poly1305 as Poly1305M

newtype KeyStreams = KeyStreams (BS.ByteString -> [BA.Bytes])

type DecryptionContext = Word64 -> IO BS.ByteString
type EncryptionContext = Word64 -> B.ByteArrayBuilder -> IO BS.ByteString

plainEncryptionContext :: OutputStream stream => stream -> EncryptionContext
plainEncryptionContext _ _ payload = pure $ runPut $
    B.word32BE (fromIntegral packetLen) <>
    putWord8 (fromIntegral paddingLen) <>
    payload <>
    B.zeroes (fromIntegral paddingLen)
    where
        payloadLen = B.babLength payload
        paddingLen = paddingLenFor payloadLen
        packetLen  = 1 + payloadLen + paddingLen

plainDecryptionContext :: InputStream stream => stream -> DecryptionContext
plainDecryptionContext stream = const $ allocaBytes headerLen $ \headerPtr -> do
    receiveAllUnsafe stream (BA.MemView headerPtr headerLen)
    packetLen <- peekPacketLen headerPtr
    (bsLen, bs) <- BA.allocRet packetLen $ \bsPtr -> do
        receiveAllUnsafe stream (BA.MemView bsPtr packetLen)
        -- the first byte of the packet announces the number of padding bytes
        paddingLen <- fromIntegral <$> (peekByteOff bsPtr 0 :: IO Word8)
        -- RFC: the padding must be >=4 && <= 255
        when (paddingLen < minPaddingLen) (throwIO exceptionInvalidPacket)
        -- the padding must not exceed the packet length
        when (paddingLen + 1 >= packetLen) (throwIO exceptionInvalidPacket)
        -- return the length of the actual message without padding
        pure (packetLen - 1 - paddingLen)
    pure $! BS.take bsLen (BS.drop 1 bs)

newChaCha20Poly1305EncryptionContext ::
    (OutputStream stream, BA.ByteArrayAccess key) =>
    stream -> key -> key -> IO EncryptionContext
newChaCha20Poly1305EncryptionContext _ headerKey mainKey = do
    chaChaState <- ChaChaM.new
    polyState <- Poly1305M.new
    poly64 <- BA.alloc (2 * polyKeyLen) (const $ pure ()) :: IO BA.Bytes
    pure $ \packetsSent plainBuilder -> do
        let plainLen   = B.babLength plainBuilder :: Int
            packetLen  = 1 + plainLen + paddingLen
            paddingLen = paddingLenFor plainLen
        BA.alloc (headerLen + packetLen + macLen) $ \headerPtr -> do
            let macPtr        = plusPtr packetPtr packetLen
                noncePtr      = macPtr
                nonceView     = BA.MemView noncePtr nonceLen
                packetPtr     = plusPtr headerPtr headerLen
                packetBuilder = B.word8 (fromIntegral paddingLen) <> plainBuilder <> B.zeroes paddingLen
            -- Use the MAC area to store the nonce temporarily and
            -- safe an allocation (made up 8% of all allocations in benchmark)
            B.copyToPtr (B.word64BE packetsSent) noncePtr
            -- Header
            ChaChaM.initialize chaChaState chaChaRounds headerKey nonceView
            B.copyToPtr (B.word32BE $ fromIntegral packetLen) headerPtr
            ChaChaM.combineUnsafe chaChaState headerPtr headerPtr headerLen
            -- Packet
            B.copyToPtr packetBuilder packetPtr
            BA.withByteArray poly64 $ \poly64Ptr -> do
                ChaChaM.initialize chaChaState chaChaRounds mainKey nonceView
                ChaChaM.generateUnsafe chaChaState poly64Ptr (2 * polyKeyLen)
                ChaChaM.combineUnsafe chaChaState packetPtr packetPtr packetLen
                -- MAC
                Poly1305M.authUnsafe polyState
                    (BA.MemView poly64Ptr polyKeyLen)
                    (BA.MemView headerPtr $ headerLen + packetLen) macPtr

newChaCha20Poly1305DecryptionContext ::
    InputStream stream => BA.ByteArrayAccess key =>
    stream -> key -> key -> IO DecryptionContext
newChaCha20Poly1305DecryptionContext stream headerKey mainKey = do
    -- The mutable states for ChaCha and Poly1305 are allocated once
    -- per new decryption context. They are re-used for the decryption of
    -- subsequent messages. This is safe as long as the context is used by
    -- only one thread at a time.
    -- Both states get scrubbed on connection loss or after rekeying.
    -- The states do contain secret data while they are alive, but
    -- the ephemeral keys are stored in memory anyway.
    chaChaState <- ChaChaM.new
    polyState <- Poly1305M.new
    -- A piece of memory is allocated once for the lifetime of this
    -- decryption context. It does not contain confidential data and
    -- does not need to be scrubbed.
    temp <- BA.alloc
        (nonceLen + 2 * headerLen + macLen + 2 * polyKeyLen)
        (const $ pure ()) :: IO BA.Bytes
    pure $ \packetsReceived -> BA.withByteArray temp $ \ tempPtr -> do
        let noncePtr       = tempPtr
            nonceView      = BA.MemView noncePtr nonceLen
            headerCryptPtr = noncePtr       `plusPtr` nonceLen
            headerPlainPtr = headerCryptPtr `plusPtr` headerLen
            macTrustedPtr  = headerPlainPtr `plusPtr` headerLen
            polyKeyPtr     = macTrustedPtr  `plusPtr` macLen
        -- Poke the current nonce to the pre-allocated memory location (big-endian).
        -- It is the caller's responsibility to avoid nonce-reuse by timely rekeying.
        B.copyToPtr (B.word64BE packetsReceived) noncePtr
        -- Receive and decrypt the header (packet length).
        -- The encrypted packet header is also needed for integrity check (below).
        receiveAllUnsafe stream (BA.MemView headerCryptPtr headerLen)
        ChaChaM.initialize chaChaState chaChaRounds headerKey (BA.MemView noncePtr nonceLen)
        ChaChaM.combineUnsafe chaChaState headerPlainPtr headerCryptPtr headerLen
        packetLen <- peekPacketLen headerPlainPtr
        -- 64 (2*polyKeyLen) bytes shall be taken from the main key stream of which
        -- the first 32 are used for Poly1305. The other 32 bytes are
        -- not needed, but generated in order to get the correct ChaCha state.
        ChaChaM.initialize chaChaState chaChaRounds mainKey nonceView
        ChaChaM.generateUnsafe chaChaState polyKeyPtr (2 * polyKeyLen)
        -- Receive and authenticate the remaining packet.
        (bsLen, bs) <- BA.allocRet (headerLen + packetLen + macLen) $ \bsPtr -> do
            let packetPtr       = bsPtr     `plusPtr` headerLen
                macUntrustedPtr = packetPtr `plusPtr` packetLen
            -- Copy the ciphered header for inclusion in integrity check.
            memCopy bsPtr headerCryptPtr headerLen
            -- Receive the announced packet len + mac.
            receiveAllUnsafe stream
                (BA.MemView packetPtr (packetLen + macLen))
            Poly1305M.authUnsafe polyState
                (BA.MemView  polyKeyPtr polyKeyLen)         -- authentication key
                (BA.MemView  bsPtr (headerLen + packetLen)) -- authenticated data
                macTrustedPtr                               -- mac destination
            -- CRITICAL: check the message integrity!
            memConstEqual macTrustedPtr macUntrustedPtr macLen >>= \case
                False -> throwIO exceptionMacError
                True  -> do
                    -- decrypt message in-place
                    ChaChaM.combineUnsafe chaChaState packetPtr packetPtr packetLen
                    -- the first byte of the packet announces the number of padding bytes
                    paddingLen <- fromIntegral <$> (peekByteOff packetPtr 0 :: IO Word8)
                    -- RFC: the padding must be >=4 && <= 255
                    when (paddingLen < minPaddingLen) (throwIO exceptionInvalidPacket)
                    -- the padding must not exceed the packet length
                    when (paddingLen + 1 >= packetLen) (throwIO exceptionInvalidPacket)
                    -- return the length of the actual message without padding
                    pure (packetLen - 1 - paddingLen)
        -- The resulting message is a slice of the `BS.ByteString` (without padding and mac).
        -- The header, padding and mac are not confidential and remain in memory until the
        -- whole `BS.ByteString` gets collected. This saves allocations.
        pure $! BS.take bsLen (BS.drop (headerLen + 1) bs)

-------------------------------------------------------------------------------
-- UTIL
-------------------------------------------------------------------------------

headerLen, macLen, nonceLen, polyKeyLen, chaChaRounds, minPaddingLen :: Int
headerLen     = 4
macLen        = 16
nonceLen      = 8
polyKeyLen    = 32
chaChaRounds  = 20
minPaddingLen = 4

paddingLenFor :: Int -> Int
paddingLenFor plainLen =
    if p < minPaddingLen then p + minBlockSize else p
    where
        minBlockSize = 8
        p = minBlockSize - ((1 + plainLen) `mod` minBlockSize)

receiveAllUnsafe :: InputStream stream => stream -> BA.MemView -> IO ()
receiveAllUnsafe stream v@(BA.MemView ptr n)
    | n <= 0 = pure ()
    | otherwise = do
        m <- receiveUnsafe stream v
        when (m <= 0) (throwIO exceptionConnectionLost)
        receiveAllUnsafe stream (BA.MemView (plusPtr ptr m) (n - m))

peekPacketLen :: Ptr Word8 -> IO Int
peekPacketLen ptr = do
    packetLen <- f
        <$> (peekByteOff ptr 0 :: IO Word8)
        <*> (peekByteOff ptr 1 :: IO Word8)
        <*> (peekByteOff ptr 2 :: IO Word8)
        <*> (peekByteOff ptr 3 :: IO Word8)
    -- Any manipulation of the ciphered packet header will
    -- (with extreme likelyhood) result in a huge designated packet size
    -- after decryption. In this case, do not try to receive this packet
    -- and allocate memory for it but throw an exception and disconnect
    -- before even trying to authenticate the packet.
    when (packetLen > fromIntegral maxPacketLength) (throwIO exceptionMacError)
    -- Packet always consists of at least padding size byte, 1 byte payload
    -- and 4 bytes padding.
    when (packetLen < 1 + 1 + 4) (throwIO exceptionMacError)
    pure packetLen
    where
        f h0 h1 h2 h3 = g h0 24 .|. g h1 16 .|. g h2 8 .|. g h3 0
        g w8 = unsafeShiftL (fromIntegral w8)
