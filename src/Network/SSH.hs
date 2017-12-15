module Network.SSH where

import qualified Data.Binary.Get as B

data Packet
  = Packet
  { packetLength :: Word32
  , paddingLength :: Word8

clientVersionParser :: B.Get B.ByteString
clientVersionParser = do
  magic <- B.getWord64be
  if magic /= 0x5353482d322e302d -- "SSH-2.0-"
    then stop
    else untilCRLF 0 []
  where
    stop
      = fail "syntax error"
    untilCRLF !i !xs
      = if i >= 255
        then stop
        else B.getWord8 >>= \case
          0x0d -> B.getWord8 >>= \case
            0x0a -> pure $ B.pack (reverse xs)
            _    -> stop
          x -> untilCRLF (i+1) (x:xs)
