{-# LANGUAGE OverloadedStrings #-}
module Main where

import qualified Data.ByteString as BS
import           Network.SSH.Key

main :: IO ()
main = print $ decodePrivateKeyFile bs

bs :: BS.ByteString
bs  = mconcat
  [ "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  , "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
  , "QyNTUxOQAAACBqcmku9hX4rPO7yC339uHazvqRD/aMgyjq/4exCKGATwAAAJjG8+5kxvPu\n"
  , "ZAAAAAtzc2gtZWQyNTUxOQAAACBqcmku9hX4rPO7yC339uHazvqRD/aMgyjq/4exCKGATw\n"
  , "AAAEBPNkrjYh+rbEcLJEX5w63fHuNLuiw9hJOrOaZRxGqDgWpyaS72Ffis87vILff24drO\n"
  , "+pEP9oyDKOr/h7EIoYBPAAAAE2xwZXRlcnNlbkBnYWxsaWZyZXkBAg==\n"
  , "-----END OPENSSH PRIVATE KEY-----\n"
  ]
