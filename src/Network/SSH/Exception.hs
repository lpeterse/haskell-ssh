{-# LANGUAGE DeriveDataTypeable #-}
module Network.SSH.Exception where

import           Control.Exception
import           Data.Typeable

data SshException
  = SshCryptoErrorException String
  | SshSyntaxErrorException String
  | SshProtocolErrorException String
  | SshUnexpectedEndOfInputException
  | SshDisconnectException
  | SshUnimplementedException
  deriving (Eq, Ord, Show, Typeable)

instance Exception SshException
