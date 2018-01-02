{-# LANGUAGE DeriveDataTypeable #-}
module Network.SSH.Exception where

import           Control.Exception
import           Data.Typeable

data SshException
  = SshMacMismatchException
  | SshSyntaxErrorException String
  | SshProtocolErrorException String
  | SshUnexpectedEndOfInputException
  deriving (Eq, Ord, Show, Typeable)

instance Exception SshException
