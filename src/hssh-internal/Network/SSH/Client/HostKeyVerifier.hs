module Network.SSH.Client.HostKeyVerifier where

import Network.SSH.HostAddress
import Network.SSH.Key

type HostKeyVerifier = Host -> PublicKey -> IO Bool

acceptKnownHosts :: HostKeyVerifier
acceptKnownHosts _host _Key = pure True -- FIXME: stub
