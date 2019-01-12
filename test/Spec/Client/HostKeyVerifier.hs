module Spec.Client.HostKeyVerifier ( tests ) where
    
import           Control.Concurrent.Async
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519    as Ed25519
import qualified Crypto.PubKey.RSA        as RSA
import qualified Data.ByteString          as BS
import           Data.Default
import qualified Data.List.NonEmpty       as NE
import           Data.List.NonEmpty (NonEmpty (..))

import           Test.Tasty
import           Test.Tasty.HUnit

import           Network.SSH.Key
import           Network.SSH.HostAddress
import           Network.SSH.Client.HostKeyVerifier

import           Spec.Util

tests :: TestTree
tests = testGroup "Network.SSH.Client.HostKeyVerifier"
    [ test01
    ]

test01 :: TestTree
test01 = testCase "keyfile with sinlge ssh-ed25519 key shall match 'localhost'" do
    let xs = parseKnownHostsFile file
    assertEqual "number of entries" 1 (length xs)
    let x = head xs
    assertEqual "number of names" 1 (NE.length $ khNames x)
    let knownName :| _ = khNames x
    assertBool "hmac matches"
        $ matchKnownHostName (HostAddress (Host "localhost") (Port 22)) knownName
    case khPublicKey x of
        PublicKeyEd25519 {} -> pure ()
        _                   -> assertFailure "wrong public key type"
    where
        file :: BS.ByteString
        file = mconcat
            [ "|1|aHrJ4eVXowu9nJG2HF0d1o5VvQY=|X4PozJK2Z9yiaEZVt+AGHA8wB5U= "
            , "ssh-ed25519 "
            , "AAAAC3NzaC1lZDI1NTE5AAAAIMKAnwEHVJhkuSZ/Eomtu/BhDsYLG1/S4hyjvo8pBq2g"
            ]

