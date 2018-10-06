{-# LANGUAGE OverloadedStrings          #-}
module Spec.Server ( tests ) where

import           Test.Tasty

tests :: TestTree
tests = testGroup "Network.SSH.Server" []
