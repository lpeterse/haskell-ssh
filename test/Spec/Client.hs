{-# LANGUAGE OverloadedStrings          #-}
module Spec.Client ( tests ) where

import           Test.Tasty

tests :: TestTree
tests = testGroup "Network.SSH.Client" []
