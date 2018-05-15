import           Test.Tasty
import           Test.Tasty.QuickCheck as QC

import qualified Spec.Key
import qualified Spec.Message

main :: IO ()
main = defaultMain $ testGroup "Network.SSH"
    [ Spec.Key.tests
    , Spec.Message.tests
    ]
