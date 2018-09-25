import           Test.Tasty
import           Test.Tasty.QuickCheck as QC

import qualified Spec.Key
import qualified Spec.Message
import qualified Spec.Server.Transport
import qualified Spec.Server.Service.Connection

main :: IO ()
main = defaultMain $ testGroup "Network.SSH"
    [ Spec.Key.tests
    , Spec.Message.tests
    , Spec.Server.Transport.tests
    , Spec.Server.Service.Connection.tests
    ]
