import           Test.Tasty

import qualified Spec.Algorithms
import qualified Spec.Client
import qualified Spec.Client.Connection
import qualified Spec.Client.UserAuth
import qualified Spec.Key
import qualified Spec.Message
import qualified Spec.Server
import qualified Spec.Server.Connection
import qualified Spec.Server.UserAuth
import qualified Spec.Transport
import qualified Spec.TWindowBuffer

main :: IO ()
main = defaultMain $ testGroup "Network.SSH"
    [ 
     Spec.Algorithms.tests
    --, Spec.Client.tests
    --, Spec.Client.Connection.tests
    --, Spec.Client.UserAuth.tests
    --, Spec.Key.tests
    --, Spec.Message.tests
    --, Spec.Server.tests
    , Spec.Server.Connection.tests
    --, Spec.Server.UserAuth.tests
    --, Spec.Transport.tests
    , Spec.TWindowBuffer.tests
    ]
