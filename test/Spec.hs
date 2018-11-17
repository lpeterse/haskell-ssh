import           Test.Tasty

import qualified Spec.Algorithms
import qualified Spec.Key
import qualified Spec.Message
import qualified Spec.Server
import qualified Spec.Server.Connection
import qualified Spec.Server.UserAuth
import qualified Spec.Transport
import qualified Spec.TStreamingQueue

main :: IO ()
main = defaultMain $ testGroup "Network.SSH"
    [ Spec.Algorithms.tests
    , Spec.Key.tests
    , Spec.Message.tests
    , Spec.Server.tests
    , Spec.Server.Connection.tests
    , Spec.Server.UserAuth.tests
    , Spec.Transport.tests
    , Spec.TStreamingQueue.tests
    ]
