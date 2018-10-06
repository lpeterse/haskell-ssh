import           Test.Tasty

import qualified Spec.Key
import qualified Spec.Message
import qualified Spec.Server
import qualified Spec.Server.Service.Connection
import qualified Spec.Server.Service.UserAuth
import qualified Spec.Transport
import qualified Spec.TStreamingQueue

main :: IO ()
main = defaultMain $ testGroup "Network.SSH"
    [ Spec.Key.tests
    , Spec.Message.tests
    , Spec.Server.tests
    , Spec.Server.Service.Connection.tests
    , Spec.Server.Service.UserAuth.tests
    , Spec.Transport.tests
    , Spec.TStreamingQueue.tests
    ]
