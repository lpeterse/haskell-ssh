module Network.SSH.Server.Internal where

import Network.SSH.Message

type Sender              = Message -> IO ()
newtype Continuation   a = Continuation ((Message -> Continuation a -> IO a) -> IO a)
type MessageDispatcher a = Message -> Continuation a -> IO a