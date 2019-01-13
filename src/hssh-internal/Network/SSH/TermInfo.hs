module Network.SSH.TermInfo where

import Network.SSH.Message


-- | The `TermInfo` describes the client's terminal settings if it requested a pty.
--
--   NOTE: This will follow in a future release. You may access the constructor
--   through the `Network.SSH.Internal` module, but should not rely on it yet.
data TermInfo = TermInfo PtySettings