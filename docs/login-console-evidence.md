# Login Console Evidence

The attached 1477×211 landscape console screenshot was tiled into three ordered overlapping horizontal crops and reviewed left-to-right.

The visible warning reads: `processSmsQueue skipped: Error: Your session is no longer valid. Please sign in again.` The stack references `validateRpcRequest` at `https://www.samiciousmicrofinance.online/:9667`, `guardedCallRpc` at `/:9728`, `get` at `/:1358`, `getSyncState` at `/:3119`, `processSmsQueue` at `/:3305`, and an anonymous caller at `/:3357`. The browser console shows three errors in the top-right indicator.

This is consistent with the production login failure being a session-token lifecycle problem after or during authentication, not merely a wrong-password message. The screenshot itself does not expose a Supabase error code or secret.
