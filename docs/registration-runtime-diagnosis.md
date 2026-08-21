# Customer registration runtime diagnosis

The generic customer-registration failure is caused by deployment routing, not by the customer fields or login credentials.

The frontend sends authentication and persistence requests to `/api/rpc`. The live production endpoint `https://www.samiciousmicrofinance.online/api/rpc` currently returns `{"error":"not_found"}`, confirming that the deployed site has no reachable serverless RPC handler. The repository already contains `server/index.mjs` with the existing security gateway and `api/rpc.js` as the intended adapter, but production has not exposed that route.

A local static preview reproduced the same generic operation failure during login because `/api/rpc` was unavailable. A direct Supabase call is not a safe substitute: the configured public RPC schema does not expose `rpc_verify_login` directly, and direct browser access would bypass the existing gateway architecture. The correct fix is to deploy the existing gateway adapter at `/api/rpc` and preserve the current secure client-only gateway path.
