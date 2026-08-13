# Production Login Diagnosis — Initial Findings

## Confirmed live behavior

The production site `https://www.samiciousmicrofinance.online` serves the current login page and includes the password visibility toggle. A direct GET request to `https://www.samiciousmicrofinance.online/api/rpc` returns Vercel `404: NOT_FOUND`, with a Vercel request ID. This confirms that the production deployment currently has no reachable `/api/rpc` function at the path expected by the frontend.

## Repository evidence

The frontend `callRpc()` wrapper posts to `/api/rpc`. The repository contains `server/index.mjs`, which implements the HTTP security gateway and handles `rpc_verify_login`, but the repository has no `api/rpc.js`, `api/rpc.mjs`, or `vercel.json`. `package.json` only defines a Vite static build and a local `start:security-gateway` script; it does not expose a Vercel serverless entrypoint.

The gateway uses server-only `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` environment variables and calls Supabase REST RPCs. The likely root cause is deployment routing: the gateway exists in source but is not packaged under Vercel's `/api` serverless-function convention.
