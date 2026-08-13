# Vercel Production Environment Evidence

The authenticated Vercel project `samicious-microfinance` is connected to `FRANK12517/samicious-microfinance`, and the Production deployment is marked Ready at commit `65a7da0`.

The project Environment Variables page currently lists only `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY`, both for Production and Preview. No server-only `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, or `SUPABASE_SERVICE_KEY` variable is visible.

The live `/api/rpc` route returns HTTP 503 with `backend_not_configured` for the Administrator login RPC. This matches the gateway’s fail-closed behavior when the server-only Supabase URL or privileged key is missing. The privileged service-role key must be added in Vercel as a server-side Production variable; it must never be placed in the frontend or under a `VITE_` name.
