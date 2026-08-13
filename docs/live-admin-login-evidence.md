# Live Administrator Login Evidence

The live production RPC route is reachable: a harmless POST to `/api/rpc` with an unknown operation returned HTTP 403 and `{"error":"rpc_not_allowed"}`, proving the request reaches the gateway instead of Vercel returning 404.

With user confirmation, the live login form was submitted using username `adugyamfi` and the user-confirmed default Administrator credential. The page returned `Could not log in: The operation could not be completed. Please try again.` The browser console view did not expose the upstream error body beyond the client-safe message; the earlier attached screenshot shows a related session cascade: `processSmsQueue skipped: Error: Your session is no longer valid. Please sign in again.`

The current failure is therefore downstream of route existence, most likely the Supabase login material/RPC contract or the default Administrator record/password hash in the production database. The server gateway intentionally redacts the upstream error as `request_rejected`, so local source and production response tracing are required to isolate it without exposing secrets.
