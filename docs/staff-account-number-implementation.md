# Staff operational account number implementation

## Scope

The existing staff registration flow remains the single staff-registration system. Tellers and Susu Collectors now receive a generated operational account number while their existing username, password, role, branch, staff ID, and credential lifecycle remain unchanged.

## Generation and persistence

The trusted server gateway generates values using cryptographically secure random integers and role-specific operational prefixes (`SAM-T-######` for Tellers and `SAM-SC-######` for Susu Collectors). The browser may display the read-only field but does not choose or override the value. Existing values are preserved on later edits and credential changes.

The server normalizes every eligible user upsert and generates a number when the record does not already have one. A retry loop handles a unique-constraint collision without overwriting another staff record. The Administrator-only backfill RPC assigns numbers to existing eligible staff who are missing them.

The database migration adds the nullable `"staffAccountNumber"` field to the existing `users` table and creates a partial unique index plus lookup index. Nullable storage allows safe rollout before backfill; eligible staff are filled by the authorized migration/backfill process.

## Display and EOD linkage

The number is displayed in the staff list and read-only staff-registration form, returned in the post-save notification, recorded in EOD reconciliations and cash handovers, shown in Branch Manager oversight, and included in collection, daily cash, teller-closing, and cash-variance reports.

## Security and compatibility

The generation and backfill RPCs are Administrator-only. The number is never derived from passwords, national IDs, usernames, Supabase auth IDs, or sequential database IDs. Authentication continues to use the existing username and password material. Existing staff records, transactions, roles, branches, and credentials are not replaced.

## Verification

The focused staff account-number tests, EOD role tests, Vercel RPC tests, server syntax checks, production build, distribution synchronization, and whitespace checks passed.
