# PokerMaster Backend

PostgreSQL Schema, Row-Level Security, and ACID Game Engine RPC Functions for **PokerMaster: No-Limit Texas Hold'em**.

## Supabase Project Details
- **Project Ref:** `hesjadnveduthwxstvdf`
- **Dashboard:** [https://supabase.com/dashboard/project/hesjadnveduthwxstvdf](https://supabase.com/dashboard/project/hesjadnveduthwxstvdf)

## Applying Migrations

### Option 1: Supabase Web SQL Editor (Fastest)
1. Open your Supabase Dashboard -> **SQL Editor**.
2. Click **New query**.
3. Copy the contents of `supabase/migrations/20261010000000_poker_schema_and_engine.sql` and click **Run**.

### Option 2: Automated CI/CD (GitHub Actions)
Add the following repository secrets to your GitHub repository (`pokermaster-backend` -> Settings -> Secrets and variables -> Actions):
- `SUPABASE_ACCESS_TOKEN`
- `SUPABASE_DB_PASSWORD`
- `SUPABASE_PROJECT_ID`: `hesjadnveduthwxstvdf`

Any push to `main` will automatically link and apply migrations.
