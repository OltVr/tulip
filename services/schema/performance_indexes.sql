-- Indexes for Tulip's most common read and retention paths.
--
-- This file is intentionally idempotent so it can be applied both by a fresh
-- Postgres initialization and to an existing Tulip database:
--
--   docker compose exec -T timescale \
--     psql -U tulip -d tulip < services/schema/performance_indexes.sql

-- Flow detail requests and retention both locate flow items by their parent.
-- Keeping id second also supports the time-bounded lookup used by flow_detail.
CREATE INDEX IF NOT EXISTS flow_item_flow_id_id_idx
    ON flow_item (flow_id, id);

-- Retention deletes index text chunks by flow_id. The existing trigram GiST
-- index starts with text and cannot efficiently serve this lookup by itself.
CREATE INDEX IF NOT EXISTS flow_index_flow_id_idx
    ON flow_index (flow_id);

-- The UI normally filters by destination service and asks for newest flows.
-- Put equality columns first and the time-ordered flow id last.
CREATE INDEX IF NOT EXISTS flow_service_time_idx
    ON flow (ip_dst, port_dst, id DESC);
