ALTER TABLE proposals ADD COLUMN kind TEXT NOT NULL DEFAULT 'general';
ALTER TABLE proposals ADD COLUMN needs_new_capability INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proposals ADD COLUMN capability_request TEXT;
ALTER TABLE proposals ADD COLUMN ai_context_hash TEXT;
ALTER TABLE proposals ADD COLUMN ai_context_excerpt TEXT;

CREATE INDEX idx_proposals_kind ON proposals(kind);
