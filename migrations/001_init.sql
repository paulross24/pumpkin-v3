CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    severity TEXT NOT NULL
);

CREATE INDEX idx_events_ts ON events(ts);

CREATE TABLE proposals (
    id INTEGER PRIMARY KEY,
    ts_created TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL,
    risk REAL NOT NULL CHECK (risk >= 0.0 AND risk <= 1.0),
    expected_outcome TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'pending',
        'approved',
        'rejected',
        'executed',
        'failed',
        'superseded'
    )),
    policy_hash TEXT NOT NULL
);

CREATE INDEX idx_proposals_status_ts ON proposals(status, ts_created);

CREATE TABLE proposal_events (
    proposal_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (proposal_id, event_id),
    FOREIGN KEY (proposal_id) REFERENCES proposals(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE INDEX idx_proposal_events_proposal_id ON proposal_events(proposal_id);
CREATE INDEX idx_proposal_events_event_id ON proposal_events(event_id);

CREATE TABLE approvals (
    id INTEGER PRIMARY KEY,
    proposal_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    policy_hash TEXT NOT NULL,
    FOREIGN KEY (proposal_id) REFERENCES proposals(id) ON DELETE CASCADE
);

CREATE INDEX idx_approvals_proposal_ts ON approvals(proposal_id, ts);

CREATE TABLE actions (
    id INTEGER PRIMARY KEY,
    proposal_id INTEGER,
    ts_started TEXT NOT NULL,
    ts_finished TEXT,
    action_type TEXT NOT NULL,
    params_json TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT,
    policy_hash TEXT NOT NULL,
    FOREIGN KEY (proposal_id) REFERENCES proposals(id) ON DELETE SET NULL
);

CREATE INDEX idx_actions_proposal_ts ON actions(proposal_id, ts_started);

CREATE TABLE memory (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    ts_updated TEXT NOT NULL
);

CREATE TABLE policy_snapshots (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    policy_path TEXT NOT NULL,
    policy_excerpt TEXT
);
