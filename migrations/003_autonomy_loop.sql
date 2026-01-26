CREATE TABLE identity (
    id INTEGER PRIMARY KEY,
    ts_created TEXT NOT NULL,
    name TEXT NOT NULL,
    notes TEXT
);

CREATE TABLE heartbeats (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    details_json TEXT
);

CREATE INDEX idx_heartbeats_ts ON heartbeats(ts);

CREATE TABLE detections (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    detection_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL,
    event_id INTEGER,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE SET NULL
);

CREATE INDEX idx_detections_ts ON detections(ts);
CREATE INDEX idx_detections_type ON detections(detection_type);

CREATE TABLE decisions (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    detection_id INTEGER,
    observation TEXT NOT NULL,
    reasoning TEXT NOT NULL,
    decision TEXT NOT NULL,
    action_type TEXT,
    action_id INTEGER,
    proposal_id INTEGER,
    restricted_id INTEGER,
    verification_status TEXT,
    evidence_json TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(id) ON DELETE SET NULL,
    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE SET NULL,
    FOREIGN KEY (proposal_id) REFERENCES proposals(id) ON DELETE SET NULL
);

CREATE INDEX idx_decisions_ts ON decisions(ts);

CREATE TABLE outcomes (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    action_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    evidence_json TEXT,
    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE
);

CREATE INDEX idx_outcomes_action_id ON outcomes(action_id);

CREATE TABLE restricted_requests (
    id INTEGER PRIMARY KEY,
    ts_created TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL,
    risk REAL NOT NULL CHECK (risk >= 0.0 AND risk <= 1.0),
    expected_outcome TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','executed','failed','superseded')),
    policy_hash TEXT NOT NULL
);

CREATE INDEX idx_restricted_status_ts ON restricted_requests(status, ts_created);

CREATE TABLE restricted_approvals (
    id INTEGER PRIMARY KEY,
    restricted_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    policy_hash TEXT NOT NULL,
    FOREIGN KEY (restricted_id) REFERENCES restricted_requests(id) ON DELETE CASCADE
);

CREATE INDEX idx_restricted_approvals_ts ON restricted_approvals(restricted_id, ts);

CREATE TABLE briefings (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    period TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE INDEX idx_briefings_ts ON briefings(ts);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    ts_updated TEXT NOT NULL
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX idx_audit_log_ts ON audit_log(ts);
