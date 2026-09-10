// zk-threat-exchange :: enterprise-api :: store
// Author: Ciprian Ștefan Pleșca
//
// PostgreSQL-backed persistence for the enterprise API. Replaces the
// original in-memory map + mutex (v0.1.0/v0.2.0) so commitments, dashboard
// data, and billing counters survive a restart or redeploy — a real
// requirement for a service customers pay for and expect an accurate
// invoice from.
//
// PostgreSQL was chosen over SQLite here (unlike core-node, which uses
// embedded SQLite — see core-node/src/memory_pool/) because enterprise-api
// is a multi-tenant service meant to run as a normal horizontally-scalable
// web backend, where a client-server database is the standard, correct
// choice.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// ThreatCommitment mirrors the public output of core-node's ZKP module: a
// commitment plus metadata, never the underlying witness/log data.
type ThreatCommitment struct {
	Commitment     string    `json:"commitment"`
	NodeID         string    `json:"node_id"`
	ReceivedAt     time.Time `json:"received_at"`
	Corroborations int       `json:"corroborations"`
}

type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS commitments (
    commitment     TEXT PRIMARY KEY,
    node_id        TEXT NOT NULL,
    received_at    TIMESTAMPTZ NOT NULL,
    corroborations INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS billing_verifications (
    id          BIGSERIAL PRIMARY KEY,
    node_id     TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_billing_verifications_node_id
    ON billing_verifications (node_id);
`

// Open connects to Postgres at databaseURL, verifies connectivity, and
// applies the (idempotent) schema migration.
func Open(databaseURL string) (*Store, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("apply schema migration: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Reset truncates all tables. Intended for test setup/teardown only — never
// call this against a production database.
func (s *Store) Reset() error {
	_, err := s.db.Exec(`TRUNCATE commitments, billing_verifications RESTART IDENTITY`)
	return err
}

// IngestCommitment records a new commitment, or increments the
// corroboration count if it's already known. Returns the resulting row.
func (s *Store) IngestCommitment(commitment, nodeID string) (*ThreatCommitment, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO commitments (commitment, node_id, received_at, corroborations)
		VALUES ($1, $2, $3, 1)
		ON CONFLICT (commitment) DO UPDATE
			SET corroborations = commitments.corroborations + 1
	`, commitment, nodeID, now)
	if err != nil {
		return nil, fmt.Errorf("ingest commitment: %w", err)
	}

	var result ThreatCommitment
	err = s.db.QueryRow(`
		SELECT commitment, node_id, received_at, corroborations
		FROM commitments WHERE commitment = $1
	`, commitment).Scan(&result.Commitment, &result.NodeID, &result.ReceivedAt, &result.Corroborations)
	if err != nil {
		return nil, fmt.Errorf("read back ingested commitment: %w", err)
	}
	return &result, nil
}

// ListCommitments returns the full dashboard feed, most recently seen first.
func (s *Store) ListCommitments() ([]*ThreatCommitment, error) {
	rows, err := s.db.Query(`
		SELECT commitment, node_id, received_at, corroborations
		FROM commitments
		ORDER BY received_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list commitments: %w", err)
	}
	defer rows.Close()

	out := make([]*ThreatCommitment, 0)
	for rows.Next() {
		var c ThreatCommitment
		if err := rows.Scan(&c.Commitment, &c.NodeID, &c.ReceivedAt, &c.Corroborations); err != nil {
			return nil, fmt.Errorf("scan commitment row: %w", err)
		}
		out = append(out, &c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate commitment rows: %w", err)
	}
	return out, nil
}

// RecordVerification logs one billable verification event for nodeID.
func (s *Store) RecordVerification(nodeID string) error {
	_, err := s.db.Exec(`INSERT INTO billing_verifications (node_id) VALUES ($1)`, nodeID)
	if err != nil {
		return fmt.Errorf("record verification: %w", err)
	}
	return nil
}

// BillingSummary returns the total metered verifications and the count of
// distinct nodes that have ever submitted one — the two dimensions the
// enterprise pricing model bills on (see docs/enterprise_integration.md).
func (s *Store) BillingSummary() (verificationsTotal int, connectedNodes int, err error) {
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM billing_verifications`).Scan(&verificationsTotal); err != nil {
		return 0, 0, fmt.Errorf("count verifications: %w", err)
	}
	if err = s.db.QueryRow(`SELECT COUNT(DISTINCT node_id) FROM billing_verifications`).Scan(&connectedNodes); err != nil {
		return 0, 0, fmt.Errorf("count connected nodes: %w", err)
	}
	return verificationsTotal, connectedNodes, nil
}
