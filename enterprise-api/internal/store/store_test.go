// Author: Ciprian Ștefan Pleșca
package store

import (
	"os"
	"testing"
)

// newTestStore connects to the Postgres instance configured via
// DATABASE_URL (set by .github/workflows/go-tests.yml's Postgres service
// container in CI, or exported manually for local development) and resets
// its tables before each test for isolation. Tests skip cleanly if no
// database is configured, so `go test ./...` still works in an environment
// without Postgres — just without this package's coverage.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed test (see .github/workflows/go-tests.yml)")
	}
	s, err := Open(dbURL)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	if err := s.Reset(); err != nil {
		t.Fatalf("failed to reset store tables: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestIngestCommitmentInsertsNewRow(t *testing.T) {
	s := newTestStore(t)

	entry, err := s.IngestCommitment("commit-abc", "node-1")
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	if entry.Commitment != "commit-abc" || entry.NodeID != "node-1" || entry.Corroborations != 1 {
		t.Fatalf("unexpected entry: %+v", entry)
	}
}

func TestIngestCommitmentCorroboratesOnRepeat(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.IngestCommitment("commit-xyz", "node-a"); err != nil {
		t.Fatalf("first ingest failed: %v", err)
	}
	second, err := s.IngestCommitment("commit-xyz", "node-b")
	if err != nil {
		t.Fatalf("second ingest failed: %v", err)
	}
	if second.Corroborations != 2 {
		t.Fatalf("expected corroborations=2 after second ingest, got %d", second.Corroborations)
	}

	list, err := s.ListCommitments()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected exactly one distinct commitment row, got %d", len(list))
	}
}

func TestListCommitmentsOrdersMostRecentFirst(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.IngestCommitment("commit-1", "node-1"); err != nil {
		t.Fatalf("ingest 1 failed: %v", err)
	}
	if _, err := s.IngestCommitment("commit-2", "node-1"); err != nil {
		t.Fatalf("ingest 2 failed: %v", err)
	}

	list, err := s.ListCommitments()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 commitments, got %d", len(list))
	}
	if list[0].Commitment != "commit-2" {
		t.Fatalf("expected most recent commitment first, got %+v", list[0])
	}
}

func TestBillingSummaryCountsVerificationsAndDistinctNodes(t *testing.T) {
	s := newTestStore(t)

	for _, nodeID := range []string{"node-a", "node-a", "node-b"} {
		if err := s.RecordVerification(nodeID); err != nil {
			t.Fatalf("record verification failed: %v", err)
		}
	}

	total, nodes, err := s.BillingSummary()
	if err != nil {
		t.Fatalf("billing summary failed: %v", err)
	}
	if total != 3 {
		t.Fatalf("expected 3 total verifications, got %d", total)
	}
	if nodes != 2 {
		t.Fatalf("expected 2 distinct nodes, got %d", nodes)
	}
}

func TestStateSurvivesReconnection(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed test")
	}

	s1, err := Open(dbURL)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	if err := s1.Reset(); err != nil {
		t.Fatalf("failed to reset: %v", err)
	}
	if _, err := s1.IngestCommitment("persistent-commit", "node-1"); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	s1.Close() // simulate the service restarting

	s2, err := Open(dbURL)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer s2.Close()

	list, err := s2.ListCommitments()
	if err != nil {
		t.Fatalf("list after reconnect failed: %v", err)
	}
	if len(list) != 1 || list[0].Commitment != "persistent-commit" {
		t.Fatalf("expected commitment to survive reconnection, got %+v", list)
	}
}
