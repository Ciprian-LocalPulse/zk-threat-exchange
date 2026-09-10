// Author: Ciprian Ștefan Pleșca
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Ciprian-LocalPulse/zk-threat-exchange/enterprise-api/internal/auth"
	"github.com/Ciprian-LocalPulse/zk-threat-exchange/enterprise-api/internal/store"
)

// newTestServer connects to the Postgres instance configured via
// DATABASE_URL (see .github/workflows/go-tests.yml's Postgres service
// container in CI) and resets its tables before each test. Skips cleanly
// if no database is configured.
func newTestServer(t *testing.T) (*Server, *auth.TokenIssuer) {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed test (see .github/workflows/go-tests.yml)")
	}
	st, err := store.Open(dbURL)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	if err := st.Reset(); err != nil {
		t.Fatalf("failed to reset store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	issuer := auth.NewTokenIssuer("test-secret")
	return NewServer(issuer, st), issuer
}

func TestHealthIsUnauthenticated(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.HandleHealth(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestIngestRequiresAnalystRole(t *testing.T) {
	s, issuer := newTestServer(t)
	viewerToken, _ := issuer.Issue("u1", "org", auth.RoleViewer, time.Hour)

	body, _ := json.Marshal(ingestRequest{Commitment: "abc123", NodeID: "node-1"})
	req := httptest.NewRequest(http.MethodPost, "/v1/commitments/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	rec := httptest.NewRecorder()

	handler := s.AuthMiddleware(auth.RoleAnalyst, s.HandleIngestCommitment)
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer role, got %d", rec.Code)
	}
}

func TestIngestAndListRoundTrip(t *testing.T) {
	s, issuer := newTestServer(t)
	analystToken, _ := issuer.Issue("u1", "org", auth.RoleAnalyst, time.Hour)

	body, _ := json.Marshal(ingestRequest{Commitment: "commit-xyz", NodeID: "node-a"})
	req := httptest.NewRequest(http.MethodPost, "/v1/commitments/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+analystToken)
	rec := httptest.NewRecorder()
	s.AuthMiddleware(auth.RoleAnalyst, s.HandleIngestCommitment)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ingest failed: %d %s", rec.Code, rec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/commitments", nil)
	listReq.Header.Set("Authorization", "Bearer "+analystToken)
	listRec := httptest.NewRecorder()
	s.AuthMiddleware(auth.RoleViewer, s.HandleListCommitments)(listRec, listReq)

	var results []store.ThreatCommitment
	if err := json.Unmarshal(listRec.Body.Bytes(), &results); err != nil {
		t.Fatalf("could not parse list response: %v", err)
	}
	if len(results) != 1 || results[0].Commitment != "commit-xyz" {
		t.Fatalf("unexpected commitments list: %+v", results)
	}
}

func TestIngestPersistsAcrossServerInstances(t *testing.T) {
	// Regression test for the v0.1.0/v0.2.0 in-memory-map behavior this
	// migration replaces: a commitment ingested by one Server instance
	// must be visible from a brand new Server instance backed by the same
	// database — simulating a service restart or a second replica.
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed test")
	}
	st1, err := store.Open(dbURL)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	if err := st1.Reset(); err != nil {
		t.Fatalf("failed to reset: %v", err)
	}
	issuer := auth.NewTokenIssuer("test-secret")
	server1 := NewServer(issuer, st1)
	analystToken, _ := issuer.Issue("u1", "org", auth.RoleAnalyst, time.Hour)

	body, _ := json.Marshal(ingestRequest{Commitment: "restart-test", NodeID: "node-1"})
	req := httptest.NewRequest(http.MethodPost, "/v1/commitments/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+analystToken)
	rec := httptest.NewRecorder()
	server1.AuthMiddleware(auth.RoleAnalyst, server1.HandleIngestCommitment)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest on server1 failed: %d", rec.Code)
	}
	st1.Close() // simulate the process exiting

	st2, err := store.Open(dbURL)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer st2.Close()
	server2 := NewServer(issuer, st2)

	listReq := httptest.NewRequest(http.MethodGet, "/v1/commitments", nil)
	listReq.Header.Set("Authorization", "Bearer "+analystToken)
	listRec := httptest.NewRecorder()
	server2.AuthMiddleware(auth.RoleViewer, server2.HandleListCommitments)(listRec, listReq)

	var results []store.ThreatCommitment
	if err := json.Unmarshal(listRec.Body.Bytes(), &results); err != nil {
		t.Fatalf("could not parse list response: %v", err)
	}
	if len(results) != 1 || results[0].Commitment != "restart-test" {
		t.Fatalf("commitment did not survive server restart: %+v", results)
	}
}

func TestBillingSummaryRequiresAdmin(t *testing.T) {
	s, issuer := newTestServer(t)
	analystToken, _ := issuer.Issue("u1", "org", auth.RoleAnalyst, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/summary", nil)
	req.Header.Set("Authorization", "Bearer "+analystToken)
	rec := httptest.NewRecorder()
	s.AuthMiddleware(auth.RoleAdmin, s.HandleBillingSummary)(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for analyst on billing endpoint, got %d", rec.Code)
	}
}

func TestBillingSummaryReflectsIngestedVerifications(t *testing.T) {
	s, issuer := newTestServer(t)
	analystToken, _ := issuer.Issue("u1", "org", auth.RoleAnalyst, time.Hour)
	adminToken, _ := issuer.Issue("u2", "org", auth.RoleAdmin, time.Hour)

	for _, c := range []string{"c1", "c2"} {
		body, _ := json.Marshal(ingestRequest{Commitment: c, NodeID: "node-1"})
		req := httptest.NewRequest(http.MethodPost, "/v1/commitments/ingest", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+analystToken)
		rec := httptest.NewRecorder()
		s.AuthMiddleware(auth.RoleAnalyst, s.HandleIngestCommitment)(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ingest %s failed: %d", c, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/summary", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	s.AuthMiddleware(auth.RoleAdmin, s.HandleBillingSummary)(rec, req)

	var summary map[string]float64
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatalf("could not parse billing summary: %v", err)
	}
	if summary["verifications_total"] != 2 {
		t.Fatalf("expected 2 total verifications, got %v", summary["verifications_total"])
	}
	if summary["connected_nodes"] != 1 {
		t.Fatalf("expected 1 connected node, got %v", summary["connected_nodes"])
	}
}
