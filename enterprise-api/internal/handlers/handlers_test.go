// Author: Ciprian Ștefan Pleșca
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cipriansplesca/zk-threat-exchange/enterprise-api/internal/auth"
)

func newTestServer() (*Server, *auth.TokenIssuer) {
	issuer := auth.NewTokenIssuer("test-secret")
	return NewServer(issuer), issuer
}

func TestHealthIsUnauthenticated(t *testing.T) {
	s, _ := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.HandleHealth(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestIngestRequiresAnalystRole(t *testing.T) {
	s, issuer := newTestServer()
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
	s, issuer := newTestServer()
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

	var results []ThreatCommitment
	if err := json.Unmarshal(listRec.Body.Bytes(), &results); err != nil {
		t.Fatalf("could not parse list response: %v", err)
	}
	if len(results) != 1 || results[0].Commitment != "commit-xyz" {
		t.Fatalf("unexpected commitments list: %+v", results)
	}
}

func TestBillingSummaryRequiresAdmin(t *testing.T) {
	s, issuer := newTestServer()
	analystToken, _ := issuer.Issue("u1", "org", auth.RoleAnalyst, time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/summary", nil)
	req.Header.Set("Authorization", "Bearer "+analystToken)
	rec := httptest.NewRecorder()
	s.AuthMiddleware(auth.RoleAdmin, s.HandleBillingSummary)(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for analyst on billing endpoint, got %d", rec.Code)
	}
}
