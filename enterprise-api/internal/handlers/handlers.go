// zk-threat-exchange :: enterprise-api :: handlers
// Author: Ciprian Ștefan Pleșca
//
// REST handlers exposed to paying enterprise customers, sitting in front of
// the open-source core-node/heuristics-engine/rule-mutator stack. This is
// the layer that gets metered for billing (see docstrings below) and wired
// into a customer's SOC (Splunk, CrowdStrike, Sentinel, etc.) via webhooks.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/Ciprian-LocalPulse/zk-threat-exchange/enterprise-api/internal/auth"
	"github.com/Ciprian-LocalPulse/zk-threat-exchange/enterprise-api/internal/store"
)

// Server holds the enterprise API's dependencies. State is persisted in
// PostgreSQL via `store` (see internal/store/store.go) — v0.1.0/v0.2.0 used
// an in-memory map here, which lost all data on every restart.
type Server struct {
	store  *store.Store
	issuer *auth.TokenIssuer
}

func NewServer(issuer *auth.TokenIssuer, st *store.Store) *Server {
	return &Server{store: st, issuer: issuer}
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// AuthMiddleware validates the bearer token and enforces a minimum role.
func (s *Server) AuthMiddleware(minRole auth.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
			tokenStr = tokenStr[7:]
		}
		claims, err := s.issuer.Verify(tokenStr)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized: "+err.Error())
			return
		}
		if err := auth.RequireRole(claims, minRole); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		next(w, r)
	}
}

// HandleIngestCommitment accepts a verified threat commitment forwarded from
// a customer's core-node instance and persists it. (Analyst role or above.)
type ingestRequest struct {
	Commitment string `json:"commitment"`
	NodeID     string `json:"node_id"`
}

func (s *Server) HandleIngestCommitment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if req.Commitment == "" || req.NodeID == "" {
		writeError(w, http.StatusBadRequest, "commitment and node_id are required")
		return
	}

	entry, err := s.store.IngestCommitment(req.Commitment, req.NodeID)
	if err != nil {
		log.Printf("ingest commitment failed: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to store commitment")
		return
	}

	if err := s.store.RecordVerification(req.NodeID); err != nil {
		// A billing-metering write failure shouldn't fail the customer's
		// request — the commitment itself was already safely persisted
		// above. Log it so it's investigable, but don't block the caller.
		log.Printf("record verification failed (commitment was still stored): %v", err)
	}

	writeJSON(w, http.StatusOK, entry)
}

// HandleListCommitments returns the current dashboard feed. (Viewer or above.)
func (s *Server) HandleListCommitments(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListCommitments()
	if err != nil {
		log.Printf("list commitments failed: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to list commitments")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// HandleBillingSummary exposes the current metering counters used to
// generate an enterprise customer's invoice. (Admin only.)
func (s *Server) HandleBillingSummary(w http.ResponseWriter, r *http.Request) {
	total, nodes, err := s.store.BillingSummary()
	if err != nil {
		log.Printf("billing summary failed: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to compute billing summary")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"verifications_total": total,
		"connected_nodes":     nodes,
	})
}

// HandleHealth is an unauthenticated liveness probe.
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "author": "Ciprian Ștefan Pleșca"})
}
