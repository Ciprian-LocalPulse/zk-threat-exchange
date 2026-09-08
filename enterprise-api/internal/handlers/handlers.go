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
	"net/http"
	"sync"
	"time"

	"github.com/cipriansplesca/zk-threat-exchange/enterprise-api/internal/auth"
)

// ThreatCommitment mirrors the public output of core-node's ZKP module: a
// commitment plus a proof, never the underlying witness/log data.
type ThreatCommitment struct {
	Commitment     string    `json:"commitment"`
	NodeID         string    `json:"node_id"`
	ReceivedAt     time.Time `json:"received_at"`
	Corroborations int       `json:"corroborations"`
}

// Server holds the (in-memory, demo-grade) enterprise API state. A real
// deployment would back this with Postgres + the actual core-node gRPC
// client instead of an in-process map.
type Server struct {
	mu          sync.RWMutex
	commitments map[string]*ThreatCommitment
	issuer      *auth.TokenIssuer
	billing     *BillingMeter
}

func NewServer(issuer *auth.TokenIssuer) *Server {
	return &Server{
		commitments: make(map[string]*ThreatCommitment),
		issuer:      issuer,
		billing:     NewBillingMeter(),
	}
}

// BillingMeter tracks usage-based metering: decrypted-verification volume
// and distinct connected nodes, the two dimensions the README's monetization
// model bills on.
type BillingMeter struct {
	mu                 sync.Mutex
	VerificationsTotal int
	nodesSeen          map[string]bool
}

func NewBillingMeter() *BillingMeter {
	return &BillingMeter{nodesSeen: make(map[string]bool)}
}

func (b *BillingMeter) RecordVerification(nodeID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.VerificationsTotal++
	b.nodesSeen[nodeID] = true
}

func (b *BillingMeter) ConnectedNodeCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.nodesSeen)
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
// a customer's core-node instance and stores it for the enterprise dashboard.
// (Analyst role or above.)
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

	s.mu.Lock()
	entry, exists := s.commitments[req.Commitment]
	if exists {
		entry.Corroborations++
	} else {
		entry = &ThreatCommitment{
			Commitment:     req.Commitment,
			NodeID:         req.NodeID,
			ReceivedAt:     time.Now().UTC(),
			Corroborations: 1,
		}
		s.commitments[req.Commitment] = entry
	}
	s.mu.Unlock()

	s.billing.RecordVerification(req.NodeID)
	writeJSON(w, http.StatusOK, entry)
}

// HandleListCommitments returns the current dashboard feed. (Viewer or above.)
func (s *Server) HandleListCommitments(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ThreatCommitment, 0, len(s.commitments))
	for _, c := range s.commitments {
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, out)
}

// HandleBillingSummary exposes the current metering counters used to
// generate an enterprise customer's invoice. (Admin only.)
func (s *Server) HandleBillingSummary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"verifications_total": s.billing.VerificationsTotal,
		"connected_nodes":     s.billing.ConnectedNodeCount(),
	})
}

// HandleHealth is an unauthenticated liveness probe.
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "author": "Ciprian Ștefan Pleșca"})
}
