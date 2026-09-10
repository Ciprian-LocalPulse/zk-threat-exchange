// zk-threat-exchange :: enterprise-api :: cmd/server
// Author: Ciprian Ștefan Pleșca
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Ciprian-LocalPulse/zk-threat-exchange/enterprise-api/internal/auth"
	"github.com/Ciprian-LocalPulse/zk-threat-exchange/enterprise-api/internal/handlers"
	"github.com/Ciprian-LocalPulse/zk-threat-exchange/enterprise-api/internal/store"
)

func main() {
	secret := os.Getenv("ZKT_JWT_SECRET")
	if secret == "" {
		secret = "dev-only-secret-change-me" // never use this default in production
		log.Println("WARNING: ZKT_JWT_SECRET not set, using an insecure development default.")
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		// Sensible default for `docker-compose up` (see deployments/docker-compose.yml's
		// postgres service) and for a bare `psql` on localhost during local dev.
		databaseURL = "postgres://postgres:postgres@localhost:5432/zkthreat?sslmode=disable"
		log.Println("WARNING: DATABASE_URL not set, using local-dev default.")
	}

	st, err := store.Open(databaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer st.Close()
	log.Println("connected to database and applied schema migration.")

	issuer := auth.NewTokenIssuer(secret)
	server := handlers.NewServer(issuer, st)

	// Convenience: mint a short-lived admin token on boot in dev mode so the
	// quickstart in README.md works without a separate identity provider.
	if os.Getenv("ZKT_ENV") != "production" {
		token, err := issuer.Issue("dev-user", "local-org", auth.RoleAdmin, 24*time.Hour)
		if err != nil {
			log.Fatalf("failed to mint dev token: %v", err)
		}
		log.Printf("Dev admin token (24h): %s\n", token)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.HandleHealth)
	mux.HandleFunc("/v1/commitments/ingest", server.AuthMiddleware(auth.RoleAnalyst, server.HandleIngestCommitment))
	mux.HandleFunc("/v1/commitments", server.AuthMiddleware(auth.RoleViewer, server.HandleListCommitments))
	mux.HandleFunc("/v1/billing/summary", server.AuthMiddleware(auth.RoleAdmin, server.HandleBillingSummary))

	addr := ":8080"
	log.Printf("zk-threat-exchange enterprise-api listening on %s (author: Ciprian Ștefan Pleșca)\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
