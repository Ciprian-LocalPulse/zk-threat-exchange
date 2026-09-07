// Author: Ciprian Ștefan Pleșca
package auth

import (
	"testing"
	"time"
)

func TestIssueAndVerify(t *testing.T) {
	issuer := NewTokenIssuer("test-secret")
	token, err := issuer.Issue("user-1", "org-a", RoleAnalyst, time.Hour)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	claims, err := issuer.Verify(token)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if claims.Subject != "user-1" || claims.Org != "org-a" || claims.Role != RoleAnalyst {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	issuer := NewTokenIssuer("test-secret")
	token, _ := issuer.Issue("user-1", "org-a", RoleViewer, time.Hour)
	tampered := token + "x"
	if _, err := issuer.Verify(tampered); err == nil {
		t.Fatal("expected tampered token to fail verification")
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	issuer := NewTokenIssuer("test-secret")
	token, _ := issuer.Issue("user-1", "org-a", RoleAdmin, -time.Hour) // already expired
	if _, err := issuer.Verify(token); err == nil {
		t.Fatal("expected expired token to fail verification")
	}
}

func TestRequireRoleHierarchy(t *testing.T) {
	viewerClaims := &Claims{Role: RoleViewer}
	adminClaims := &Claims{Role: RoleAdmin}

	if err := RequireRole(viewerClaims, RoleAdmin); err == nil {
		t.Fatal("viewer should not satisfy admin requirement")
	}
	if err := RequireRole(adminClaims, RoleViewer); err != nil {
		t.Fatalf("admin should satisfy viewer requirement: %v", err)
	}
}

func TestDifferentSecretsRejectEachOther(t *testing.T) {
	issuerA := NewTokenIssuer("secret-a")
	issuerB := NewTokenIssuer("secret-b")
	token, _ := issuerA.Issue("user-1", "org-a", RoleAdmin, time.Hour)
	if _, err := issuerB.Verify(token); err == nil {
		t.Fatal("token signed with a different secret must not verify")
	}
}
