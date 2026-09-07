// zk-threat-exchange :: enterprise-api :: auth
// Author: Ciprian Ștefan Pleșca
//
// A minimal, dependency-free JWT-style token issuer/verifier (HMAC-SHA256)
// plus role-based access control. Deliberately stdlib-only so the
// open/enterprise split has no hidden vendor lock-in in the auth layer;
// swap in a full OIDC/SAML provider for real corporate SSO in production.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidToken = errors.New("invalid or expired token")
var ErrForbidden = errors.New("insufficient role for this operation")

type Role string

const (
	RoleViewer Role = "viewer"
	RoleAnalyst Role = "analyst"
	RoleAdmin  Role = "admin"
)

type Claims struct {
	Subject   string `json:"sub"`
	Org       string `json:"org"`
	Role      Role   `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type TokenIssuer struct {
	secret []byte
}

func NewTokenIssuer(secret string) *TokenIssuer {
	return &TokenIssuer{secret: []byte(secret)}
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Issue creates a signed token for the given subject/org/role, valid for ttl.
func (ti *TokenIssuer) Issue(subject, org string, role Role, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		Subject:   subject,
		Org:       org,
		Role:      role,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	header := map[string]string{"alg": "HS256", "typ": "ZKT"} // ZKT = zk-threat-exchange token
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64URLEncode(headerBytes) + "." + base64URLEncode(claimsBytes)
	sig := ti.sign(unsigned)
	return unsigned + "." + base64URLEncode(sig), nil
}

func (ti *TokenIssuer) sign(unsigned string) []byte {
	mac := hmac.New(sha256.New, ti.secret)
	mac.Write([]byte(unsigned))
	return mac.Sum(nil)
}

// Verify checks the signature and expiry of a token and returns its claims.
func (ti *TokenIssuer) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	unsigned := parts[0] + "." + parts[1]
	expectedSig := ti.sign(unsigned)
	gotSig, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	if subtle.ConstantTimeCompare(expectedSig, gotSig) != 1 {
		return nil, ErrInvalidToken
	}
	claimsBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}

// roleRank gives a strict ordering used for "at least this role" checks.
var roleRank = map[Role]int{
	RoleViewer:  1,
	RoleAnalyst: 2,
	RoleAdmin:   3,
}

// RequireRole returns an error unless claims.Role is at least minRole.
func RequireRole(claims *Claims, minRole Role) error {
	got, ok := roleRank[claims.Role]
	if !ok {
		return fmt.Errorf("%w: unknown role %q", ErrForbidden, claims.Role)
	}
	need, ok := roleRank[minRole]
	if !ok {
		return fmt.Errorf("%w: unknown required role %q", ErrForbidden, minRole)
	}
	if got < need {
		return ErrForbidden
	}
	return nil
}
