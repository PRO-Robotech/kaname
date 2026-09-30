// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registry_token

import (
	"context"
	"testing"
	"time"
)

// anonConfig — a Config with anonymous pull ENABLED: a declared public identity
// the registry data-plane resolves to the FGA wildcard AnonymousSubject
// (`user:*`). No user/SA credential is ever presented for the anonymous flow —
// our signer mints for that identity.
func anonConfig() Config {
	return Config{
		AllowedAudiences: []string{"registry.kacho.local"},
		DefaultService:   "registry.kacho.local",
		Anonymous:        AnonymousIdentity{ClientID: "registry-anonymous"},
	}
}

// TestExecuteAnonymous_IssuesReadOnlyPublicBearer — RG-1-B13. A `/token` request
// WITHOUT Basic creds (the docker anon-pull flow) gets a Bearer minted by OUR
// signer whose subject resolves to the public `user:*` principal, requested for
// the registry data-plane audience. NO user credential is validated (anonymous =
// wildcard, not a specific user).
//
// Прежде проба утверждала то же на ветке обмена у внешнего поставщика; ветка
// снята (kaname#494), и свойство утверждается там, где токен теперь выпускается.
// Пол чтения (B14), выключенный поток и отказ чеканки — our_minter_is_required_test.go.
func TestExecuteAnonymous_IssuesReadOnlyPublicBearer(t *testing.T) {
	fixedNow := time.Unix(1_700_000_000, 0)
	m := &fakeMinter{out: MintOutput{AccessToken: "anon-jwt", ExpiresIn: 120}}
	uc := mustUseCase(t, anonConfig(), m).WithClock(func() time.Time { return fixedNow })

	if !uc.AnonymousEnabled() {
		t.Fatal("AnonymousEnabled() = false; want true when an anon identity is configured")
	}

	out, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local")
	if err != nil {
		t.Fatalf("ExecuteAnonymous: %v", err)
	}
	if out.Token != "anon-jwt" || out.ExpiresIn != 120 || out.IssuedAt != fixedNow.Unix() {
		t.Fatalf("out = %+v; want our minted anon bearer relayed", out)
	}
	// The token is minted FOR the declared anon identity — the subject the
	// data-plane resolves to the public AnonymousSubject (`user:*`), NOT a user SA.
	if m.got.Subject != "registry-anonymous" {
		t.Errorf("anon token subject = %q; want the declared anon identity", m.got.Subject)
	}
	// The requested token audience is the registry data-plane service.
	if m.got.Audience != "registry.kacho.local" {
		t.Errorf("anon token aud = %q; want the registry data-plane service", m.got.Audience)
	}
	// Anonymous callers present no transport material — the token stays a bearer.
	if m.got.HasConfirmation() {
		t.Error("anon token carries a binding nobody presented")
	}
	// Contract: the anonymous principal is the FGA wildcard.
	if AnonymousSubject != "user:*" {
		t.Errorf("AnonymousSubject = %q; want the FGA wildcard user:*", AnonymousSubject)
	}
}
