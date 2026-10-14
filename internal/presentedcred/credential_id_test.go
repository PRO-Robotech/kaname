// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package presentedcred_test

// credential_id_test.go — идентификатор выпуска ПРОВЕРЕННОГО удостоверения
// доезжает до обработчика носителем `callerorigin` (kaname#669): по нему
// снятие ключа доступа находит текущую сессию вызывающего (Ф13 Р8).

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
)

// credentialIDSeen — что увидел бы обработчик в носителе выпуска.
func credentialIDSeen(t *testing.T, s *stand, with func(context.Context) context.Context) (string, bool, error) {
	t.Helper()
	ctx := with(context.Background())
	var (
		id string
		ok bool
	)
	final := func(c context.Context, _ any) (any, error) {
		id, ok = callerorigin.CredentialIDFrom(c)
		return nil, nil
	}
	_, err := s.reader.UnaryOver(nil)(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.AccessKeyService/Revoke"}, final)
	return id, ok, err
}

// TestPresentedCredentialIDReachesTheHandler — годный токен: носитель несёт
// его `jti`. Близнец, отличный одним фактом, — переданная личность без
// предъявленного токена: носитель пуст.
func TestPresentedCredentialIDReachesTheHandler(t *testing.T) {
	s := newStand(t)
	raw := s.good(t)
	id, ok, err := credentialIDSeen(t, s, func(c context.Context) context.Context {
		return metadata.NewIncomingContext(c, metadata.Pairs(presentedcred.MetadataKey, "Bearer "+raw))
	})
	if err != nil {
		t.Fatalf("годный токен отвергнут: %v", err)
	}
	if !ok || id != "tok-"+testSubject {
		t.Fatalf("выпуск проверенного токена не доехал: %q (носитель=%v), ждали %q", id, ok, "tok-"+testSubject)
	}

	forwarded := operations.Principal{Type: "user", ID: "usr-forwarded", DisplayName: "fwd"}
	id, ok, err = credentialIDSeen(t, s, withTrustedForwarded(forwarded))
	if err != nil {
		t.Fatalf("переданная личность отвергнута: %v", err)
	}
	if ok {
		t.Fatalf("у переданной личности выпуска нет, а носитель назвал %q", id)
	}
}
