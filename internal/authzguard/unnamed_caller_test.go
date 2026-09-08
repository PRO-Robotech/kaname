// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// unnamed_caller_test.go — тому, кто НЕ НАЗВАЛСЯ, публичный слушатель отвечает
// «назовись», а не «не пускают» (задача продукта #2103, находка Н1 приёмки
// KAN-REST-1).
//
// # Предмет
//
// Отказ существует затем, чтобы вызывающий построил следующий шаг. «Тебя знают
// и не пускают» и «назовись» — РАЗНЫЕ утверждения, и второе на запросе без
// удостоверения ложно: назвавшегося никем никто не знает. Для арендатора чужого
// облака, у которого нашего края нет by construction, отказ по правам не
// восстанавливает ни одного следующего шага — он предлагает просить прав там,
// где просить надо удостоверение.
//
// # Почему это НЕ оракул
//
// Различаются здесь не два состояния СЕРВЕРА, а два состояния ЗАПРОСА, и оба
// известны самому вызывающему ещё до ответа: он либо приложил удостоверение,
// либо нет. Ничего, чего он не знал, ответ ему не сообщает.
//
// Отказ ПРЕДЪЯВИВШЕМУ негодное остаётся ровно тем, чем был: единственным
// побайтово равным текстом без подробностей — там различимость и правда была бы
// оракулом (какая половина предъявленного неверна). Обе половины утверждаются
// ЗДЕСЬ и рядом: проба одной половины зеленела бы на службе, которая отвечает
// одинаково всем.

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
)

// prodPolicy — политика в боевой посадке: именно там пол «проверенный модульный
// сертификат» отвергает вызывающего, и именно там сегодня стоит отказ по правам.
func prodPolicy() *PublicCallerPolicy {
	return NewPublicCallerPolicy(true, PublicPeerCallableRPCs(), nil, bearerPresent)
}

// bearerPresent — реализация порта присутствия удостоверения для проб.
//
// Зовётся ТОТ ЖЕ предикат, что подставляет боевой корень: своя копия разбора
// метаданных разошлась бы с ним молча — на входе, который обе считают годным.
var bearerPresent = presentedcred.Presented

// runPolicy прогоняет запрос через перехватчик политики и отдаёт статус отказа.
func runPolicy(t *testing.T, ctx context.Context, method string) *status.Status {
	t.Helper()
	_, err := prodPolicy().Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
		func(context.Context, any) (any, error) { return nil, nil })
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("отказ не является статусом gRPC: %v", err)
	}
	return st
}

// TestUnnamedCaller_IsToldToIdentifyItself — несущее утверждение половины A.
func TestUnnamedCaller_IsToldToIdentifyItself(t *testing.T) {
	st := runPolicy(t, context.Background(), projectGetMethod)
	if st == nil {
		t.Fatalf("вызывающий, не назвавшийся ничем, прошёл политику — отказа нет вовсе")
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("код отказа безымянному вызывающему = %v, ожидался %v (%q)",
			st.Code(), codes.Unauthenticated, st.Message())
	}
	if st.Message() != UnnamedCallerMessage {
		t.Fatalf("текст отказа = %q, ожидался %q", st.Message(), UnnamedCallerMessage)
	}
	// Следующий шаг обязан быть НАЗВАН, иначе отказ восстанавливает ровно
	// столько же, сколько прежний.
	if !containsAll(st.Message(), presentedcred.MetadataKey, "Bearer") {
		t.Fatalf("текст отказа не называет, ЧЕМ назваться: %q", st.Message())
	}
}

// TestUnnamedCaller_PresentedButNotAcceptedIsUnchanged — половина B, и она
// несущая: без неё половина A зеленела бы на службе, отвечающей всем одинаково.
func TestUnnamedCaller_PresentedButNotAcceptedIsUnchanged(t *testing.T) {
	reader := refusingReader(t)
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(presentedcred.MetadataKey, "Bearer not-a-token"))

	_, err := reader.UnaryOver(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: projectGetMethod},
		func(context.Context, any) (any, error) { return nil, nil })
	st, ok := status.FromError(err)
	if !ok || err == nil {
		t.Fatalf("негодное удостоверение не отвергнуто: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("код отказа предъявившему негодное = %v, ожидался %v", st.Code(), codes.Unauthenticated)
	}
	if st.Message() != presentedcred.RefusalMessage {
		t.Fatalf("текст отказа предъявившему = %q, ожидался единственный объявленный %q",
			st.Message(), presentedcred.RefusalMessage)
	}
	if n := len(st.Proto().GetDetails()); n != 0 {
		t.Fatalf("отказ предъявившему несёт %d подробностей, ожидалось 0", n)
	}
	// Две половины обязаны РАЗЛИЧАТЬСЯ: совпадение текстов означало бы, что
	// половина A ничего не добавила.
	if presentedcred.RefusalMessage == UnnamedCallerMessage {
		t.Fatalf("тексты обеих половин совпали (%q) — различия нет", UnnamedCallerMessage)
	}
}

// TestUnnamedCaller_KnownButNotAdmittedStaysPermissionDenied — положительный
// контроль к половине A. «Тебя знают и не пускают» остаётся отказом по правам:
// вызывающий назвался проверенным модульным сертификатом, и предлагать ему
// назваться значило бы послать его чинить не то.
func TestUnnamedCaller_KnownButNotAdmittedStaysPermissionDenied(t *testing.T) {
	st := runPolicy(t, newStorageCtx(), userTokenIssueMethod)
	if st == nil {
		t.Fatalf("сосед допущен к чеканке личного токена — политика не сработала")
	}
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("код отказа названному, но не допущенному = %v, ожидался %v",
			st.Code(), codes.PermissionDenied)
	}
	if st.Message() != "permission denied" {
		t.Fatalf("текст отказа названному = %q, ожидался прежний %q", st.Message(), "permission denied")
	}
}

// TestUnnamedCaller_PresentedAndAcceptedPassesThrough — второй положительный
// контроль: назвавшийся ПРЕДЪЯВЛЕННЫМ удостоверением проходит, то есть новая
// ветвь не отвергает того, кто назвался не сертификатом.
func TestUnnamedCaller_PresentedAndAcceptedPassesThrough(t *testing.T) {
	ctx := callerorigin.With(context.Background(), callerorigin.PresentedCredential)
	if st := runPolicy(t, ctx, projectGetMethod); st != nil {
		t.Fatalf("арендатор с проверенным удостоверением отвергнут: %v %q", st.Code(), st.Message())
	}
}

// TestUnnamedCaller_PresentedYetUnverifiedIsNotCalledUnnamed — граница ветви.
// Вызывающий ПРИСЛАЛ удостоверение, но читатель его не пометил (читатель не
// провязан либо не дошёл): называть такого «не назвавшимся» нельзя — он назвался,
// и ответ «назовись» послал бы его повторять уже сделанное.
func TestUnnamedCaller_PresentedYetUnverifiedIsNotCalledUnnamed(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(presentedcred.MetadataKey, "Bearer some-token"))
	st := runPolicy(t, ctx, projectGetMethod)
	if st == nil {
		t.Fatalf("непроверенное удостоверение пропущено политикой")
	}
	if st.Code() == codes.Unauthenticated && st.Message() == UnnamedCallerMessage {
		t.Fatalf("предъявившему сказано «назовись» — он уже назвался")
	}
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("код = %v, ожидался %v", st.Code(), codes.PermissionDenied)
	}
}

// containsAll — все подстроки присутствуют.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// refusingReader — читатель предъявленного, отвергающий всё: его предмет здесь
// один — текст отказа предъявившему, и он объявлен самим читателем.
func refusingReader(t *testing.T) *presentedcred.Reader {
	t.Helper()
	mat, err := signingkeygen.Generate(domain.SigningAlgES256)
	if err != nil {
		t.Fatalf("порождение ключа: %v", err)
	}
	r, err := presentedcred.New(presentedcred.Config{
		Issuer:            "https://kaname.unnamed.test",
		Audience:          "kaname-public",
		AllowedAlgorithms: []string{tokenpolicy.AlgES256},
		Keys: staticKeys{keys: []domain.PublishedKey{{
			KID:          domain.KeyID("kaname-unnamed-a"),
			Algorithm:    domain.SigningAlgES256,
			PublicKeyPEM: mat.PublicKeyPEM,
		}}},
		Revocations:        noRevocations{},
		RevocationCacheTTL: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("построение читателя: %v", err)
	}
	return r
}

type staticKeys struct{ keys []domain.PublishedKey }

func (k staticKeys) PublishedSet(context.Context) ([]domain.PublishedKey, error) { return k.keys, nil }

type noRevocations struct{}

func (noRevocations) RevokedBefore(context.Context, string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

var _ = jwt.MapClaims{}
var _ = grpcsrv.NewTrustDomain
