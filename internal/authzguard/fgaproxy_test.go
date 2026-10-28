// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// fgaproxy_test.go — the FGA-proxy authz ReBAC gate + cert-SAN→SA mapping.
//
// Уровень модуля: ворота посредника модели переводят SAN проверенного
// клиентского сертификата (spiffe://kacho.cloud/ns/<ns>/sa/<учётка>, учётка —
// формы, объявленной пробой: mod-<svc>) в детерминированный идентификатор
// ServiceAccount и спрашивают `service_account:<sva>#fga_writer@cluster:cluster_root`
// через подставленный RelationChecker. Без базы и без живого TLS:
//   - личность сертификата подставляется через grpcsrv.WithCertIdentity;
//   - решение модели прав — поддельным RelationChecker.
//
// Со снятия внешнего движка прав вопрос уходит не чужому хранилищу, а двери
// решения над реляционной формой собственной базы (`authzcascade.Client` поверх
// `relverdict`). Для ЭТОЙ пробы источник ответа безразличен по построению —
// проверяется, как страж распоряжается ответом, — но вид ОТКАЗА источника уже не
// безразличен: он и есть вход двух проб ниже, поэтому берётся из сегодняшнего
// мира, а не из мира снятого движка.
//
// Scenarios:
//
//	valid SAN → resolved to module SA → ReBAC allow → nil.
//	SA without fga_writer relation → PermissionDenied.
//	SAN references unknown SA (no relation) → PermissionDenied (fail-closed).
//	malformed / foreign-trust-domain SAN → PermissionDenied.
//	unverified peer (verified=false) → PermissionDenied (no trust).
//	SA-cert path never consults required_acr_min (no ACR in ctx) → allow.
package authzguard_test

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

// probeServiceNameForm — форма учёток модулей, которой проба объявляет
// установку. Приставка нарочно не та, что стражу прав когда-то вписывали
// литералом: совпавшая проба осталась бы зелёной при вернувшемся литерале.
var probeServiceNameForm = servicesan.NewForm("mod-{service}")

// sva derives the deterministic ServiceAccount id for a module svc-name
// (`'sva' || substr(md5('<учётка>'), 1, 17)`) — учётка в форме пробы, той же
// формулой, что у посева владельца модуля.
// md5 here is an id-derivation function chosen to agree with Postgres `md5()`,
// not a security primitive — the digest guards nothing.
func sva(svc string) string {
	sum := md5.Sum([]byte(probeServiceNameForm.Account(svc)))
	return "sva" + hex.EncodeToString(sum[:])[:17]
}

// fakeChecker records the (subject,relation,object) and returns a canned allow.
// When err is non-nil it is returned verbatim (modelling a source failure: база
// не отвечает / дверь решения собрана без формы), so the gate can distinguish a
// Check that never got an answer from an explicit deny (allowed==false, nil err).
//
// Дублёр НЕ снисходительнее настоящего: единственная его вольность — отвечать
// без базы, а форму ответа он повторяет дословно, включая то, что «ошибка» и
// «нет» — разные исходы (см. authzcascade.Client.Check).
type fakeChecker struct {
	allowSubjects map[string]bool
	err           error
	gotSubject    string
	gotRelation   string
	gotObject     string
}

func (f *fakeChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	f.gotSubject, f.gotRelation, f.gotObject = subject, relation, object
	if f.err != nil {
		return false, f.err
	}
	return f.allowSubjects[subject], nil
}

func TestRelationWriteGate_C01_B07_ValidSANResolvedAndAllowed(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-vpc", true)

	dom, err := gate.Authorize(ctx)
	require.NoError(t, err, "vpc SA with fga_writer relation → allow")
	require.Equal(t, "vpc", dom, "Authorize returns the caller module domain for object-type binding")
	require.Equal(t, "service_account:"+sva("vpc"), chk.gotSubject, "SAN mapped to deterministic sva-id")
	require.Equal(t, "fga_writer", chk.gotRelation)
	// Объект вопроса — платформенный синглтон кластера (kacho#914). Утверждение
	// стоит дословно: гейт, спросивший про ДРУГОЙ объект, задаёт вопрос, на
	// который системная выдача не отвечает, — и отказ выглядел бы честным.
	require.Equal(t, "cluster:cluster_root", chk.gotObject)
}

func TestRelationWriteGate_B08_NoFGAWriterRelationDenied(t *testing.T) {
	// A well-formed module SAN resolves to its deterministic SA id, and ReBAC
	// then denies it: geo holds no fga_writer relation.
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho/sa/mod-geo", true)

	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "no fga_writer relation → PermissionDenied")
}

func TestRelationWriteGate_C03_MalformedOrForeignSANDenied(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	for _, san := range []string{
		"spiffe://other-trust-domain/x",    // foreign trust domain — never extracted
		"spiffe://kacho.cloud/garbage",     // wrong path shape
		"spiffe://kacho.cloud/ns//sa/mod-", // empty segments
		"",                                 // no identity
	} {
		ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), san, true)
		_, err := gate.Authorize(ctx)
		require.Equal(t, codes.PermissionDenied, status.Code(err), "malformed SAN %q → PermissionDenied", san)
	}
}

func TestRelationWriteGate_C05_UnverifiedPeerDenied(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	// Verified=false (TLS peer without verified client-cert) → never trusted.
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-vpc", false)
	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "unverified peer → fail-closed")
}

func TestRelationWriteGate_C02_UnknownSADenied(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	// Well-formed SPIRE SAN, but the resolved SA has no fga_writer relation
	// (unknown / unregistered module) → fail-closed PermissionDenied.
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-unknown", true)
	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRelationWriteGate_B09_NoACRConsulted(t *testing.T) {
	// service→service (mTLS-SA) is exempt from required_acr_min: the gate
	// decision is purely the ReBAC relation; there is no ACR floor in the SA path.
	chk := &fakeChecker{allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	// ctx carries NO acr claim of any kind — must still pass on relation alone.
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-vpc", true)
	_, err := gate.Authorize(ctx)
	require.NoError(t, err, "SA exempt from ACR-floor")
}

func TestRelationWriteGate_D01_DevModeInsecureAllowed(t *testing.T) {
	// Dev-mode (production=false): insecure listener, no verified cert →
	// backward-compat allow. New RPCs must not break dev flow.
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithModuleRoster(writerRoster(t)) // dev-mode default

	ctx := context.Background() // no cert-identity ever set (insecure listener)
	dom, err := gate.Authorize(ctx)
	require.NoError(t, err, "dev-mode insecure → allow (backward-compat)")
	require.Empty(t, dom, "dev-mode (no cert) → empty domain disables object-domain binding")
}

func TestRelationWriteGate_D02_ProdModeAnonymousFailClosed(t *testing.T) {
	// Production-mode: no verified cert (anonymous) → fail-closed.
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	ctx := context.Background()
	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "prod-mode anonymous → fail-closed")
}

// TestRelationWriteGate_I1_BackendFailureIsUnavailable — источник не ответил → Unavailable.
//
// Вопрос, не получивший ответа, — НЕ решение о доступе. Два вида такого исхода, и
// оба берутся из сегодняшнего мира: база службы прав не отвечает (форма читает
// её читающей транзакцией) и дверь решения собрана без формы
// (`authzcascade.ErrFormNotWired`) — последний ЗАМЕЩАЕТ здесь снятый вместе с
// движком `clients.ErrNotConfigured` и означает ровно то же: спросить не у кого.
//
// Схлопывание любого из них в PermissionDenied отравило бы законное намерение в
// очереди регистраций: дренаж читает отказ в правах как ТЕРМИНАЛЬНЫЙ и больше не
// повторяет строку. Страж обязан отдать codes.Unavailable (повторяемо,
// fail-closed): вызывающий повторит, намерение уцелеет.
func TestRelationWriteGate_I1_BackendFailureIsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"база службы прав не отвечает", errors.New("relverdict: транзакция чтения: dial tcp 127.0.0.1:5432: connect: connection refused")},
		{"дверь решения собрана без формы", authzcascade.ErrFormNotWired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A well-formed, verified module cert that resolves to a known SA;
			// the relation WOULD be allowed, but the Check call fails at the
			// backend before any decision can be made.
			chk := &fakeChecker{
				allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true},
				err:           tc.err,
			}
			gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

			ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
				"spiffe://kacho.cloud/ns/platform-system/sa/mod-vpc", true)

			_, err := gate.Authorize(ctx)
			require.Equal(t, codes.Unavailable, status.Code(err),
				"backend Check failure must be Unavailable (retryable), never PermissionDenied — "+
					"else the drainer poisons a legitimate intent")
			// Текст отказа источника НЕ вытекает через стража: ни адрес базы, ни
			// внутреннее имя двери решения вызывающему не адресованы.
			msg := status.Convert(err).Message()
			require.NotContains(t, msg, "relverdict",
				"сырой текст отказа источника не вытекает к вызывающему")
			require.NotContains(t, msg, "authzcascade",
				"внутреннее имя двери решения не вытекает к вызывающему")
			require.NotContains(t, msg, "5432",
				"координата базы не вытекает к вызывающему")
		})
	}
}

// TestRelationWriteGate_I1_ExplicitDenyIsPermissionDenied — explicit deny → PermissionDenied.
//
// The other branch: a successful Check that returns allowed==false is a genuine
// authorization decision (the SA lacks fga_writer). That is PermissionDenied —
// NOT Unavailable — so the caller does not pointlessly retry a real deny.
func TestRelationWriteGate_I1_ExplicitDenyIsPermissionDenied(t *testing.T) {
	// Known SA, Check succeeds (nil err) but returns allowed==false.
	chk := &fakeChecker{allowSubjects: map[string]bool{}} // empty → allowed=false, err=nil
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-vpc", true)

	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"explicit deny (allowed=false, nil err) must be PermissionDenied, not Unavailable")
}

// rosterOf — перечень личностей из тех ИДЕНТИФИКАТОРОВ, которые предъявляют
// пробы: пара берётся разбором самого идентификатора, а не пишется второй раз
// рядом — разойтись предъявленному и объявленному негде. Учётки читает форма
// имени службы проб (probeServiceNameForm, kaname#308).
func rosterOf(t *testing.T, profile moduleidentity.Profile, sans ...string) moduleidentity.Roster {
	t.Helper()
	return rosterOfForm(t, probeServiceNameForm, profile, sans...)
}

// rosterOfForm — тот же перечень под объявленной формой form.
func rosterOfForm(t *testing.T, form servicesan.Form, profile moduleidentity.Profile, sans ...string) moduleidentity.Roster {
	t.Helper()
	d := grpcsrv.NewTrustDomain("kacho.cloud")
	entries := make([]string, 0, len(sans))
	for _, san := range sans {
		ns, account, ok := moduleidentity.ParseSAN(d, san)
		require.True(t, ok, "идентификатор проб %q не разобрался", san)
		entries = append(entries, ns+"/"+account+"="+string(profile))
	}
	r, err := moduleidentity.Parse(form, entries)
	require.NoError(t, err)
	return r
}

// writerRoster — перечень личностей проб посредника (kaname#984): модулем
// признаётся только объявленная пара. `mod-geo` и `mod-unknown` объявлены
// намеренно — их пробы утверждают отказ ОТНОШЕНИЯ, а не признания.
func writerRoster(t *testing.T) moduleidentity.Roster {
	t.Helper()
	return rosterOf(t, moduleidentity.ProfileModuleWriter,
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-vpc",
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-unknown",
		"spiffe://kacho.cloud/ns/kacho/sa/mod-geo",
	)
}

// TestRosterIdentityDerivesTheDeterministicServiceAccountID — признанная
// личность выводит идентификатор служебной учётки тем же производителем, что
// посев: `'sva' || substr(md5('<учётка>'),1,17)`. Своё пространство имён у
// пира — законный случай: сегмент ns приходит из чарта самого пира.
func TestRosterIdentityDerivesTheDeterministicServiceAccountID(t *testing.T) {
	want := map[string]string{
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-vpc":         "vpc",
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-compute":     "compute",
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-nlb":         "nlb",
		"spiffe://kacho.cloud/ns/platform-storage/sa/mod-storage":    "storage",
		"spiffe://kacho.cloud/ns/platform-system/sa/mod-api-gateway": "api-gateway",
	}
	sans := make([]string, 0, len(want))
	for san := range want {
		sans = append(sans, san)
	}
	r := rosterOf(t, moduleidentity.ProfileModuleWriter, sans...)
	d := grpcsrv.NewTrustDomain("kacho.cloud")
	for san, svc := range want {
		id, ok := r.Lookup(d, san)
		require.True(t, ok, "san=%q не признан", san)
		require.Equal(t, svc, id.Service, "san=%q → служба", san)
		require.Equal(t, sva(svc), authzguard.ServiceAccountIDForAccount(id.Account), "san=%q → sva-id", san)
	}
}

// TestRosterIdentityOfAnotherFormDerivesItsIDFromTheWholeAccount — форма имени
// службы приезжает величиной (kaname#308): под ДРУГОЙ объявленной формой
// учётка прежней формы перестаёт быть модулем, а учётка той формы — становится,
// и идентификатор служебной учётки выводится из учётки ЦЕЛИКОМ, с окончанием
// формы, а не из имени службы с приставкой, вписанной в код. Близнец — та же
// учётка под формой, которой она названа.
func TestRosterIdentityOfAnotherFormDerivesItsIDFromTheWholeAccount(t *testing.T) {
	const (
		ofOtherForm = "spiffe://kacho.cloud/ns/platform-system/sa/acme-vpc-sa"
		ofProbeForm = "spiffe://kacho.cloud/ns/platform-system/sa/mod-vpc"
	)
	otherForm := servicesan.NewForm("acme-{service}-sa")
	r := rosterOfForm(t, otherForm, moduleidentity.ProfileModuleWriter, ofOtherForm)
	d := grpcsrv.NewTrustDomain("kacho.cloud")

	id, ok := r.Lookup(d, ofOtherForm)
	require.True(t, ok, "учётка ОБЪЯВЛЕННОЙ формы обязана признаваться")
	require.Equal(t, "vpc", id.Service)
	sum := md5.Sum([]byte("acme-vpc-sa"))
	require.Equal(t, "sva"+hex.EncodeToString(sum[:])[:17], authzguard.ServiceAccountIDForAccount(id.Account),
		"идентификатор выведен не из учётки целиком")

	_, err := moduleidentity.Parse(otherForm, []string{"platform-system/mod-vpc=module-writer"})
	require.Error(t, err, "учётка чужой формы принята записью перечня — перечень читает не объявленную форму")
	_, ok = r.Lookup(d, ofProbeForm)
	require.False(t, ok, "учётка чужой формы признана модулем")
}
