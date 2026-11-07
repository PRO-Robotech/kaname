// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// fgaproxy_test.go — страж авторизации ReBAC прокси FGA и отображение SAN сертификата в SA.
//
// Модульный уровень: страж прокси FGA разрешает проверенный SAN клиентского сертификата mTLS
// (формат SPIRE spiffe://kacho.cloud/ns/<ns>/sa/kacho-<svc>) в детерминированный
// идентификатор ServiceAccount, затем проверяет ReBAC `service_account:<sva>#fga_writer@
// account:acc_writer_probe` через внедрённый RelationChecker. Без БД и живого TLS:
//   - личность сертификата внедряется через grpcsrv.WithCertIdentity;
//   - решение ReBAC внедряется поддельным RelationChecker.
//
// Со снятия внешнего движка прав вопрос уходит не чужому хранилищу, а двери
// решения над реляционной формой собственной базы (`authzcascade.Client` поверх
// `relverdict`). Для ЭТОЙ пробы источник ответа безразличен по построению —
// проверяется, как страж распоряжается ответом, — но вид ОТКАЗА источника уже не
// безразличен: он и есть вход двух проб ниже, поэтому берётся из сегодняшнего
// мира, а не из мира снятого движка.
//
// Сценарии:
//
// Корректный SAN → служебная учётка модуля → разрешение ReBAC → nil.
// SA без отношения fga_writer → PermissionDenied.
// SAN ссылается на неизвестную SA (нет отношения) → PermissionDenied (безопасный отказ).
// Неверный SAN / чужой домен доверия → PermissionDenied.
// Непроверенный пир (verified=false) → PermissionDenied (нет доверия).
// Путь сертификата SA не спрашивает required_acr_min (нет ACR в ctx) → разрешение.
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
)

// sva выводит детерминированный идентификатор ServiceAccount для имени службы модуля
// (`'sva' || substr(md5('kacho-<svc>'), 1, 17)`), совпадающий с начальной миграцией.
// Здесь md5 — функция вывода идентификатора, выбранная в согласии с Postgres `md5()`,
// а не примитив безопасности: хеш ничего не защищает.
func sva(svc string) string {
	sum := md5.Sum([]byte("kacho-" + svc))
	return "sva" + hex.EncodeToString(sum[:])[:17]
}

// fakeChecker записывает (subject,relation,object) и возвращает заданное разрешение.
// При ненулевом err возвращает его дословно (моделирует сбой источника: база
// не отвечает / дверь решения собрана без формы), чтобы страж различал
// Check без ответа и явный отказ (allowed==false, ошибка nil).
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
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", true)

	dom, err := gate.Authorize(ctx)
	if err == nil {
		err = gate.AuthorizeAccount(ctx, "acc_writer_probe")
	}
	require.NoError(t, err, "vpc SA with fga_writer relation → allow")
	require.Equal(t, "vpc", dom, "Authorize returns the caller module domain for object-type binding")
	require.Equal(t, "service_account:"+sva("vpc"), chk.gotSubject, "SAN mapped to deterministic sva-id")
	require.Equal(t, "fga_writer", chk.gotRelation)
	// Объект вопроса — платформенный синглтон кластера (kacho#914). Утверждение
	// стоит дословно: гейт, спросивший про ДРУГОЙ объект, задаёт вопрос, на
	// который системная выдача не отвечает, — и отказ выглядел бы честным.
	require.Equal(t, "account:acc_writer_probe", chk.gotObject)
}

func TestRelationWriteGate_B08_NoFGAWriterRelationDenied(t *testing.T) {
	// Корректный SAN модуля разрешается в детерминированный идентификатор SA, после чего
	// ReBAC отказывает: у geo нет отношения fga_writer.
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-geo", true)

	err := gate.AuthorizeAccount(ctx, "acc_writer_probe")
	require.Equal(t, codes.PermissionDenied, status.Code(err), "no fga_writer relation → PermissionDenied")
}

func TestRelationWriteGate_C03_MalformedOrForeignSANDenied(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	for _, san := range []string{
		"spiffe://other-trust-domain/x",      // Чужой домен доверия — никогда не извлекается.
		"spiffe://kacho.cloud/garbage",       // Неверная форма пути.
		"spiffe://kacho.cloud/ns//sa/kacho-", // Пустые сегменты.
		"",                                   // Личности нет.
	} {
		ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"), san, true)
		err := gate.AuthorizeAccount(ctx, "acc_writer_probe")
		require.Equal(t, codes.PermissionDenied, status.Code(err), "malformed SAN %q → PermissionDenied", san)
	}
}

func TestRelationWriteGate_C05_UnverifiedPeerDenied(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	// Verified=false (пир TLS без проверенного клиентского сертификата) → никогда не доверяем.
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", false)
	err := gate.AuthorizeAccount(ctx, "acc_writer_probe")
	require.Equal(t, codes.PermissionDenied, status.Code(err), "unverified peer → fail-closed")
}

func TestRelationWriteGate_C02_UnknownSADenied(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	// Корректный SAN SPIRE, но у найденной SA нет отношения fga_writer
	// (неизвестный / незарегистрированный модуль) → безопасный отказ PermissionDenied.
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-unknown", true)
	err := gate.AuthorizeAccount(ctx, "acc_writer_probe")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRelationWriteGate_B09_NoACRConsulted(t *testing.T) {
	// Межсервисный путь (mTLS-SA) освобождён от required_acr_min: решение стража
	// зависит лишь от отношения ReBAC; нижнего предела ACR на пути SA нет.
	chk := &fakeChecker{allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	// ctx НЕ несёт никакого утверждения acr — одного отношения всё равно должно хватить.
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", true)
	err := gate.AuthorizeAccount(ctx, "acc_writer_probe")
	require.NoError(t, err, "SA exempt from ACR-floor")
}

func TestRelationWriteGate_D01_DevModeInsecureAllowed(t *testing.T) {
	// Режим разработки (production=false): незащищённый слушатель, нет проверенного сертификата →
	// разрешение для обратной совместимости. Новые RPC не должны ломать поток разработки.
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithModuleRoster(writerRoster(t)) // Режим разработки по умолчанию.

	ctx := context.Background() // Личность сертификата никогда не задавалась (незащищённый слушатель).
	dom, err := gate.Authorize(ctx)
	if err == nil {
		err = gate.AuthorizeAccount(ctx, "acc_writer_probe")
	}
	require.Equal(t, codes.PermissionDenied, status.Code(err), "registration has no insecure bypass")
	require.Empty(t, dom, "dev-mode (no cert) → empty domain disables object-domain binding")
}

func TestRelationWriteGate_D02_ProdModeAnonymousFailClosed(t *testing.T) {
	// Боевой режим: нет проверенного сертификата (аноним) → безопасный отказ.
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	ctx := context.Background()
	err := gate.AuthorizeAccount(ctx, "acc_writer_probe")
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
			// Корректный проверенный сертификат модуля разрешается в известную SA;
			// отношение БЫЛО БЫ разрешено, но вызов Check падает в
			// хранилище до принятия решения.
			chk := &fakeChecker{
				allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true},
				err:           tc.err,
			}
			gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

			ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
				"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", true)

			err := gate.AuthorizeAccount(ctx, "acc_writer_probe")
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

// TestRelationWriteGate_I1_ExplicitDenyIsPermissionDenied — явный отказ → PermissionDenied.
//
// Другая ветвь: успешный Check с allowed==false — настоящее
// решение авторизации (у SA нет fga_writer). Это PermissionDenied,
// а НЕ Unavailable, чтобы вызывающий бессмысленно не повторял настоящий отказ.
func TestRelationWriteGate_I1_ExplicitDenyIsPermissionDenied(t *testing.T) {
	// Известная SA, Check успешен (ошибка nil), но возвращает allowed==false.
	chk := &fakeChecker{allowSubjects: map[string]bool{}} // Пусто → allowed=false, err=nil.
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true).WithModuleRoster(writerRoster(t))

	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", true)

	err := gate.AuthorizeAccount(ctx, "acc_writer_probe")
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"explicit deny (allowed=false, nil err) must be PermissionDenied, not Unavailable")
}

// rosterOf — перечень личностей из тех ИДЕНТИФИКАТОРОВ, которые предъявляют
// пробы: пара берётся разбором самого идентификатора, а не пишется второй раз
// рядом — разойтись предъявленному и объявленному негде.
func rosterOf(t *testing.T, profile moduleidentity.Profile, sans ...string) moduleidentity.Roster {
	t.Helper()
	d := grpcsrv.NewTrustDomain("kacho.cloud")
	entries := make([]string, 0, len(sans))
	for _, san := range sans {
		ns, account, ok := moduleidentity.ParseSAN(d, san)
		require.True(t, ok, "идентификатор проб %q не разобрался", san)
		entries = append(entries, ns+"/"+account+"="+string(profile))
	}
	r, err := moduleidentity.Parse(entries)
	require.NoError(t, err)
	return r
}

// writerRoster — перечень личностей проб посредника (kaname#984): модулем
// признаётся только объявленная пара. `kacho-geo` и `kacho-unknown` объявлены
// намеренно — их пробы утверждают отказ ОТНОШЕНИЯ, а не признания.
func writerRoster(t *testing.T) moduleidentity.Roster {
	t.Helper()
	return rosterOf(t, moduleidentity.ProfileModuleWriter,
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc",
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-unknown",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-geo",
	)
}

// TestRosterIdentityDerivesTheDeterministicServiceAccountID — признанная
// личность выводит идентификатор служебной учётки тем же производителем, что
// посев: `'sva' || substr(md5('kacho-<svc>'),1,17)`. Своё пространство имён у
// пира — законный случай: сегмент ns приходит из чарта самого пира.
func TestRosterIdentityDerivesTheDeterministicServiceAccountID(t *testing.T) {
	want := map[string]string{
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc":         "vpc",
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-compute":     "compute",
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-nlb":         "nlb",
		"spiffe://kacho.cloud/ns/kacho-storage/sa/kacho-storage":    "storage",
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-api-gateway": "api-gateway",
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
		require.Equal(t, sva(svc), authzguard.ServiceAccountIDForService(id.Service), "san=%q → sva-id", san)
	}
}
