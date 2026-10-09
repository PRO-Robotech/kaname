// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recipient_directory_integration_test.go — справочник адресов
// `InternalNotificationRecipientService` (приёмка NTF-3, kacho#2918, Р7, Р28;
// полоса X4D, формы аудитории — редакция 42): половина службы доступа у
// NTF3-25, NTF3-26, NTF3-27, NTF3-28, NTF3-30, NTF3-50, NTF3-119, NTF3-120,
// NTF3-151; условия замысла УК3-07, УК3-08 (половина посева). Форма `event` и
// `ListEventAudience` на мире с поколениями — `audience_fence_integration_test.go`
// (NTF3-23 — TestNTF3173…, отказы входа NTF3-173, NTF3-171).
//
// Сняты вместе с предметом (§4 приёмки, редакция 35): форма `resource` и
// `visible_refs` (NTF3-24, NTF3-118, NTF3-121), `ListProjectAudience`
// (NTF3-117); NTF3-29 — шаблоны notify, не служба доступа.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК ПОСТРОЕНО
//
// Как у пробы K3 (`notification_grant_integration_test.go`): служба собирается
// строителем корня, регистрация — `registerInternalServices`, цепочка —
// `internalUnaryChain` с ключом `authn.service-identity`, рукопожатие — mTLS с
// листом точного SAN; вызывающий — пир по проводу. База — свой клон на
// testcontainers, дверь решения — настоящая, мир G0 — фикстура
// `recipient_directory_fixture_test.go` (судится отдельно,
// TestNTF3X4D_FixtureSelfCheck).
//
// «Вопросов к модели 0» — измерение провода (журнал операторов пула службы:
// операторы, несущие глагол `v_get`, кроме вопроса о праве на сам справочник),
// а не дублёр порта: устройство портов сценария использования проба не
// утверждает. Положительный контроль счёта — rdRequireWireSeesVGet.
package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/corelib/principalwire"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// rdWorld — служба доступа пробы X4D.
type rdWorld struct {
	db   *ntfDB
	door *service.AuthorizeService
	srv  iamv1.InternalNotificationRecipientServiceServer
	lis  *ntfListener
	pki  *ntfPKI
}

// newRDWorld — мир G0 и справочник за внутренним слушателем.
// withDirectoryReader — факт читателя справочника заведён фикстурой (иначе его
// заводит проба посевом, NTF3-50).
func newRDWorld(t *testing.T, withDirectoryReader bool) *rdWorld {
	t.Helper()
	db := newNTFDB(t)
	door, relations := ntfDoor(db)
	// Фикстура судится ДО предмета.
	requireWireSeesDoorQuestions(t, db, door)
	rdSeedG0(t, db, door, withDirectoryReader)
	rdRequireWireSeesVGet(t, db, door)

	// Предмет начинается здесь.
	cfg, err := ntfConfig(t, rdIdentityYAML())
	require.NoError(t, err, "настройка пробы не загрузилась")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := buildRecipientDirectoryServer(db.pool, door, relations, cfg, logger)
	require.NoError(t, err, "справочник не собран")
	chain, err := internalUnaryChain(ntfChainDeps(t, &cfg, db))
	require.NoError(t, err, "цепочка внутреннего слушателя не собрана с перечнем звена Р28 (ResolveSend + методы справочника)")
	w := &rdWorld{db: db, door: door, srv: srv, pki: newNTFPKI(t)}
	w.lis = ntfServe(t, w.pki, chain, func(s grpc.ServiceRegistrar) {
		registerInternalServices(s, &services{recipientDirectoryHandler: srv}, nil, ntfMustConfig(t), nil)
	})
	return w
}

func (w *rdWorld) client(t *testing.T, san string) iamv1.InternalNotificationRecipientServiceClient {
	t.Helper()
	return iamv1.NewInternalNotificationRecipientServiceClient(w.lis.dial(t, san))
}

// resolveAs — `Resolve` пиром san. При отказе ответа нет (адрес не уходит
// вместе с ошибкой).
func (w *rdWorld) resolveAs(t *testing.T, san string, req *iamv1.ResolveRecipientRequest) (*iamv1.ResolveRecipientResponse, error) {
	t.Helper()
	resp, err := w.client(t, san).Resolve(context.Background(), req)
	if err != nil {
		require.Nil(t, resp, "отказ с ответом: адрес не должен уходить вместе с ошибкой")
	}
	return resp, err
}

func (w *rdWorld) resolve(t *testing.T, req *iamv1.ResolveRecipientRequest) (*iamv1.ResolveRecipientResponse, error) {
	t.Helper()
	return w.resolveAs(t, ntfNotifySAN, req)
}

// outcome — исход notify без ошибки.
func (w *rdWorld) outcome(t *testing.T, req *iamv1.ResolveRecipientRequest) *iamv1.ResolveRecipientResponse {
	t.Helper()
	resp, err := w.resolve(t, req)
	require.NoError(t, err, "Resolve(%v) отказал: %v", req, err)
	return resp
}

func (w *rdWorld) audience(t *testing.T, san string, req *iamv1.ListEventAudienceRequest) (*iamv1.ListEventAudienceResponse, error) {
	t.Helper()
	resp, err := w.client(t, san).ListEventAudience(context.Background(), req)
	if err != nil {
		require.Nil(t, resp, "отказ со страницей: субъекты не должны уходить вместе с ошибкой")
	}
	return resp, err
}

// ── построители запроса ─────────────────────────────────────────────────────

// rdEvent — `Resolve{audience = event}` о версии 1 объекта object с токеном в
// форме снимка; у G0 поколений нет, поэтому ответ на принятый вход — барьер.
func rdEvent(ns, subject, object string) *iamv1.ResolveRecipientRequest {
	return &iamv1.ResolveRecipientRequest{
		Namespace: ns, Subject: subject,
		Audience: &iamv1.ResolveRecipientRequest_Event{Event: &iamv1.RecipientEventAudience{
			Object: object, SourceVersion: 1, AuthzRev: rdToken,
			Facts: &iamv1.RecipientEventFacts{ProjectId: "prj-1", AccountId: "acc-1"},
		}},
	}
}

// rdToken — токен версии прав в форме снимка (содержимое здесь не судится).
const rdToken = "1:1:"

// rdEventList — `ListEventAudience` о версии 1 тома vol-1.
func rdEventList() *iamv1.ListEventAudienceRequest {
	return &iamv1.ListEventAudienceRequest{Object: "storage_volume:vol-1", SourceVersion: 1, AuthzRev: rdToken}
}

func rdSelf(ns, subject string) *iamv1.ResolveRecipientRequest {
	return &iamv1.ResolveRecipientRequest{
		Namespace: ns, Subject: subject,
		Audience: &iamv1.ResolveRecipientRequest_Self{Self: &iamv1.RecipientSelfAudience{}},
	}
}

func rdOwner(ns, subject, account string) *iamv1.ResolveRecipientRequest {
	return &iamv1.ResolveRecipientRequest{
		Namespace: ns, Subject: subject,
		Audience: &iamv1.ResolveRecipientRequest_AccountOwner{AccountOwner: &iamv1.RecipientAccountOwnerAudience{AccountId: account}},
	}
}

// rdReader — `Resolve{audience = account_reader}`: вопрос двери `v_get` на аккаунт.
func rdReader(ns, subject, account string) *iamv1.ResolveRecipientRequest {
	return &iamv1.ResolveRecipientRequest{
		Namespace: ns, Subject: subject,
		Audience: &iamv1.ResolveRecipientRequest_AccountReader{
			AccountReader: &iamv1.RecipientAccountReaderAudience{AccountId: account},
		},
	}
}

// rdBase — база G0: `usr-A` читает `account:acc-1` (форма контакта
// безопасности, Р19, Р20) — вопрос двери до адреса.
func rdBase() *iamv1.ResolveRecipientRequest {
	return rdReader("notify", "user:usr-A", "acc-1")
}

func rdRequireAddress(t *testing.T, resp *iamv1.ResolveRecipientResponse, address string) {
	t.Helper()
	require.Equal(t, iamv1.RecipientOutcome_RECIPIENT_OUTCOME_ADDRESS, resp.GetOutcome(), "исход; ответ %v", resp)
	require.Equal(t, address, resp.GetAddress())
}

// rdRequireOutcome — исход по субъекту: без адреса.
func rdRequireOutcome(t *testing.T, resp *iamv1.ResolveRecipientResponse, want iamv1.RecipientOutcome) {
	t.Helper()
	require.Equal(t, want, resp.GetOutcome(), "исход; ответ %v", resp)
	require.Empty(t, resp.GetAddress(), "адрес в ответе на исход %s", want)
}

// rdRequireInvalid — отказ входа: INVALID_ARGUMENT, текст (если задан) и поле.
func rdRequireInvalid(t *testing.T, err error, message, field string) {
	t.Helper()
	require.Error(t, err, "ждали INVALID_ARGUMENT (%q, поле %q)", message, field)
	r := ntfRefusalOf(err)
	require.Equal(t, codes.InvalidArgument.String(), r.code, "код отказа; текст %q", r.message)
	if message != "" {
		require.Equal(t, message, r.message)
	}
	if field != "" {
		require.Contains(t, r.fields, field, "поле нарушения; текст %q", r.message)
	}
}

// measured — вызов в окне журнала: вопросы к модели о `v_get`.
func (w *rdWorld) measured(t *testing.T, req *iamv1.ResolveRecipientRequest) (*iamv1.ResolveRecipientResponse, error, []ntfStatement) {
	t.Helper()
	w.db.wire.reset()
	resp, err := w.resolve(t, req)
	return resp, err, rdModelQuestions(w.db.wire)
}

// ── NTF3-25 · NTF3-26 · NTF3-119 ────────────────────────────────────────────

// TestNTF3X4D_AccountReaderAsksTheDoorBeforeTheAddress — адрес выдаётся после
// вопроса двери о праве получателя (CX3B-14); близнец — субъект без права —
// AUDIENCE_DENIED (NTF3-173 (к) на мире G0).
func TestNTF3X4D_AccountReaderAsksTheDoorBeforeTheAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	resp, err, asked := w.measured(t, rdBase())
	require.NoError(t, err)
	rdRequireAddress(t, resp, "a@example.test")
	require.True(t, rdAsked(asked, "usr-A", "account", "acc-1"),
		"адрес выдан без вопроса {user:usr-A, v_get, account:acc-1} к модели (Check до адреса, CX3B-14)")
	rdRequireOutcome(t, w.outcome(t, rdReader("notify", "user:usr-X", "acc-1")),
		iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED)
}

// TestNTF325_UnconfirmedAddressIsNoConfirmedAddress — половина службы доступа:
// адрес сменён и не подтверждён — `NO_CONFIRMED_ADDRESS`, ни прежнего, ни
// нового адреса в ответе; после подтверждения — новый адрес.
func TestNTF325_UnconfirmedAddressIsNoConfirmedAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdExec(t, w.db, "смена адреса usr-A", `UPDATE kaname.users SET email = 'a2@example.test' WHERE id = 'usr-A'`)
	require.Equal(t, 1, rdCount(t, w.db, `SELECT count(*) FROM kaname.users WHERE id = 'usr-A' AND email_verified_at IS NULL`),
		"фикстура: смена адреса не сбросила отметку подтверждения")
	resp := w.outcome(t, rdBase())
	rdRequireOutcome(t, resp, iamv1.RecipientOutcome_RECIPIENT_OUTCOME_NO_CONFIRMED_ADDRESS)

	rdExec(t, w.db, "подтверждение адреса usr-A", `UPDATE kaname.users SET email_verified_at = now() WHERE id = 'usr-A'`)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a2@example.test")
}

// TestNTF326_ServiceAccountSubjectIsNoConfirmedAddress — защита справочника:
// субъект — учётная запись службы.
func TestNTF326_ServiceAccountSubjectIsNoConfirmedAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireOutcome(t, w.outcome(t, rdSelf("storage", "service_account:sva-1")),
		iamv1.RecipientOutcome_RECIPIENT_OUTCOME_NO_CONFIRMED_ADDRESS)
	rdRequireAddress(t, w.outcome(t, rdSelf("storage", "user:usr-A")), "a@example.test") // близнец user:usr-A
}

func TestNTF3119_InactiveUserHasNoAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireOutcome(t, w.outcome(t, rdReader("notify", "user:usr-blk", "acc-1")),
		iamv1.RecipientOutcome_RECIPIENT_OUTCOME_SUBJECT_INACTIVE)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test")
}

// ── NTF3-27 · NTF3-151: право вызывающего ───────────────────────────────────

// TestNTF327_CallerOtherThanNotifyIsRefused — storage и notify-api по своим
// сертификатам (SAN не ключ таблицы звена): каждый вызов — отказ двери.
func TestNTF327_CallerOtherThanNotifyIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test") // близнец notify
	for _, san := range []string{rdStorageSAN, rdNotifyAPISAN} {
		t.Run(san, func(t *testing.T) {
			_, err := w.resolveAs(t, san, rdBase())
			requireAuthzDenied(t, err)
			_, err = w.audience(t, san, rdEventList())
			requireAuthzDenied(t, err)
		})
	}
}

// TestNTF3151_CloudAdminDoesNotReadAddressesPastTheModel — пересланная личность
// администратора облака на внутреннем слушателе: отказ двери; близнец —
// service:notify.
func TestNTF3151_CloudAdminDoesNotReadAddressesPastTheModel(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test")

	ctx := metadata.AppendToOutgoingContext(context.Background(),
		principalwire.MetaPrincipalType, "user",
		principalwire.MetaPrincipalID, "usr-ca",
		principalwire.MetaTokenACR, "2")
	c := iamv1.NewInternalNotificationRecipientServiceClient(w.lis.dial(t, acrTestGatewaySAN))
	resp, err := c.Resolve(ctx, rdBase())
	require.Nil(t, resp, "адрес ушёл пересланному администратору облака")
	requireAuthzDenied(t, err)
	page, err := c.ListEventAudience(ctx, rdEventList())
	require.Nil(t, page, "субъекты ушли пересланному администратору облака")
	requireAuthzDenied(t, err)
}

// ── NTF3-28 · УК3-07: тип объекта события ───────────────────────────────────

// TestNTF328_UK307_EventObjectTypeIsAnExactMemberOfTheNamespace — тип объекта
// события чужого пространства, с общим началом имени и с хвостом — отказ входа
// с полем `audience.event.object`, вопросов к модели 0. Близнец по одному
// факту — тип своего пространства: вход принят, ответ дальше по пути
// (барьер поколения: у G0 поколений нет) — не отказ входа.
func TestNTF328_UK307_EventObjectTypeIsAnExactMemberOfTheNamespace(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	for _, c := range []struct{ ns, object string }{
		{"storage", "storage_volume:vol-1"},
		{"vpc", "vpc_network:net-1"},
	} {
		_, err := w.resolve(t, rdEvent(c.ns, "user:usr-A", c.object))
		r := ntfRefusalOf(err)
		require.Equal(t, codes.Unavailable.String(), r.code, "близнец %s в %s: вход не принят: %v", c.object, c.ns, err)
		require.Equal(t, "OBJECT_GENERATION_NOT_APPLIED", r.reason)
	}
	for _, object := range []string{
		"vpc_network:net-1",     // NTF3-28: тип чужого пространства
		"storagex_volume:vol-1", // УК3-07: общее начало имени без разделителя
		"storage_volumes:vol-1", // УК3-07: тип пространства с хвостом
		"net-1",                 // NTF3-28: не форма <тип>:<id>
	} {
		t.Run(object, func(t *testing.T) {
			resp, err, asked := w.measured(t, rdEvent("storage", "user:usr-A", object))
			require.Nil(t, resp)
			rdRequireInvalid(t, err, "", "audience.event.object")
			require.Empty(t, asked, "вопрос к модели задан до отказа входа")
		})
	}
}

// ── NTF3-30: только внутренний слушатель ────────────────────────────────────

func TestNTF330_DirectoryIsNotOnTheExternalListener(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test") // близнец: внутренний слушатель

	pub := ntfServe(t, w.pki, nil, func(s grpc.ServiceRegistrar) {
		registerPublicServices(s, &services{recipientDirectoryHandler: w.srv}, nil)
	})
	resp, err := iamv1.NewInternalNotificationRecipientServiceClient(pub.dial(t, ntfNotifySAN)).Resolve(context.Background(), rdBase())
	require.Nil(t, resp)
	require.Equal(t, codes.Unimplemented.String(), ntfRefusalOf(err).code,
		"справочник отвечает на внешнем слушателе: %v", err)
	_, onInternal := w.lis.srv.GetServiceInfo()[rdServiceName]
	require.True(t, onInternal, "контроль: на внутреннем слушателе службы нет")
}

// ── NTF3-50: строка манифеста → читатель справочника ────────────────────────

const (
	rdNotifyManifest = `
apiVersion: iam/v1
module: notify
resources: []
recipientDirectory: {readers: [notify]}
`
	rdStorageManifest = `
apiVersion: iam/v1
module: storage
resources: []
recipientDirectory: {readers: [notify]}
`
)

func TestNTF350_OnlyTheNotifyManifestDeclaresTheDirectoryReader(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, false)
	directoryFacts := func() int {
		return rdCount(t, w.db, `SELECT count(*) FROM kaname.relation_fact WHERE object_type = $1`, rdDirectoryType)
	}
	require.Zero(t, directoryFacts(), "Дано: кортежей справочника нет")

	// Манифест storage со строкой — отвергнут, посев его не применяет.
	_, err := manifest.Load([]byte(rdStorageManifest))
	require.Error(t, err, "строка recipientDirectory манифеста storage принята")
	require.Contains(t, err.Error(), "читатель справочника — только notify")
	require.Zero(t, directoryFacts())
	rdRequireDoor(t, w.door, "service:storage", "reader", rdDirectoryRoot, false)
	_, err = w.resolveAs(t, rdStorageSAN, rdBase())
	requireAuthzDenied(t, err)
	_, err = w.resolve(t, rdBase())
	requireAuthzDenied(t, err) // кортежа нет — и у notify права нет

	// Близнец: манифест notify — ровно один кортеж, Check истинен, Resolve — адрес.
	ntfApply(t, w.db, rdNotifyManifest)
	require.Equal(t, 1, directoryFacts())
	require.Equal(t, 1, ntfFactCount(t, w.db, "service:notify", "reader", rdDirectoryType, "root"))
	rdRequireDoor(t, w.door, "service:notify", "reader", rdDirectoryRoot, true)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test")
}

// ── NTF3-120: аудитории self и account_owner ────────────────────────────────

func TestNTF3120_SelfAndAccountOwnerAudiences(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdSelf("vpc", "user:usr-A")), "a@example.test")
	rdRequireAddress(t, w.outcome(t, rdOwner("notify", "", "acc-1")), "own@example.test")
	rdRequireOutcome(t, w.outcome(t, rdOwner("notify", "", "acc-zzz")), iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED)
	rdRequireOutcome(t, w.outcome(t, rdSelf("vpc", "user:usr-blk")), iamv1.RecipientOutcome_RECIPIENT_OUTCOME_SUBJECT_INACTIVE)

	for _, tc := range []struct {
		name    string
		req     *iamv1.ResolveRecipientRequest
		message string
	}{
		{"(а) account_id пуст", rdOwner("notify", "", ""), "audience.account_owner.account_id: required"},
		{"(б) subject пуст при self", rdSelf("vpc", ""), "subject: required"},
		{"(в) subject при account_owner", rdOwner("notify", "user:usr-A", "acc-1"), "subject: must be empty for audience account_owner"},
		{"без аудитории", &iamv1.ResolveRecipientRequest{Namespace: "vpc", Subject: "user:usr-A"}, "audience: required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err, asked := w.measured(t, tc.req)
			require.Nil(t, resp)
			rdRequireInvalid(t, err, tc.message, "")
			require.Empty(t, asked, "вопросов к модели за отказ входа обязано быть 0")
		})
	}
}

// ── Р28: перечень звена корня знает методы справочника ──────────────────────

// TestNTF3R28_ServiceIdentityPerimeterKnowsTheDirectoryMethods — ключ с тремя
// методами (ResolveSend + методы полосы) собирает цепочку; близнец — ключ с
// опечаткой в имени метода справочника — отказ сборки с именем метода.
func TestNTF3R28_ServiceIdentityPerimeterKnowsTheDirectoryMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	db := newNTFDB(t)
	cfg, err := ntfConfig(t, rdIdentityYAML())
	require.NoError(t, err)
	_, err = internalUnaryChain(ntfChainDeps(t, &cfg, db))
	require.NoError(t, err, "перечень звена {ResolveSend, Resolve, ListEventAudience} отвергнут корнем (Р28)")

	typo := ntfServiceIdentityYAML([]string{ntfResolveSendKey, rdResolveKey[:len(rdResolveKey)-1], rdAudienceKey},
		[][2]string{{ntfNotifySAN, "notify"}})
	cfg2, err := ntfConfig(t, typo)
	require.NoError(t, err)
	_, err = internalUnaryChain(ntfChainDeps(t, &cfg2, db))
	require.Error(t, err, "перечень с опечаткой …/Resolv принят")
	require.Contains(t, err.Error(), rdResolveKey[:len(rdResolveKey)-1])
}
