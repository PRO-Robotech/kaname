// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recipient_directory_integration_test.go — справочник адресов
// `InternalNotificationRecipientService` (приёмка NTF-3, kacho#2918, Р7, Р28;
// полоса X4D: `Resolve`, `ListProjectAudience`; `ListExpiringCredentials` вне
// полосы по Д96). Сценарии: NTF3-23 (близнец), половина службы доступа у
// NTF3-24 и NTF3-25, NTF3-26…30, NTF3-50, NTF3-117…121, NTF3-151; условия
// замысла УК3-07, УК3-08 (половина посева).
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
//
// ─────────────────────────────────────────────────────────────────────────────
// КОНТРАКТ, КОТОРЫЙ ЗАДАЁТ ЭТА ПРОБА (полоса RED, до реализации)
//
//	proto/kaname/cloud/iam/v1/<новый файл>.proto, пакет kaname.cloud.iam.v1:
//
//	service InternalNotificationRecipientService {      // без HTTP-привязки
//	  rpc Resolve (ResolveRecipientRequest) returns (ResolveRecipientResponse);
//	  rpc ListProjectAudience (ListProjectAudienceRequest) returns (ListProjectAudienceResponse);
//	}
//	message RecipientResourceRef { string type = 1; string id = 2; }
//	message RecipientResourceAudience { repeated RecipientResourceRef resource_refs = 1; string relation = 2; }
//	message RecipientSelfAudience {}
//	message RecipientAccountOwnerAudience { string account_id = 1; }
//	message ResolveRecipientRequest {
//	  string namespace = 1;
//	  string subject = 2;
//	  oneof audience {
//	    RecipientResourceAudience resource = 3;
//	    RecipientSelfAudience self = 4;
//	    RecipientAccountOwnerAudience account_owner = 5;
//	  }
//	}
//	enum RecipientOutcome {
//	  RECIPIENT_OUTCOME_UNSPECIFIED = 0; RECIPIENT_OUTCOME_ADDRESS = 1;
//	  RECIPIENT_OUTCOME_SUBJECT_NOT_FOUND = 2; RECIPIENT_OUTCOME_SUBJECT_INACTIVE = 3;
//	  RECIPIENT_OUTCOME_AUDIENCE_DENIED = 4; RECIPIENT_OUTCOME_NO_CONFIRMED_ADDRESS = 5;
//	}
//	message ResolveRecipientResponse {
//	  RecipientOutcome outcome = 1; string address = 2; repeated RecipientResourceRef visible_refs = 3;
//	}
//	message ListProjectAudienceRequest { string project_id = 1; string page_token = 2; int32 page_size = 3; }
//	message ListProjectAudienceResponse { repeated string subjects = 1; string next_page_token = 2; }
//
//	func buildRecipientDirectoryServer(pool *pgxpool.Pool, door *service.AuthorizeService,
//	    relations *authzcascade.Client, cfg config.Config, logger *slog.Logger,
//	) (iamv1.InternalNotificationRecipientServiceServer, error)
//
//	services.recipientDirectoryHandler iamv1.InternalNotificationRecipientServiceServer
//	    — регистрирует `registerInternalServices`; `registerPublicServices` — нет;
//
//	закрытый перечень звена корня (`serviceIdentityMethods`) знает `Resolve` и
//	`ListProjectAudience` (Р28).
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
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

func (w *rdWorld) audience(t *testing.T, san string, req *iamv1.ListProjectAudienceRequest) (*iamv1.ListProjectAudienceResponse, error) {
	t.Helper()
	resp, err := w.client(t, san).ListProjectAudience(context.Background(), req)
	if err != nil {
		require.Nil(t, resp, "отказ со страницей: субъекты не должны уходить вместе с ошибкой")
	}
	return resp, err
}

// ── построители запроса ─────────────────────────────────────────────────────

func rdRef(typ, id string) *iamv1.RecipientResourceRef {
	return &iamv1.RecipientResourceRef{Type: typ, Id: id}
}

func rdVol(id string) *iamv1.RecipientResourceRef { return rdRef("storage_volume", id) }

func rdResource(ns, subject, relation string, refs ...*iamv1.RecipientResourceRef) *iamv1.ResolveRecipientRequest {
	return &iamv1.ResolveRecipientRequest{
		Namespace: ns, Subject: subject,
		Audience: &iamv1.ResolveRecipientRequest_Resource{Resource: &iamv1.RecipientResourceAudience{
			ResourceRefs: refs, Relation: relation,
		}},
	}
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

// rdBase — база NTF3-23: `usr-A`, `vol-1`, `v_get`.
func rdBase() *iamv1.ResolveRecipientRequest {
	return rdResource("storage", "user:usr-A", "v_get", rdVol("vol-1"))
}

func rdIDs(refs []*iamv1.RecipientResourceRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.GetType()+":"+r.GetId())
	}
	return out
}

func rdRequireAddress(t *testing.T, resp *iamv1.ResolveRecipientResponse, address string, visible ...string) {
	t.Helper()
	require.Equal(t, iamv1.RecipientOutcome_RECIPIENT_OUTCOME_ADDRESS, resp.GetOutcome(), "исход; ответ %v", resp)
	require.Equal(t, address, resp.GetAddress())
	if visible != nil {
		require.Equal(t, visible, rdIDs(resp.GetVisibleRefs()), "видимое подмножество ссылок")
	}
}

// rdRequireOutcome — исход по субъекту: ни адреса, ни видимых ссылок.
func rdRequireOutcome(t *testing.T, resp *iamv1.ResolveRecipientResponse, want iamv1.RecipientOutcome) {
	t.Helper()
	require.Equal(t, want, resp.GetOutcome(), "исход; ответ %v", resp)
	require.Empty(t, resp.GetAddress(), "адрес в ответе на исход %s", want)
	require.Empty(t, resp.GetVisibleRefs(), "видимые ссылки в ответе на исход %s", want)
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

// ── NTF3-23 · NTF3-24 · NTF3-25 · NTF3-26 · NTF3-119 · NTF3-121 ─────────────

func TestNTF323_DirectoryReturnsTheConfirmedAddressOfAReader(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	resp, err, asked := w.measured(t, rdBase())
	require.NoError(t, err)
	rdRequireAddress(t, resp, "a@example.test", "storage_volume:vol-1")
	require.True(t, rdAsked(asked, "usr-A", "storage_volume", "vol-1"),
		"адрес выдан без вопроса {user:usr-A, v_get, storage_volume:vol-1} к модели (Check до адреса, CX3B-14)")
}

// TestNTF324_ReadRightRemovedBeforeSendIsAudienceDenied — половина службы
// доступа: право чтения снято (снятие видно дверью) — `AUDIENCE_DENIED`.
func TestNTF324_ReadRightRemovedBeforeSendIsAudienceDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test", "storage_volume:vol-1") // близнец
	rdExec(t, w.db, "снятие права", `DELETE FROM kaname.relation_fact
		WHERE object_type = 'storage_volume' AND object_id = 'vol-1' AND relation = 'v_get' AND subject = 'user:usr-A'`)
	rdRequireDoor(t, w.door, "user:usr-A", "v_get", "storage_volume:vol-1", false)
	rdRequireOutcome(t, w.outcome(t, rdBase()), iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED)
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
	rdRequireAddress(t, w.outcome(t, rdBase()), "a2@example.test", "storage_volume:vol-1")
}

// TestNTF326_ServiceAccountSubjectIsNoConfirmedAddress — защита справочника:
// субъект — учётная запись службы.
func TestNTF326_ServiceAccountSubjectIsNoConfirmedAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireDoor(t, w.door, "service_account:sva-1", "v_get", "storage_volume:vol-1", true)
	rdRequireOutcome(t, w.outcome(t, rdResource("storage", "service_account:sva-1", "v_get", rdVol("vol-1"))),
		iamv1.RecipientOutcome_RECIPIENT_OUTCOME_NO_CONFIRMED_ADDRESS)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test", "storage_volume:vol-1") // близнец user:usr-A
}

func TestNTF3119_InactiveUserHasNoAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireOutcome(t, w.outcome(t, rdResource("storage", "user:usr-blk", "v_get", rdVol("vol-1"))),
		iamv1.RecipientOutcome_RECIPIENT_OUTCOME_SUBJECT_INACTIVE)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test", "storage_volume:vol-1")
}

func TestNTF3121_AnchorAndAccountAreAcceptedInAnyNamespace(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdResource("storage", "user:usr-E", "v_get", rdRef("project", "prj-1"))),
		"e@example.test", "project:prj-1")
	rdRequireAddress(t, w.outcome(t, rdResource("notify", "user:usr-A", "v_get", rdRef("account", "acc-1"))),
		"a@example.test", "account:acc-1")
}

// ── NTF3-27 · NTF3-151: право вызывающего ───────────────────────────────────

// TestNTF327_CallerOtherThanNotifyIsRefused — storage и notify-api по своим
// сертификатам (SAN не ключ таблицы звена): каждый вызов — отказ двери.
func TestNTF327_CallerOtherThanNotifyIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test", "storage_volume:vol-1") // близнец notify
	for _, san := range []string{rdStorageSAN, rdNotifyAPISAN} {
		t.Run(san, func(t *testing.T) {
			_, err := w.resolveAs(t, san, rdBase())
			requireAuthzDenied(t, err)
			_, err = w.audience(t, san, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-1"})
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
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test", "storage_volume:vol-1")

	ctx := metadata.AppendToOutgoingContext(context.Background(),
		principalwire.MetaPrincipalType, "user",
		principalwire.MetaPrincipalID, "usr-ca",
		principalwire.MetaTokenACR, "2")
	c := iamv1.NewInternalNotificationRecipientServiceClient(w.lis.dial(t, acrTestGatewaySAN))
	resp, err := c.Resolve(ctx, rdBase())
	require.Nil(t, resp, "адрес ушёл пересланному администратору облака")
	requireAuthzDenied(t, err)
	page, err := c.ListProjectAudience(ctx, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-1"})
	require.Nil(t, page, "субъекты ушли пересланному администратору облака")
	requireAuthzDenied(t, err)
}

// ── NTF3-28 · УК3-07 · NTF3-29: тип и отношение ─────────────────────────────

func TestNTF328_UK307_ResourceTypeIsAnExactMemberOfTheNamespace(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test", "storage_volume:vol-1") // близнец storage_volume
	for _, typ := range []string{
		"vpc_network",     // NTF3-28: тип чужого пространства
		"storagex_volume", // УК3-07: общее начало имени без разделителя
		"storage_volumes", // УК3-07: тип пространства с хвостом
	} {
		t.Run(typ, func(t *testing.T) {
			resp, err, asked := w.measured(t, rdResource("storage", "user:usr-A", "v_get", rdRef(typ, "vol-1")))
			require.Nil(t, resp)
			rdRequireInvalid(t, err, "", "resource_refs[0].type")
			require.Empty(t, asked, "вопрос к модели задан до отказа входа")
		})
	}
}

func TestNTF329_RelationOutsideTheClosedSetIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test", "storage_volume:vol-1") // близнец v_get
	resp, err, asked := w.measured(t, rdResource("storage", "user:usr-A", "viewer", rdVol("vol-1")))
	require.Nil(t, resp)
	rdRequireInvalid(t, err, "", "relation")
	require.Empty(t, asked, "вопрос к модели задан до отказа входа")
}

// ── NTF3-30: только внутренний слушатель ────────────────────────────────────

func TestNTF330_DirectoryIsNotOnTheExternalListener(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test", "storage_volume:vol-1") // близнец: внутренний слушатель

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
	rdRequireAddress(t, w.outcome(t, rdBase()), "a@example.test", "storage_volume:vol-1")
}

// ── NTF3-117: аудитория проекта ─────────────────────────────────────────────

func TestNTF3117_ProjectAudienceIsDirectUserBindingsOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	want := []string{"user:usr-A", "user:usr-B", "user:usr-E", "user:usr-blk"}
	sort.Strings(want)
	page := func(t *testing.T, req *iamv1.ListProjectAudienceRequest) *iamv1.ListProjectAudienceResponse {
		t.Helper()
		resp, err := w.audience(t, ntfNotifySAN, req)
		require.NoError(t, err, "ListProjectAudience(%v): %v", req, err)
		return resp
	}

	t.Run("обход page_size=2", func(t *testing.T) {
		var all []string
		var sizes []int
		token := ""
		for i := 0; i < 10; i++ {
			resp := page(t, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-1", PageSize: 2, PageToken: token})
			if len(resp.GetSubjects()) > 0 {
				sizes = append(sizes, len(resp.GetSubjects()))
			}
			all = append(all, resp.GetSubjects()...)
			token = resp.GetNextPageToken()
			if token == "" {
				break
			}
		}
		require.Empty(t, token, "обход не дошёл до пустого next_page_token за 10 страниц")
		require.Equal(t, want, all, "объединение страниц: ровно прямые действующие привязки пользователей, id по возрастанию")
		require.Equal(t, []int{2, 2}, sizes, "страниц с субъектами две, по 2")
	})
	t.Run("близнец обхода page_size=0", func(t *testing.T) {
		resp := page(t, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-1"})
		require.Equal(t, want, resp.GetSubjects())
		require.Empty(t, resp.GetNextPageToken())
	})

	refused := func(t *testing.T, req *iamv1.ListProjectAudienceRequest, message, field string) {
		t.Helper()
		_, err := w.audience(t, ntfNotifySAN, req)
		rdRequireInvalid(t, err, message, field)
	}
	t.Run("(а) page_size=1001; близнец 1000", func(t *testing.T) {
		refused(t, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-1", PageSize: 1001}, "", "page_size")
		require.Equal(t, want, page(t, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-1", PageSize: 1000}).GetSubjects())
	})
	t.Run("(б) page_size=-1; близнец 0", func(t *testing.T) {
		refused(t, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-1", PageSize: -1}, "", "page_size")
	})
	t.Run("(в) prj-2 с мусорным курсором; близнец без курсора", func(t *testing.T) {
		refused(t, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-2", PageToken: "!!not-a-cursor!!"}, "", "page_token")
		twin := page(t, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-2"})
		require.Empty(t, twin.GetSubjects())
		require.Empty(t, twin.GetNextPageToken())
	})
	t.Run("(г) мусорный курсор", func(t *testing.T) {
		refused(t, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-1", PageToken: "!!not-a-cursor!!"}, "", "page_token")
	})
	t.Run("(д) project_id не по форме", func(t *testing.T) {
		refused(t, &iamv1.ListProjectAudienceRequest{ProjectId: "p@1"}, "invalid project id 'p@1'", "")
	})
	t.Run("(е) project_id пуст", func(t *testing.T) {
		refused(t, &iamv1.ListProjectAudienceRequest{ProjectId: ""}, "project_id: required", "")
	})
	t.Run("близнец: прямая привязка у usr-C", func(t *testing.T) {
		var role string
		require.NoError(t, w.db.fixture.QueryRow(context.Background(),
			`SELECT role_id FROM kaname.access_bindings WHERE id = 'acb-x4d-a'`).Scan(&role))
		rdBind(t, w.db, role, "acb-x4d-c2", "user", "usr-C", "project", "prj-1", "")
		got := page(t, &iamv1.ListProjectAudienceRequest{ProjectId: "prj-1"}).GetSubjects()
		require.Contains(t, got, "user:usr-C")
	})
}

// ── NTF3-118: пакетная проверка ссылок ──────────────────────────────────────

func TestNTF3118_BatchRefsYieldTheVisibleSubset(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newRDWorld(t, true)
	rdRequireAddress(t, w.outcome(t, rdResource("storage", "user:usr-A", "v_get",
		rdVol("vol-1"), rdVol("vol-2"), rdVol("vol-20"))), "a@example.test", "storage_volume:vol-1", "storage_volume:vol-2")
	rdRequireOutcome(t, w.outcome(t, rdResource("storage", "user:usr-A", "v_get", rdVol("vol-20"))),
		iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED)

	t.Run("база (а)–(е): один вопрос о vol-1", func(t *testing.T) {
		resp, err, asked := w.measured(t, rdBase())
		require.NoError(t, err)
		rdRequireAddress(t, resp, "a@example.test", "storage_volume:vol-1")
		require.True(t, rdAsked(asked, "usr-A", "storage_volume", "vol-1"), "вопрос {usr-A, v_get, vol-1} не задан")
	})

	vols := func(ids ...string) []*iamv1.RecipientResourceRef {
		out := make([]*iamv1.RecipientResourceRef, 0, len(ids))
		for _, id := range ids {
			out = append(out, rdVol(id))
		}
		return out
	}
	many := func(last int) []string {
		ids := []string{"vol-1", "vol-2"}
		for i := 101; i <= last; i++ {
			ids = append(ids, fmt.Sprintf("vol-%d", i))
		}
		return ids
	}
	withRefs := func(refs ...*iamv1.RecipientResourceRef) *iamv1.ResolveRecipientRequest {
		return rdResource("storage", "user:usr-A", "v_get", refs...)
	}
	for _, tc := range []struct {
		name          string
		req, twin     *iamv1.ResolveRecipientRequest
		message, path string
		twinVisible   []string
	}{
		{"(а) id пуст", withRefs(rdVol("")), rdBase(), "resource_refs[0].id: required", "", []string{"storage_volume:vol-1"}},
		{"(б) вторая ссылка пуста", withRefs(rdVol("vol-1"), rdVol("")), withRefs(rdVol("vol-1"), rdVol("vol-2")),
			"resource_refs[1].id: required", "", []string{"storage_volume:vol-1", "storage_volume:vol-2"}},
		{"(в) subject пуст", rdResource("storage", "", "v_get", rdVol("vol-1")), rdBase(), "subject: required", "",
			[]string{"storage_volume:vol-1"}},
		{"(г) subject без id", rdResource("storage", "user:", "v_get", rdVol("vol-1")), rdBase(), "subject: required", "",
			[]string{"storage_volume:vol-1"}},
		{"(д) namespace пуст", rdResource("", "user:usr-A", "v_get", rdVol("vol-1")), rdBase(), "namespace: required", "",
			[]string{"storage_volume:vol-1"}},
		{"(е) ссылок 0", withRefs(), rdBase(), "resource_refs: required", "", []string{"storage_volume:vol-1"}},
		{"(ж) 101 ссылка; близнец 100", withRefs(vols(many(199)...)...), withRefs(vols(many(198)...)...), "", "resource_refs",
			[]string{"storage_volume:vol-1", "storage_volume:vol-2"}},
		{"(з) смесь типов", withRefs(rdVol("vol-1"), rdRef("storage_snapshot", "snp-1")), withRefs(rdVol("vol-1"), rdVol("vol-2")),
			"", "resource_refs", []string{"storage_volume:vol-1", "storage_volume:vol-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err, asked := w.measured(t, tc.req)
			require.Nil(t, resp, "отказ входа с ответом")
			rdRequireInvalid(t, err, tc.message, tc.path)
			require.Empty(t, asked, "вопросов к модели за отказ входа обязано быть 0, задано %d", len(asked))
			rdRequireAddress(t, w.outcome(t, tc.twin), "a@example.test", tc.twinVisible...)
		})
	}
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
	require.NoError(t, err, "перечень звена {ResolveSend, Resolve, ListProjectAudience} отвергнут корнем (Р28)")

	typo := ntfServiceIdentityYAML([]string{ntfResolveSendKey, rdResolveKey[:len(rdResolveKey)-1], rdAudienceKey},
		[][2]string{{ntfNotifySAN, "notify"}})
	cfg2, err := ntfConfig(t, typo)
	require.NoError(t, err)
	_, err = internalUnaryChain(ntfChainDeps(t, &cfg2, db))
	require.Error(t, err, "перечень с опечаткой …/Resolv принят")
	require.Contains(t, err.Error(), rdResolveKey[:len(rdResolveKey)-1])
}
