// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notification_grant_integration_test.go — запись выдачи, `ResolveSend`,
// `Revoke`/`Restore` (полоса K3; приёмка NTF-1 §6 F: NTF1-F01, F04–F11,
// F13–F20, F23, NTF1-J03; Р5; замысел З18; CX1-06…CX1-09, CX1-110, УК8, УК101).
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК ПОСТРОЕНО
//
// Испытуемый собирается тем же путём, что в процессе: служба — строителем
// корня, регистрация — `registerInternalServices`, цепочка внутреннего
// слушателя — `internalUnaryChain` (K5), рукопожатие — mTLS с листом точного
// SAN. `ResolveSend` зовётся пиром по проводу; `Revoke`/`Restore` — прямым
// вызовом службы в контексте принципала (их право — администратор кластера,
// пересылку личности краем утверждает соседняя проба
// `notification_grant_edge_leg_integration_test.go`). База — свой клон на
// testcontainers, дверь решения — настоящая, посев — настоящий применитель.
//
// «Чтений записи выдачи 0» и «вопрос о праве задан с субъектом X» —
// измерение провода (журнал операторов пула службы, фикстура), а не дублёр
// порта: обработчик волен устроить порты как угодно, провод от этого не
// меняется.
//
// ─────────────────────────────────────────────────────────────────────────────
// КОНТРАКТ, КОТОРЫЙ ЗАДАЁТ ЭТА ПРОБА (полоса RED, до реализации)
//
//	func buildNotificationGrantServer(pool *pgxpool.Pool, door *service.AuthorizeService,
//	    relations *authzcascade.Client, cfg config.Config, logger *slog.Logger,
//	) (iamv1.InternalNotificationGrantServiceServer, error)
//
//	services.notificationGrantHandler iamv1.InternalNotificationGrantServiceServer
//	    — регистрирует `registerInternalServices`;
//
//	ключ файла `notifications.cutoff-guard` — полоса `notificationCutoffGuard`
//	    (Р5), без умолчания, граница `[1s..10m]`; судит строитель (как
//	    `invite.ttl` судит сборка служб) — отказ с именем ключа и границей;
//
//	таблицы замысла §6 в схеме `kaname`: `notification_grants(namespace,
//	    granted_at, revoked_at, cutoff_at)`, `notification_template_grants(
//	    namespace, template, revoked_at, cutoff_at)`.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ntfGuard — полоса пробы: внутри границы `[1s..10m]`, мала ради скорости.
const ntfGuard = 2 * time.Second

func ntfGuardYAML(v string) string {
	if v == "" {
		return ""
	}
	return "notifications:\n  cutoff-guard: " + v + "\n"
}

// ntfGrantWorld — kaname пробы K3: база, дверь, служба, слушатель с цепочкой
// корня, администратор кластера.
type ntfGrantWorld struct {
	db        *ntfDB
	door      *service.AuthorizeService
	relations *authzcascade.Client
	srv       iamv1.InternalNotificationGrantServiceServer
	lis       *ntfListener
	pki       *ntfPKI
	chain     []grpc.UnaryServerInterceptor
	admin     context.Context
}

// newNTFGrantWorld — мир пробы. identityYAML — ключ `authn.service-identity`
// (пусто — ключа нет).
func newNTFGrantWorld(t *testing.T, identityYAML string) *ntfGrantWorld {
	t.Helper()
	db := newNTFDB(t)
	door, relations := ntfDoor(db)
	// Фикстура судится ДО предмета: слепой журнал, непризнанный
	// администратор и непосеянный читатель — сломанный вопрос, а не ответ.
	requireWireSeesDoorQuestions(t, db, door)
	admin := ntfAdminCtx(t, db, door)
	// Предмет начинается здесь: ключи `authn.service-identity` (K5) и
	// `notifications.cutoff-guard` (K3) обязан знать декодер.
	cfg, err := ntfConfig(t, identityYAML+ntfGuardYAML(ntfGuard.String()))
	require.NoError(t, err, "настройка пробы не загрузилась")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := buildNotificationGrantServer(db.pool, door, relations, cfg, logger)
	require.NoError(t, err, "служба выдачи не собрана")
	chain, err := internalUnaryChain(ntfChainDeps(t, &cfg, db))
	require.NoError(t, err, "цепочка внутреннего слушателя не собрана")
	w := &ntfGrantWorld{db: db, door: door, relations: relations, srv: srv, pki: newNTFPKI(t), chain: chain, admin: admin}
	w.serve(t)
	return w
}

// serve — (пере)подъём внутреннего слушателя ТЕМ ЖЕ путём регистрации, что в
// процессе.
func (w *ntfGrantWorld) serve(t *testing.T) {
	t.Helper()
	w.lis = ntfServe(t, w.pki, w.chain, func(s grpc.ServiceRegistrar) {
		registerInternalServices(s, &services{notificationGrantHandler: w.srv}, nil, ntfMustConfig(t), nil)
	})
}

func ntfMustConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := ntfConfig(t, "")
	require.NoError(t, err)
	return cfg
}

// resolve — `ResolveSend` пиром с листом san по проводу.
func (w *ntfGrantWorld) resolve(t *testing.T, san, ns, tmpl string, at time.Time) (iamv1.SendDecision, error) {
	t.Helper()
	resp, err := iamv1.NewInternalNotificationGrantServiceClient(w.lis.dial(t, san)).ResolveSend(context.Background(),
		&iamv1.ResolveSendRequest{Namespace: ns, Template: tmpl, EnqueuedAt: timestamppb.New(at)})
	if err != nil {
		require.Nil(t, resp, "отказ с ответом: решение не должно уходить вместе с ошибкой")
		return iamv1.SendDecision_SEND_DECISION_UNSPECIFIED, err
	}
	return resp.GetDecision(), nil
}

// decide — исход notify без ошибки.
func (w *ntfGrantWorld) decide(t *testing.T, ns, tmpl string, at time.Time) iamv1.SendDecision {
	t.Helper()
	d, err := w.resolve(t, ntfNotifySAN, ns, tmpl, at)
	require.NoError(t, err, "ResolveSend(%s, %s, %s) отказал: %v", ns, tmpl, at.Format(time.RFC3339Nano), err)
	return d
}

func ntfGrantReq(ns string, tmpl ...string) *iamv1.NotificationGrantRequest {
	r := &iamv1.NotificationGrantRequest{Namespace: ns}
	if len(tmpl) > 0 {
		r.Template = proto.String(tmpl[0])
	}
	return r
}

// revoke / restore — вызов, доведённый до исхода: при отказе — ошибка, при
// приёме — операция дочитана до done и успешна.
func (w *ntfGrantWorld) revoke(t *testing.T, ctx context.Context, req *iamv1.NotificationGrantRequest) error {
	t.Helper()
	op, err := w.srv.Revoke(ctx, req)
	if err != nil {
		require.Nil(t, op, "отказ с операцией: при синхронном отказе Operation не создаётся")
		return err
	}
	done := ntfAwaitOperation(t, w.db, op.GetId())
	require.Nil(t, done.Error, "Revoke %v: операция завершилась ошибкой", req)
	return nil
}

func (w *ntfGrantWorld) restore(t *testing.T, ctx context.Context, req *iamv1.NotificationGrantRequest) error {
	t.Helper()
	op, err := w.srv.Restore(ctx, req)
	if err != nil {
		require.Nil(t, op, "отказ с операцией: при синхронном отказе Operation не создаётся")
		return err
	}
	done := ntfAwaitOperation(t, w.db, op.GetId())
	require.Nil(t, done.Error, "Restore %v: операция завершилась ошибкой", req)
	return nil
}

// grantRow / templateRow — запись целиком текстом (побайтовое «та же»).
func (w *ntfGrantWorld) grantRow(t *testing.T, ns string) (string, error) {
	return ntfRow(t, w.db, `SELECT row_to_json(g)::text FROM kaname.notification_grants g WHERE g.namespace = $1`, ns)
}

func (w *ntfGrantWorld) templateRows(t *testing.T, ns, tmpl string) int {
	t.Helper()
	var n int
	require.NoError(t, w.db.fixture.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.notification_template_grants WHERE namespace = $1 AND template = $2`, ns, tmpl).Scan(&n))
	return n
}

// cutoff — отсечка выдачи по часам kaname, полной точности.
func (w *ntfGrantWorld) cutoff(t *testing.T, ns string) time.Time {
	t.Helper()
	var c *time.Time
	require.NoError(t, w.db.fixture.QueryRow(context.Background(),
		`SELECT cutoff_at FROM kaname.notification_grants WHERE namespace = $1`, ns).Scan(&c))
	require.NotNil(t, c, "у восстановленной выдачи нет отсечки")
	return *c
}

func (w *ntfGrantWorld) templateCutoff(t *testing.T, ns, tmpl string) time.Time {
	t.Helper()
	var c *time.Time
	require.NoError(t, w.db.fixture.QueryRow(context.Background(),
		`SELECT cutoff_at FROM kaname.notification_template_grants WHERE namespace = $1 AND template = $2`, ns, tmpl).Scan(&c))
	require.NotNil(t, c, "у восстановленного шаблона нет отсечки")
	return *c
}

// senderAllowed — `Check(service:<ns>, sender, notification_namespace:<ns>)`
// дверью.
func (w *ntfGrantWorld) senderAllowed(t *testing.T, ns string) bool {
	t.Helper()
	res, err := w.door.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: "service:" + ns, Relation: "sender", Object: "notification_namespace:" + ns,
	})
	require.NoError(t, err)
	return res.Allowed
}

// seeded — мир с посеянной строкой F01 и проверенным посевом читателя.
func ntfSeededWorld(t *testing.T) *ntfGrantWorld {
	t.Helper()
	w := newNTFGrantWorld(t, ntfAgreedIdentityYAML())
	ntfApply(t, w.db, ntfProbeManifest)
	require.Equal(t, 1, ntfFactCount(t, w.db, "service:notify", "reader", "notification_feed", "probe"),
		"фикстура: посев не завёл читателя ленты")
	return w
}

func requireRefusal(t *testing.T, err error, code codes.Code, message, reason string) ntfRefusal {
	t.Helper()
	require.Error(t, err, "ждали отказ %s %q", code, message)
	r := ntfRefusalOf(err)
	require.Equal(t, code.String(), r.code, "код отказа; текст %q", r.message)
	require.Equal(t, message, r.message)
	if reason != "" {
		require.Equal(t, reason, r.reason, "reason в ErrorInfo")
	}
	return r
}

func requireGrantMetadata(t *testing.T, r ntfRefusal, ns string) {
	t.Helper()
	require.Equal(t, refusaldomain.For(refusaldomain.ServiceIAM), r.domain, "домен отказа")
	require.Equal(t, map[string]string{"resource_type": "notification_namespace", "resource_id": ns}, r.metadata)
}

func requireAuthzDenied(t *testing.T, err error) {
	t.Helper()
	requireRefusal(t, err, codes.PermissionDenied, "permission denied", "AUTHZ_DENIED")
}

// ── СЦЕНАРИИ ────────────────────────────────────────────────────────────────

func TestNTF1F01_SeededGrantAllowsAndProjectsBothRelations(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	require.True(t, w.senderAllowed(t, "probe"), "посев не дал `service:probe sender notification_namespace:probe`")
	res, err := w.door.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: "service:notify", Relation: "reader", Object: "notification_feed:probe",
	})
	require.NoError(t, err)
	require.True(t, res.Allowed)
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", time.Now()))
}

func TestNTF1F04_NoGrantRecordIsNotYetGrantedThenTheSeedAllows(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newNTFGrantWorld(t, ntfAgreedIdentityYAML())
	ntfApply(t, w.db, ntfProbeManifestNoLine)
	ntfSeedFeedReader(t, w.db, "probe")
	t0 := time.Now()
	_, err := w.grantRow(t, "probe")
	require.ErrorIs(t, err, errNTFNoRow, "Дано: записи выдачи нет")
	require.Equal(t, iamv1.SendDecision_NOT_YET_GRANTED, w.decide(t, "probe", "probe-hello", t0))

	ntfApply(t, w.db, ntfProbeManifest) // посев создаёт выдачу в t1 > t0
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", t0),
		"строка, поставленная до первой выдачи, после появления выдачи — ALLOW")
}

func TestNTF1F05_RevokeIsTerminalForRowsBeforeAndAfter(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	before := time.Now()
	require.NoError(t, w.revoke(t, w.admin, ntfGrantReq("probe")))
	require.Equal(t, iamv1.SendDecision_REVOKED, w.decide(t, "probe", "probe-hello", before))
	require.Equal(t, iamv1.SendDecision_REVOKED, w.decide(t, "probe", "probe-hello", time.Now()))
	require.Eventually(t, func() bool { return !w.senderAllowed(t, "probe") }, 10*time.Second, 50*time.Millisecond,
		"кортеж sender пережил отзыв")
}

func TestNTF1F06_RestoreDoesNotReleaseTheAccumulated(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	require.NoError(t, w.revoke(t, w.admin, ntfGrantReq("probe")))
	queued := []time.Time{time.Now(), time.Now(), time.Now()}
	require.NoError(t, w.restore(t, w.admin, ntfGrantReq("probe")))
	c := w.cutoff(t, "probe")
	for i, at := range queued {
		require.Equal(t, iamv1.SendDecision_REVOKED, w.decide(t, "probe", "probe-hello", at), "строка %d выпущена восстановлением", i+1)
	}
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", c.Add(ntfGuard)), "четвёртая строка за полосой")
	require.Eventually(t, func() bool { return w.senderAllowed(t, "probe") }, 10*time.Second, 50*time.Millisecond,
		"Restore не вернул кортеж sender")
}

func TestNTF1F07_TemplateRevokeLeavesTheNeighbour(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	require.NoError(t, w.revoke(t, w.admin, ntfGrantReq("probe", "probe-hello")))
	now := time.Now()
	require.Equal(t, iamv1.SendDecision_REVOKED, w.decide(t, "probe", "probe-hello", now))
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-bye", now))
	require.True(t, w.senderAllowed(t, "probe"), "отзыв шаблона тронул кортеж sender")
}

func TestNTF1F08_ReseedNeitherRevivesNorRewrites(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	t.Run("после Revoke", func(t *testing.T) {
		w := ntfSeededWorld(t)
		require.NoError(t, w.revoke(t, w.admin, ntfGrantReq("probe")))
		before, err := w.grantRow(t, "probe")
		require.NoError(t, err)
		ntfApply(t, w.db, ntfProbeManifest) // перезапуск: посев заново
		after, err := w.grantRow(t, "probe")
		require.NoError(t, err)
		require.Equal(t, before, after, "посев изменил отозванную запись")
		require.Equal(t, iamv1.SendDecision_REVOKED, w.decide(t, "probe", "probe-hello", time.Now()))
	})
	t.Run("близнец: без Revoke — два перезапуска запись не меняют", func(t *testing.T) {
		w := ntfSeededWorld(t)
		first, err := w.grantRow(t, "probe")
		require.NoError(t, err)
		t0 := time.Now()
		ntfApply(t, w.db, ntfProbeManifest)
		ntfApply(t, w.db, ntfProbeManifest)
		again, err := w.grantRow(t, "probe")
		require.NoError(t, err)
		require.Equal(t, first, again)
		require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", t0))
	})
}

func TestNTF1F09_ResolveSendOnlyForTheFeedReader(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	t.Run("близнец: notify на своё пространство — ALLOW", func(t *testing.T) {
		require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", time.Now()))
	})
	t.Run("(а) SAN не ключ таблицы", func(t *testing.T) {
		_, err := w.resolve(t, ntfVPCSAN, "probe", "probe-hello", time.Now())
		requireAuthzDenied(t, err)
	})
	t.Run("(б) notify без читателя ленты probe-c", func(t *testing.T) {
		_, err := w.resolve(t, ntfNotifySAN, "probe-c", "probe-hello", time.Now())
		requireAuthzDenied(t, err)
	})
}

func TestNTF1F10_RevokeIsForTheClusterAdminOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	before, err := w.grantRow(t, "probe")
	require.NoError(t, err)
	user := ntfUserCtx(t, w.db, w.door, ids.NewID(domain.PrefixUser))
	err = w.revoke(t, user, ntfGrantReq("probe"))
	requireRefusal(t, err, codes.PermissionDenied, "permission denied", "")
	after, err := w.grantRow(t, "probe")
	require.NoError(t, err)
	require.Equal(t, before, after, "надгробие появилось от не-администратора")
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", time.Now()))
}

func TestNTF1F11_StoppedListenerIsUnavailableAndTheRowWaits(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	at := time.Now()
	w.lis.srv.Stop()
	_, err := w.resolve(t, ntfNotifySAN, "probe", "probe-hello", at)
	require.Equal(t, codes.Unavailable.String(), ntfRefusalOf(err).code, "остановленный слушатель: %v", err)
	w.serve(t)
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", at), "после подъёма строка проходит")
}

func TestNTF1F13_MalformedInputIsRefusedSynchronouslyNamingTheField(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	opsBefore := ntfOperationsCount(t, w.db)
	rowBefore, err := w.grantRow(t, "probe")
	require.NoError(t, err)

	t.Run("ResolveSend namespace пуст", func(t *testing.T) {
		_, err := w.resolve(t, ntfNotifySAN, "", "probe-hello", time.Now())
		r := requireRefusal(t, err, codes.InvalidArgument, "namespace: required", "INVALID_RESOURCE_ID")
		requireGrantMetadata(t, r, "")
	})
	t.Run("ResolveSend namespace не DNS label", func(t *testing.T) {
		_, err := w.resolve(t, ntfNotifySAN, "Bad_Ns", "probe-hello", time.Now())
		r := requireRefusal(t, err, codes.InvalidArgument, "invalid notification_namespace id 'Bad_Ns'", "INVALID_RESOURCE_ID")
		requireGrantMetadata(t, r, "Bad_Ns")
	})
	t.Run("ResolveSend template не DNS label", func(t *testing.T) {
		_, err := w.resolve(t, ntfNotifySAN, "probe", "Invite_1", time.Now())
		r := requireRefusal(t, err, codes.InvalidArgument, "template: invalid name 'Invite_1'", "")
		require.Equal(t, []string{"template"}, r.fields)
	})
	t.Run("ResolveSend без enqueued_at", func(t *testing.T) {
		_, err := iamv1.NewInternalNotificationGrantServiceClient(w.lis.dial(t, ntfNotifySAN)).ResolveSend(
			context.Background(), &iamv1.ResolveSendRequest{Namespace: "probe", Template: "probe-hello"})
		r := requireRefusal(t, err, codes.InvalidArgument, "enqueued_at: required", "")
		require.Equal(t, []string{"enqueued_at"}, r.fields)
	})
	t.Run("Revoke namespace не DNS label", func(t *testing.T) {
		err := w.revoke(t, w.admin, ntfGrantReq("Bad_Ns"))
		r := requireRefusal(t, err, codes.InvalidArgument, "invalid notification_namespace id 'Bad_Ns'", "INVALID_RESOURCE_ID")
		requireGrantMetadata(t, r, "Bad_Ns")
	})
	t.Run("Restore namespace не DNS label", func(t *testing.T) {
		err := w.restore(t, w.admin, ntfGrantReq("Bad_Ns"))
		r := requireRefusal(t, err, codes.InvalidArgument, "invalid notification_namespace id 'Bad_Ns'", "INVALID_RESOURCE_ID")
		requireGrantMetadata(t, r, "Bad_Ns")
	})
	t.Run("Operation не создана, запись и кортеж прежние", func(t *testing.T) {
		require.Equal(t, opsBefore, ntfOperationsCount(t, w.db))
		rowAfter, err := w.grantRow(t, "probe")
		require.NoError(t, err)
		require.Equal(t, rowBefore, rowAfter)
		require.True(t, w.senderAllowed(t, "probe"))
	})
	t.Run("близнецы: исправленное поле — исход F01, F05, F06", func(t *testing.T) {
		require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", time.Now()))
		require.NoError(t, w.revoke(t, w.admin, ntfGrantReq("probe")))
		require.NoError(t, w.restore(t, w.admin, ntfGrantReq("probe")))
	})
}

func TestNTF1F14_UnknownNamespaceIsAnOutcomeNotAnError(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newNTFGrantWorld(t, ntfAgreedIdentityYAML())
	ntfSeedFeedReader(t, w.db, "probe-c")
	require.Equal(t, iamv1.SendDecision_NOT_YET_GRANTED, w.decide(t, "probe-c", "probe-hello", time.Now()))
	_, err := w.resolve(t, ntfNotifySAN, "Bad_Ns", "probe-hello", time.Now())
	requireRefusal(t, err, codes.InvalidArgument, "invalid notification_namespace id 'Bad_Ns'", "INVALID_RESOURCE_ID")
}

func TestNTF1F15_RevokeAndRestoreOfAnUnknownNamespaceAreNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newNTFGrantWorld(t, ntfAgreedIdentityYAML())
	ntfSeedFeedReader(t, w.db, "probe-c")
	ops := ntfOperationsCount(t, w.db)
	for name, call := range map[string]func() error{
		"Revoke":  func() error { return w.revoke(t, w.admin, ntfGrantReq("probe-c")) },
		"Restore": func() error { return w.restore(t, w.admin, ntfGrantReq("probe-c")) },
	} {
		t.Run(name, func(t *testing.T) {
			r := requireRefusal(t, call(), codes.NotFound, "NotificationNamespace probe-c not found", "RESOURCE_NOT_FOUND")
			requireGrantMetadata(t, r, "probe-c")
		})
	}
	require.Equal(t, ops, ntfOperationsCount(t, w.db), "Operation создана при отказе")
	_, err := w.grantRow(t, "probe-c")
	require.ErrorIs(t, err, errNTFNoRow, "у неизвестного пространства появилась запись")
}

func TestNTF1F16_RepeatedRevokeIsFailedPrecondition(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	t.Run("пространство", func(t *testing.T) {
		w := ntfSeededWorld(t)
		require.NoError(t, w.revoke(t, w.admin, ntfGrantReq("probe")))
		row, err := w.grantRow(t, "probe")
		require.NoError(t, err)
		ops := ntfOperationsCount(t, w.db)
		r := requireRefusal(t, w.revoke(t, w.admin, ntfGrantReq("probe")), codes.FailedPrecondition,
			"NotificationNamespace probe is already revoked", "NOTIFICATION_GRANT_STATE")
		requireGrantMetadata(t, r, "probe")
		require.Equal(t, ops, ntfOperationsCount(t, w.db))
		again, err := w.grantRow(t, "probe")
		require.NoError(t, err)
		require.Equal(t, row, again, "«отозвано» сдвинулось повтором")
	})
	t.Run("шаблон", func(t *testing.T) {
		w := ntfSeededWorld(t)
		require.NoError(t, w.revoke(t, w.admin, ntfGrantReq("probe", "probe-hello")))
		requireRefusal(t, w.revoke(t, w.admin, ntfGrantReq("probe", "probe-hello")), codes.FailedPrecondition,
			"NotificationNamespace probe template probe-hello is already revoked", "NOTIFICATION_GRANT_STATE")
	})
}

func TestNTF1F17_RestoreWithoutTombstoneIsFailedPrecondition(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	t0 := time.Now()
	ops := ntfOperationsCount(t, w.db)
	r := requireRefusal(t, w.restore(t, w.admin, ntfGrantReq("probe")), codes.FailedPrecondition,
		"NotificationNamespace probe is not revoked", "NOTIFICATION_GRANT_STATE")
	requireGrantMetadata(t, r, "probe")
	requireRefusal(t, w.restore(t, w.admin, ntfGrantReq("probe", "probe-hello")), codes.FailedPrecondition,
		"NotificationNamespace probe template probe-hello is not revoked", "NOTIFICATION_GRANT_STATE")
	require.Equal(t, ops, ntfOperationsCount(t, w.db))
	var cut *time.Time
	require.NoError(t, w.db.fixture.QueryRow(context.Background(),
		`SELECT cutoff_at FROM kaname.notification_grants WHERE namespace = 'probe'`).Scan(&cut))
	require.Nil(t, cut, "отказанный Restore поставил отсечку")
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", t0))
}

// ntfRace — n одновременных вызовов; число успешных и отказов
// NOTIFICATION_GRANT_STATE.
func ntfRace(t *testing.T, n int, call func() error) (ok, state int, other []string) {
	t.Helper()
	var wg sync.WaitGroup
	var mu sync.Mutex
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := call()
			mu.Lock()
			defer mu.Unlock()
			switch r := ntfRefusalOf(err); {
			case err == nil:
				ok++
			case r.code == codes.FailedPrecondition.String() && r.reason == "NOTIFICATION_GRANT_STATE":
				state++
			default:
				other = append(other, fmt.Sprintf("%s %q %s", r.code, r.message, r.reason))
			}
		}()
	}
	close(start)
	wg.Wait()
	return ok, state, other
}

// ntfSenderIffNoTombstone — после опустошения очереди kaname кортеж sender
// есть ⇔ надгробия нет.
func ntfSenderIffNoTombstone(t *testing.T, w *ntfGrantWorld) {
	t.Helper()
	var revoked bool
	require.NoError(t, w.db.fixture.QueryRow(context.Background(),
		`SELECT revoked_at IS NOT NULL FROM kaname.notification_grants WHERE namespace = 'probe'`).Scan(&revoked))
	require.Eventually(t, func() bool { return w.senderAllowed(t, "probe") == !revoked }, 10*time.Second, 50*time.Millisecond,
		"кортеж sender разошёлся с надгробием (надгробие: %v)", revoked)
}

func TestNTF1F18_ConcurrentTransitionsYieldExactlyOne(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	const n = 8
	w := ntfSeededWorld(t)
	revoke := func(req *iamv1.NotificationGrantRequest) func() error {
		return func() error { return w.revoke(t, w.admin, req) }
	}
	restore := func(req *iamv1.NotificationGrantRequest) func() error {
		return func() error { return w.restore(t, w.admin, req) }
	}
	step := func(name string, call func() error) {
		t.Run(name, func(t *testing.T) {
			ok, state, other := ntfRace(t, n, call)
			t.Logf("%s: успешных %d, NOTIFICATION_GRANT_STATE %d, прочих %v", name, ok, state, other)
			require.Empty(t, other)
			require.Equal(t, 1, ok, "переходов не ровно один")
			require.Equal(t, n-1, state)
			ntfSenderIffNoTombstone(t, w)
		})
	}
	step("(а) 8 × Revoke(probe)", revoke(ntfGrantReq("probe")))
	step("(б) 8 × Restore(probe)", restore(ntfGrantReq("probe")))

	rowBefore, err := w.grantRow(t, "probe")
	require.NoError(t, err)
	step("(г) 8 × Revoke(probe, probe-hello) без записи шаблона", revoke(ntfGrantReq("probe", "probe-hello")))
	require.Equal(t, 1, w.templateRows(t, "probe", "probe-hello"), "записей шаблона не ровно одна")
	step("(д) 8 × Restore(probe, probe-hello)", restore(ntfGrantReq("probe", "probe-hello")))
	rowAfter, err := w.grantRow(t, "probe")
	require.NoError(t, err)
	require.Equal(t, rowBefore, rowAfter, "переходы шаблона тронули запись выдачи")

	t.Run("(в) Revoke ∥ Restore из активного — одно из двух законных состояний", func(t *testing.T) {
		v := ntfSeededWorld(t)
		var wg sync.WaitGroup
		var rErr, sErr error
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; rErr = v.revoke(t, v.admin, ntfGrantReq("probe")) }()
		go func() { defer wg.Done(); <-start; sErr = v.restore(t, v.admin, ntfGrantReq("probe")) }()
		close(start)
		wg.Wait()
		require.NoError(t, rErr, "Revoke из активного обязан пройти при любом порядке")
		var revoked, hasCutoff bool
		require.NoError(t, v.db.fixture.QueryRow(context.Background(),
			`SELECT revoked_at IS NOT NULL, cutoff_at IS NOT NULL FROM kaname.notification_grants WHERE namespace = 'probe'`).
			Scan(&revoked, &hasCutoff))
		t.Logf("Restore: %v; надгробие %v, отсечка %v", sErr, revoked, hasCutoff)
		switch {
		case sErr == nil: // Revoke, затем Restore
			require.False(t, revoked)
			require.True(t, hasCutoff)
		default: // Restore раньше Revoke: «не отозвано»
			requireRefusal(t, sErr, codes.FailedPrecondition, "NotificationNamespace probe is not revoked", "NOTIFICATION_GRANT_STATE")
			require.True(t, revoked)
			require.False(t, hasCutoff)
		}
		ntfSenderIffNoTombstone(t, v)
	})

	t.Run("близнец: последовательно — ровно один успешный на переход", func(t *testing.T) {
		v := ntfSeededWorld(t)
		for _, tr := range []struct {
			name string
			call func() error
		}{
			{"Revoke", func() error { return v.revoke(t, v.admin, ntfGrantReq("probe")) }},
			{"Restore", func() error { return v.restore(t, v.admin, ntfGrantReq("probe")) }},
		} {
			ok := 0
			for i := 0; i < n; i++ {
				if tr.call() == nil {
					ok++
				}
			}
			require.Equal(t, 1, ok, "%s последовательно: успешных не ровно один", tr.name)
		}
	})
}

func TestNTF1F19_TemplateRestoreDoesNotReleaseItsAccumulated(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	require.NoError(t, w.revoke(t, w.admin, ntfGrantReq("probe", "probe-hello")))
	r1, i1 := time.Now(), time.Now()
	require.NoError(t, w.restore(t, w.admin, ntfGrantReq("probe", "probe-hello")))
	r2 := w.templateCutoff(t, "probe", "probe-hello").Add(ntfGuard)
	require.Equal(t, iamv1.SendDecision_REVOKED, w.decide(t, "probe", "probe-hello", r1))
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-bye", i1))
	require.Equal(t, iamv1.SendDecision_ALLOW, w.decide(t, "probe", "probe-hello", r2))
	var revoked, hasCutoff bool
	require.NoError(t, w.db.fixture.QueryRow(context.Background(),
		`SELECT revoked_at IS NOT NULL, cutoff_at IS NOT NULL FROM kaname.notification_grants WHERE namespace = 'probe'`).
		Scan(&revoked, &hasCutoff))
	require.False(t, revoked, "восстановление шаблона поставило надгробие пространству")
	require.False(t, hasCutoff, "восстановление шаблона поставило отсечку пространству")
}

func TestNTF1F20_RowsInsideTheGuardBandAfterRestoreAreRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	require.NoError(t, w.revoke(t, w.admin, ntfGrantReq("probe")))
	require.NoError(t, w.restore(t, w.admin, ntfGrantReq("probe")))
	c := w.cutoff(t, "probe")
	t.Logf("отсечка c = %s, полоса G = %s", c.Format(time.RFC3339Nano), ntfGuard)
	for _, tc := range []struct {
		name string
		at   time.Time
		want iamv1.SendDecision
	}{
		{"c − 1s", c.Add(-time.Second), iamv1.SendDecision_REVOKED},
		{"c − 0,5s (дробная отсечка, УК8)", c.Add(-500 * time.Millisecond), iamv1.SendDecision_REVOKED},
		{"c + G − 1s", c.Add(ntfGuard - time.Second), iamv1.SendDecision_REVOKED},
		{"c + G", c.Add(ntfGuard), iamv1.SendDecision_ALLOW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, w.decide(t, "probe", "probe-hello", tc.at))
		})
	}
}

func TestNTF1F20_GuardBandKnobRefusesStartOutsideItsBounds(t *testing.T) {
	build := func(t *testing.T, guard string) error {
		t.Helper()
		cfg, err := ntfConfig(t, ntfGuardYAML(guard))
		require.NoError(t, err, "файл с ключом полосы обязан загрузиться: суждение — у строителя")
		ndb := &ntfDB{pool: deadPool(t)}
		door, relations := ntfDoor(ndb)
		_, err = buildNotificationGrantServer(ndb.pool, door, relations, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
		return err
	}
	t.Run("близнец: 30s — строится", func(t *testing.T) {
		require.NoError(t, build(t, "30s"))
	})
	for _, tc := range []struct{ name, guard, bound string }{
		{"полосы нет", "", "notifications.cutoff-guard"},
		{"меньше 1s", "500ms", "1s"},
		{"больше 10m", "11m", "10m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := build(t, tc.guard)
			require.Error(t, err, "строитель принял полосу %q", tc.guard)
			require.Contains(t, err.Error(), "notifications.cutoff-guard", "отказ называет ручку")
			require.Contains(t, err.Error(), tc.bound, "отказ называет границу")
		})
	}
}

func TestNTF1F23_GrantReadFailureIsUnavailableNotNotYetGranted(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newNTFGrantWorld(t, ntfAgreedIdentityYAML())
	ntfSeedFeedReader(t, w.db, "probe")
	t.Run("близнец F04: без инъекции — NOT_YET_GRANTED", func(t *testing.T) {
		require.Equal(t, iamv1.SendDecision_NOT_YET_GRANTED, w.decide(t, "probe", "probe-hello", time.Now()))
	})
	t.Run("сбой чтения хранилища — UNAVAILABLE фиксированным текстом", func(t *testing.T) {
		// Инъекция — настоящий отказ хранилища: таблицы записи выдачи под
		// своим именем больше нет, и чтение возвращает ошибку драйвера.
		_, err := w.db.fixture.Exec(context.Background(),
			`ALTER TABLE kaname.notification_grants RENAME TO notification_grants_ntf1_f23_fault`)
		require.NoError(t, err, "фикстура: инъекция сбоя чтения не поставлена")
		d, err := w.resolve(t, ntfNotifySAN, "probe", "probe-hello", time.Now())
		requireRefusal(t, err, codes.Unavailable, "notification grant service temporarily unavailable", "")
		require.Equal(t, iamv1.SendDecision_SEND_DECISION_UNSPECIFIED, d, "исход ушёл вместе со сбоем")
	})
}

func TestNTF1J03_SANIsComparedWholeThroughTheLink(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := ntfSeededWorld(t)
	d, err := w.resolve(t, ntfNotifySAN, "probe", "probe-hello", time.Now())
	require.NoError(t, err, "A — свой SAN")
	require.Equal(t, iamv1.SendDecision_ALLOW, d)
	_, err = w.resolve(t, ntfForeignNotifySAN, "probe", "probe-hello", time.Now())
	require.Equal(t, codes.PermissionDenied.String(), ntfRefusalOf(err).code, "B — тот же sa в чужом пространстве имён: %v", err)
}

// TestNTF1F09_R2PairOnTheRealHandler — боевая пара Р2 (CX1-110, УК101):
// право решает обработчик, `CheckRelation` до чтения записи выдачи.
func TestNTF1F09_R2PairOnTheRealHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	measure := func(t *testing.T, w *ntfGrantWorld) (iamv1.SendDecision, error, []string, int) {
		t.Helper()
		w.db.wire.reset()
		d, err := w.resolve(t, ntfNotifySAN, "probe", "probe-hello", time.Now())
		return d, err, w.db.wire.feedQuestionSubjects(), w.db.wire.grantStatements()
	}
	t.Run("ключа нет — отказ, CheckRelation не вызван, чтений записи 0", func(t *testing.T) {
		w := newNTFGrantWorld(t, "")
		ntfApply(t, w.db, ntfProbeManifest)
		_, err, asked, reads := measure(t, w)
		t.Logf("субъекты вопросов о ленте: %v; операторов о записи выдачи: %d", asked, reads)
		requireAuthzDenied(t, err)
		require.Empty(t, asked)
		require.Zero(t, reads)
	})
	t.Run("согласный ключ и кортеж — CheckRelation с service:notify, решение по записи", func(t *testing.T) {
		w := ntfSeededWorld(t)
		d, err, asked, reads := measure(t, w)
		t.Logf("субъекты вопросов о ленте: %v; операторов о записи выдачи: %d", asked, reads)
		require.NoError(t, err)
		require.Equal(t, iamv1.SendDecision_ALLOW, d)
		require.Contains(t, asked, "service:notify")
		require.Positive(t, reads, "решение без чтения записи выдачи")
	})
	t.Run("близнец: согласный ключ без кортежа — CheckRelation вызван, отказ, чтений 0", func(t *testing.T) {
		w := ntfSeededWorld(t)
		_, err := w.db.fixture.Exec(context.Background(), `
			DELETE FROM kaname.relation_fact
			 WHERE subject = 'service:notify' AND relation = 'reader'
			   AND object_type = 'notification_feed' AND object_id = 'probe'`)
		require.NoError(t, err)
		require.Zero(t, ntfFactCount(t, w.db, "service:notify", "reader", "notification_feed", "probe"))
		_, err, asked, reads := measure(t, w)
		t.Logf("субъекты вопросов о ленте: %v; операторов о записи выдачи: %d", asked, reads)
		requireAuthzDenied(t, err)
		require.Contains(t, asked, "service:notify")
		require.Zero(t, reads)
	})
}
