// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_admission_integration_test.go — полоса Д приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, Р4а): права
// человека с неподтверждённым адресом НЕ ДЕЙСТВУЮТ — ни прямая выдача, ни
// выдача группе, ни справочное отношение, выполнимое подстановкой, ни выдача
// администратора облака и откат к ней на отказе.
//
// Вопрос задаётся ТОЙ ЖЕ двери, что композиционный корень выдаёт стражам и
// решателю края; строки сеются тем производителем, каким их кладёт продукт
// (строки — строками, прямой факт — строкой журнала). У каждого отрицания —
// близнец, отличающийся ОДНИМ фактом: подтверждён ли адрес.
package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const reasonEmailNotVerified = "email_not_verified"

// admWorld — закоммиченное состояние iam и решатель края над той же базой.
type admWorld struct {
	ci   *ciWorld
	door *authzcascade.Client
	pool *pgxpool.Pool
}

func newAdmWorld(t *testing.T) *admWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Postgres) в кратком режиме")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	door := authzcascade.Wrap(relverdict.NewAsker(pool))
	ci := &ciWorld{pool: pool, svc: service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: door, ClusterAdminChecker: door,
	})}
	ci.exec(t, `INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho') ON CONFLICT DO NOTHING`)
	return &admWorld{ci: ci, door: door, pool: pool}
}

// mark — отметка подтверждения на строке человека (посев: значение ставится
// тем же оператором, что писатель отметки, — по значению адреса).
func (w *admWorld) mark(t *testing.T, user string) {
	t.Helper()
	w.ci.exec(t, `UPDATE kaname.users SET email_verified_at = $2 WHERE id = $1 AND email = $1 || '@example.test'`,
		user, time.Now().UTC())
	var marked bool
	require.NoError(t, w.pool.QueryRow(context.Background(),
		`SELECT email_verified_at IS NOT NULL FROM kaname.users WHERE id = $1`, user).Scan(&marked))
	require.True(t, marked, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): отметка %s не легла", user)
}

func (w *admWorld) check(t *testing.T, subject, objectType, objectID, relation string) *service.CheckResult {
	t.Helper()
	res, err := w.ci.svc.Check(context.Background(), service.CheckRequest{
		Subject:          subject,
		Resource:         service.ResourceRef{Type: objectType, ID: objectID},
		Action:           "probe.address." + relation,
		RequiredRelation: relation,
	})
	require.NoErrorf(t, err, "Check не вправе ошибаться (%s %s %s:%s)", subject, relation, objectType, objectID)
	return res
}

func requireNotAdmitted(t *testing.T, id string, res *service.CheckResult) {
	t.Helper()
	require.Falsef(t, res.Allowed, "%s (а): неподтверждённому — «нет»", id)
	require.Equalf(t, []string{reasonEmailNotVerified}, res.DenyReasons, "%s (а): deny_reasons", id)
}

// TestEV50_DirectGrantDoesNotActForTheUnverified — EV-50.
func TestEV50_DirectGrantDoesNotActForTheUnverified(t *testing.T) {
	for _, verified := range []bool{false, true} {
		w := newAdmWorld(t)
		const acc, owner, person = "acc-ev50", "usr-ev50own", "usr-ev50"
		w.ci.seedAccountWithOwner(t, acc, owner)
		w.ci.seedUnverifiedUser(t, person, acc)
		w.ci.factThroughJournal(t, "user:"+person, "admin", "account", acc)
		if verified {
			w.mark(t, person)
			require.True(t, w.check(t, "user:"+person, "account", acc, "admin").Allowed, "EV-50 (б): подтверждённому — «да»")
			continue
		}
		requireNotAdmitted(t, "EV-50", w.check(t, "user:"+person, "account", acc, "admin"))
	}
}

// TestEV51_WildcardRelationDoesNotActForTheUnverified — EV-51.
func TestEV51_WildcardRelationDoesNotActForTheUnverified(t *testing.T) {
	for _, verified := range []bool{false, true} {
		w := newAdmWorld(t)
		const acc, owner, person = "acc-ev51", "usr-ev51own", "usr-ev51"
		w.ci.seedAccountWithOwner(t, acc, owner)
		w.ci.seedUnverifiedUser(t, person, acc)
		w.ci.factThroughJournal(t, "user:*", "viewer", "cluster", "cluster_root")
		if verified {
			w.mark(t, person)
			require.True(t, w.check(t, "user:"+person, "cluster", "cluster_root", "viewer").Allowed, "EV-51 (б)")
			continue
		}
		requireNotAdmitted(t, "EV-51", w.check(t, "user:"+person, "cluster", "cluster_root", "viewer"))
	}
}

// TestEV52_CloudAdministratorDoesNotActWhileUnverified — EV-52.
func TestEV52_CloudAdministratorDoesNotActWhileUnverified(t *testing.T) {
	for _, verified := range []bool{false, true} {
		w := newAdmWorld(t)
		const accA, ownA, accB, ownB, admin, abn, role = "acc-ev52a", "usr-ev52oa", "acc-ev52b", "usr-ev52ob", "usr-ev52adm", "abn-ev52", "rol-ev52"
		w.ci.seedAccountWithOwner(t, accA, ownA)
		w.ci.seedAccountWithOwner(t, accB, ownB)
		w.ci.seedUnverifiedUser(t, admin, accA)
		w.ci.seedRole(t, role, accB)
		w.ci.seedBinding(t, abn, ownB, role, "account", accB)
		w.ci.factThroughJournal(t, "user:"+admin, "system_admin", "cluster", "cluster_root")
		foreign := w.check(t, "user:"+admin, "iam_access_binding", abn, "v_delete")
		direct, err := w.ci.svc.CheckRelation(context.Background(), service.CheckRelationRequest{
			Subject: "user:" + admin, Relation: "system_admin", Object: "cluster:cluster_root",
		})
		require.NoError(t, err)
		if verified {
			w.mark(t, admin)
			foreign = w.check(t, "user:"+admin, "iam_access_binding", abn, "v_delete")
			direct, err = w.ci.svc.CheckRelation(context.Background(), service.CheckRelationRequest{
				Subject: "user:" + admin, Relation: "system_admin", Object: "cluster:cluster_root",
			})
			require.NoError(t, err)
			require.True(t, foreign.Allowed, "EV-52 (б): объект чужого аккаунта — «да»")
			require.True(t, direct.Allowed, "EV-52 (б): отношение администратора облака — «да»")
			continue
		}
		requireNotAdmitted(t, "EV-52 (объект чужого аккаунта; откат к супер-доступу не спасает)", foreign)
		require.False(t, direct.Allowed, "EV-52 (а): отношение администратора облака — «нет»")
		require.Equal(t, []string{reasonEmailNotVerified}, direct.DenyReasons, "EV-52 (а): deny_reasons CheckRelation")
	}
}

// TestEV53_GroupGrantDoesNotActForTheUnverified — EV-53.
func TestEV53_GroupGrantDoesNotActForTheUnverified(t *testing.T) {
	for _, verified := range []bool{false, true} {
		w := newAdmWorld(t)
		const acc, owner, member, grp = "acc-ev53", "usr-ev53own", "usr-ev53m", "grp-ev53"
		w.ci.seedAccountWithOwner(t, acc, owner)
		w.ci.seedUnverifiedUser(t, member, acc)
		w.ci.exec(t, `INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, $2, $1)`, grp, acc)
		w.ci.exec(t, `INSERT INTO kaname.group_members (group_id, member_type, member_id) VALUES ($1, 'user', $2)`, grp, member)
		w.ci.factThroughJournal(t, "group:"+grp+"#member", "admin", "account", acc)
		if verified {
			w.mark(t, member)
			require.True(t, w.check(t, "user:"+member, "account", acc, "admin").Allowed, "EV-53 (б)")
			continue
		}
		requireNotAdmitted(t, "EV-53", w.check(t, "user:"+member, "account", acc, "admin"))
	}
}

// TestEV54_BatchQuestion — EV-54.
func TestEV54_BatchQuestion(t *testing.T) {
	for _, verified := range []bool{false, true} {
		w := newAdmWorld(t)
		const acc, owner, person, role = "acc-ev54", "usr-ev54own", "usr-ev54", "rol-ev54"
		w.ci.seedAccountWithOwner(t, acc, owner)
		w.ci.seedUnverifiedUser(t, person, acc)
		w.ci.seedRole(t, role, acc)
		w.ci.factThroughJournal(t, "user:"+person, "admin", "account", acc)
		reqs := make([]service.CheckRequest, 0, 3)
		for _, b := range []string{"abn-ev54a", "abn-ev54b", "abn-ev54c"} {
			grantee := "usr-" + strings.TrimPrefix(b, "abn-")
			w.ci.seedUnverifiedUser(t, grantee, acc)
			w.ci.seedBinding(t, b, grantee, role, "account", acc)
			reqs = append(reqs, service.CheckRequest{Subject: "user:" + person, Resource: service.ResourceRef{Type: "iam_access_binding", ID: b},
				Action: "probe.address.v_delete", RequiredRelation: "v_delete"})
		}
		if verified {
			w.mark(t, person)
		}
		out, err := w.ci.svc.BatchCheck(context.Background(), reqs)
		require.NoError(t, err)
		require.Len(t, out, 3)
		for i, r := range out {
			if verified {
				require.Truef(t, r.Allowed, "EV-54 (б): пункт %d — «да»", i)
				continue
			}
			requireNotAdmitted(t, "EV-54 пункт", r)
		}
	}
}

// TestEV55_HoldersExcludeTheUnverified — EV-55: ListSubjects и развёрнутый
// набор принципалов (форма двери ListUsers, которой отвечает ExpandAccess).
func TestEV55_HoldersExcludeTheUnverified(t *testing.T) {
	w := newAdmWorld(t)
	const acc, owner, p, q = "acc-ev55", "usr-ev55own", "usr-ev55p", "usr-ev55q"
	w.ci.seedAccountWithOwner(t, acc, owner)
	w.ci.seedUnverifiedUser(t, p, acc)
	w.ci.seedUnverifiedUser(t, q, acc)
	w.ci.factThroughJournal(t, "user:"+p, "admin", "account", acc)
	w.ci.factThroughJournal(t, "user:"+q, "admin", "account", acc)
	w.mark(t, p)

	named := func() (subjects, users []string) {
		res, err := w.ci.svc.ListSubjects(context.Background(), service.ListSubjectsRequest{
			ResourceType: "account", ResourceID: acc, Action: "iam.account.admin",
		})
		require.NoError(t, err)
		us, _, err := w.door.ListUsers(context.Background(), "account", acc, "admin", []string{"user"})
		require.NoError(t, err)
		return res.Subjects, us
	}
	subs, users := named()
	for _, set := range [][]string{subs, users} {
		require.Contains(t, set, "user:"+p, "EV-55: P назван")
		require.NotContains(t, set, "user:"+q, "EV-55: Q не назван, пока не подтвердил адрес")
	}
	w.mark(t, q)
	subs, users = named()
	for _, set := range [][]string{subs, users} {
		require.Contains(t, set, "user:"+q, "EV-55: после подтверждения Q назван")
	}
}

// TestEV56_AGrantToTheUnverifiedActsAfterVerification — EV-56: выдача
// заводится и действует после подтверждения без повторной выдачи.
func TestEV56_AGrantToTheUnverifiedActsAfterVerification(t *testing.T) {
	w := newAdmWorld(t)
	const acc, owner, q = "acc-ev56", "usr-ev56own", "usr-ev56q"
	w.ci.seedAccountWithOwner(t, acc, owner)
	w.mark(t, owner)
	w.ci.seedUnverifiedUser(t, q, acc)
	w.ci.factThroughJournal(t, "user:"+q, "admin", "account", acc)
	requireNotAdmitted(t, "EV-56", w.check(t, "user:"+q, "account", acc, "admin"))
	w.mark(t, q)
	require.True(t, w.check(t, "user:"+q, "account", acc, "admin").Allowed, "EV-56: после подтверждения — «да» без повторной выдачи")
}

// TestEV57_OwnVerbChecksOfTheService — EV-57: проверка полномочия, которую
// глагол службы спрашивает через порт отношения (приглашение в аккаунт —
// `editor` на аккаунте).
func TestEV57_OwnVerbChecksOfTheService(t *testing.T) {
	for _, verified := range []bool{false, true} {
		w := newAdmWorld(t)
		const acc, owner, editor = "acc-ev57", "usr-ev57own", "usr-ev57ed"
		w.ci.seedAccountWithOwner(t, acc, owner)
		w.ci.seedUnverifiedUser(t, editor, acc)
		w.ci.factThroughJournal(t, "user:"+editor, "editor", "account", acc)
		if verified {
			w.mark(t, editor)
		}
		ok, err := w.door.Check(context.Background(), "user:"+editor, "editor", "account:"+acc)
		require.NoError(t, err)
		require.Equalf(t, verified, ok, "EV-57 (подтверждён=%v): проверка полномочия через порт", verified)
	}
}

// TestAdmissionThirdOutcomeIsNotVerified — условие аудита поверхности («третий
// исход»): не смогли прочесть отметку — отказ, а не «подтверждён». Строки людей
// под чужим замком; близнец — хранилище отвечает.
func TestAdmissionThirdOutcomeIsNotVerified(t *testing.T) {
	w := newAdmWorld(t)
	const acc, owner, person = "acc-adm3", "usr-adm3own", "usr-adm3"
	w.ci.seedAccountWithOwner(t, acc, owner)
	w.ci.seedUnverifiedUser(t, person, acc)
	w.ci.factThroughJournal(t, "user:"+person, "admin", "account", acc)
	w.mark(t, person)
	require.True(t, w.check(t, "user:"+person, "account", acc, "admin").Allowed, "близнец: хранилище отвечает")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	holder, err := w.pool.Begin(context.Background())
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(context.Background()) }()
	_, err = holder.Exec(context.Background(), `LOCK TABLE kaname.users IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	res, err := w.ci.svc.Check(ctx, service.CheckRequest{
		Subject: "user:" + person, Resource: service.ResourceRef{Type: "account", ID: acc},
		Action: "probe.address.admin", RequiredRelation: "admin",
	})
	if err == nil {
		require.False(t, res.Allowed, "третий исход: отметку прочесть не смогли — ни в коем случае не «да»")
		return
	}
	require.True(t, strings.Contains(err.Error(), "unavailable") || strings.Contains(err.Error(), "context"),
		"третий исход — ошибка недоступности: %v", err)
}

// TestAdmissionReasonIsDisclosedOnlyToTheSubjectOrAPeer — условие аудита
// поверхности (раскрытие Р3): причина `email_not_verified` уходит только самому
// субъекту, модулю либо администратору облака; распорядитель ресурса,
// спросивший о другом человеке, получает нейтральный отказ — побайтно тот же,
// что у подтверждённого субъекта без отношения.
func TestAdmissionReasonIsDisclosedOnlyToTheSubjectOrAPeer(t *testing.T) {
	ask := func(t *testing.T, strangerVerified, strangerHolds bool) (*iamv1.AuthorizeCheckResponse, *iamv1.AuthorizeCheckResponse) {
		t.Helper()
		w := newAdmWorld(t)
		const acc, owner, admin, stranger = "acc-disc", "usr-discown", "usr-discadm", "usr-discstr"
		w.ci.seedAccountWithOwner(t, acc, owner)
		w.ci.seedUnverifiedUser(t, admin, acc)
		w.ci.seedUnverifiedUser(t, stranger, acc)
		w.ci.factThroughJournal(t, "user:"+admin, "admin", "account", acc)
		w.mark(t, admin)
		if strangerHolds {
			w.ci.factThroughJournal(t, "user:"+stranger, "editor", "account", acc)
		}
		if strangerVerified {
			w.mark(t, stranger)
		}
		h := authorize.NewHandler(w.ci.svc, nil).WithCallerAuthority(w.door)
		req := &iamv1.AuthorizeCheckRequest{Subject: "user:" + stranger, Resource: &iamv1.ResourceRef{Type: "account", Id: acc},
			Action: "iam.account.edit", RequiredRelation: "editor"}
		delegated, err := h.Check(operations.WithPrincipal(context.Background(), operations.Principal{ID: admin, Type: "user"}), req)
		require.NoError(t, err)
		self, err := h.Check(operations.WithPrincipal(context.Background(), operations.Principal{ID: stranger, Type: "user"}), req)
		require.NoError(t, err)
		return delegated, self
	}
	delegated, self := ask(t, false, true)
	twin, _ := ask(t, true, false)
	require.False(t, delegated.GetAllowed())
	require.Equal(t, twin.GetDenyReasons(), delegated.GetDenyReasons(),
		"распорядителю — нейтральный отказ, побайтно как у подтверждённого субъекта без отношения")
	require.Equal(t, []string{reasonEmailNotVerified}, self.GetDenyReasons(), "самому субъекту — email_not_verified")
}
