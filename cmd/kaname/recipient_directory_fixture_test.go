// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recipient_directory_fixture_test.go — ФИКСТУРА проб справочника адресов
// (приёмка NTF-3, kacho#2918, полоса X4D; Р7, Р28; фон G0 §5 приёмки).
//
// Предмета здесь нет: файл собирается на дереве, где справочника ещё нет, и
// каждое его средство проверяет СВОЙ исход раньше, чем проба спросит предмет
// (скил `change-graph` §2: «фикстура → близнец → предмет»). Средства, чей
// исход зависит от предмета (тип модели справочника, строка манифеста), здесь
// НЕ проверяются ответом двери — только числом строк, которые фикстура сама
// положила: иначе отсутствующий предмет выдал бы себя за сломанную фикстуру.
//
// Мир G0 в форме службы доступа:
//
//	acc-1 (владелец usr-own), prj-1 и prj-2 в acc-1;
//	usr-A, usr-B, usr-E, usr-blk(BLOCKED) — прямая привязка на prj-1;
//	usr-C — привязка на acc-1 (прямой на проекте нет); usr-D — член grp-1,
//	у которой привязка на prj-1; usr-F — привязка на prj-1 с истёкшим сроком,
//	usr-G — отозванная; sva-1 — сервисный аккаунт с привязкой на prj-1;
//	usr-X — без привязок; usr-ca — администратор облака;
//	адреса подтверждены у всех людей.
//
// Право чтения ресурса (`v_get`) — прямыми фактами модели (источник 1 формы
// вердикта, `relverdict` TestAsk_DirectFactAllows): `usr-A` видит vol-1, vol-2
// и acc-1; `usr-B`, `usr-blk`, `sva-1` — vol-1; `usr-E` — project:prj-1 и ни
// одного ресурса модуля; vol-20 (prj-2) не видит никто из них. Привязки
// (`access_bindings`) — предмет `ListProjectAudience`, а не источник `v_get`
// для `Resolve`: так два метода судятся по разным осям мира, и отказ одного
// не маскируется миром другого.
package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	// rdDirectoryType / rdDirectoryRoot — объект справочника (Р28).
	rdDirectoryType = "notification_recipient_directory"
	rdDirectoryRoot = rdDirectoryType + ":root"

	// rdStorageSAN — сертификат storage: SAN не ключ таблицы звена (NTF3-27).
	rdStorageSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-storage"
	// rdNotifyAPISAN — сертификат notify-api: SAN не ключ таблицы звена (Р8).
	rdNotifyAPISAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-notify-api"

	// Записи перечня звена Р2 в форме файла (Р28).
	rdResolveKey  = "kaname.cloud.iam.v1.InternalNotificationRecipientService/Resolve"
	rdAudienceKey = "kaname.cloud.iam.v1.InternalNotificationRecipientService/ListProjectAudience"
	rdServiceName = "kaname.cloud.iam.v1.InternalNotificationRecipientService"
)

// rdIdentityYAML — ключ `authn.service-identity` G0: перечень `{ResolveSend}` +
// методы справочника полосы, таблица `{SAN notify → notify}`.
func rdIdentityYAML() string {
	return ntfServiceIdentityYAML([]string{ntfResolveSendKey, rdResolveKey, rdAudienceKey},
		[][2]string{{ntfNotifySAN, "notify"}})
}

// rdPeople — люди G0 и их состояние.
var rdPeople = []struct{ id, email, state string }{
	{"usr-own", "own@example.test", "ACTIVE"},
	{"usr-A", "a@example.test", "ACTIVE"},
	{"usr-B", "b@example.test", "ACTIVE"},
	{"usr-C", "c@example.test", "ACTIVE"},
	{"usr-D", "d@example.test", "ACTIVE"},
	{"usr-E", "e@example.test", "ACTIVE"},
	{"usr-F", "f@example.test", "ACTIVE"},
	{"usr-G", "g@example.test", "ACTIVE"},
	{"usr-X", "x@example.test", "ACTIVE"},
	{"usr-blk", "blk@example.test", "BLOCKED"},
	{"usr-ca", "ca@example.test", "ACTIVE"},
}

// rdVGet — прямые факты `v_get` G0.
var rdVGet = [][3]string{
	{"storage_volume", "vol-1", "user:usr-A"},
	{"storage_volume", "vol-2", "user:usr-A"},
	{"storage_volume", "vol-1", "user:usr-B"},
	{"storage_volume", "vol-1", "user:usr-blk"},
	{"storage_volume", "vol-1", "service_account:sva-1"},
	{"project", "prj-1", "user:usr-E"},
	{"account", "acc-1", "user:usr-A"},
}

func rdExec(t *testing.T, db *ntfDB, what, sql string, args ...any) {
	t.Helper()
	_, err := db.fixture.Exec(context.Background(), sql, args...)
	require.NoError(t, err, "фикстура G0: %s не легло", what)
}

func rdCount(t *testing.T, db *ntfDB, sql string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, db.fixture.QueryRow(context.Background(), sql, args...).Scan(&n))
	return n
}

// rdSeedG0 — мир G0. withDirectoryReader — завести факт
// `service:notify reader notification_recipient_directory:root` напрямую (ось
// «право notify на справочник» отделена от оси «строка манифеста», которую
// судит NTF3-50).
func rdSeedG0(t *testing.T, db *ntfDB, door *service.AuthorizeService, withDirectoryReader bool) {
	t.Helper()
	ctx := context.Background()

	// Аккаунт и люди — одной транзакцией: ключи владельца и аккаунта взаимные
	// и отложенные.
	var b strings.Builder
	b.WriteString("BEGIN;\nINSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ('acc-1', 'x4d-acc', 'usr-own');\n")
	for _, p := range rdPeople {
		fmt.Fprintf(&b, "INSERT INTO kaname.users (id, external_id, email, account_id, invite_status) "+
			"VALUES ('%s', 'ext-%s', '%s', 'acc-1', '%s');\n", p.id, p.id, p.email, p.state)
	}
	b.WriteString("COMMIT;")
	rdExec(t, db, "аккаунт и люди", b.String())
	rdExec(t, db, "отметки подтверждения адреса", `UPDATE kaname.users SET email_verified_at = now() WHERE account_id = 'acc-1'`)
	require.Equal(t, len(rdPeople), rdCount(t, db,
		`SELECT count(*) FROM kaname.users WHERE account_id = 'acc-1' AND email_verified_at IS NOT NULL`),
		"фикстура G0: не у всех людей подтверждён адрес")

	rdExec(t, db, "проекты", `INSERT INTO kaname.projects (id, account_id, name) VALUES
		('prj-1', 'acc-1', 'x4d-prj-1'), ('prj-2', 'acc-1', 'x4d-prj-2')`)
	rdExec(t, db, "сервисный аккаунт", `INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ('sva-1', 'acc-1', 'x4d-sva-1')`)
	rdExec(t, db, "группа", `INSERT INTO kaname.groups (id, account_id, name) VALUES ('grp-1', 'acc-1', 'x4d-grp-1')`)
	rdExec(t, db, "член группы", `INSERT INTO kaname.group_members (group_id, member_type, member_id) VALUES ('grp-1', 'user', 'usr-D')`)

	var role string
	require.NoError(t, db.fixture.QueryRow(ctx,
		`SELECT id FROM kaname.roles WHERE live AND is_system ORDER BY id LIMIT 1`).Scan(&role),
		"фикстура G0: живой системной роли нет — привязкам не на что ссылаться")
	type binding struct{ id, subjectType, subjectID, resourceType, resourceID, extra string }
	for _, bd := range []binding{
		{"acb-x4d-a", "user", "usr-A", "project", "prj-1", ""},
		{"acb-x4d-b", "user", "usr-B", "project", "prj-1", ""},
		{"acb-x4d-e", "user", "usr-E", "project", "prj-1", ""},
		{"acb-x4d-blk", "user", "usr-blk", "project", "prj-1", ""},
		{"acb-x4d-c", "user", "usr-C", "account", "acc-1", ""},
		{"acb-x4d-grp", "group", "grp-1", "project", "prj-1", ""},
		{"acb-x4d-sva", "service_account", "sva-1", "project", "prj-1", ""},
		{"acb-x4d-f", "user", "usr-F", "project", "prj-1", "expired"},
		{"acb-x4d-g", "user", "usr-G", "project", "prj-1", "revoked"},
	} {
		rdBind(t, db, role, bd.id, bd.subjectType, bd.subjectID, bd.resourceType, bd.resourceID, bd.extra)
	}
	require.Equal(t, 9, rdCount(t, db, `SELECT count(*) FROM kaname.access_bindings WHERE id LIKE 'acb-x4d-%'`),
		"фикстура G0: привязки легли не все")

	for _, f := range rdVGet {
		rdExec(t, db, "факт v_get "+f[0]+":"+f[1]+" "+f[2],
			`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject) VALUES ($1, $2, 'v_get', $3)`,
			f[0], f[1], f[2])
	}
	// Администратор облака — тем же фактом, что у посеянного миграцией.
	rdExec(t, db, "администратор облака usr-ca", `
		INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		SELECT object_type, object_id, 'system_admin', 'user:usr-ca' FROM kaname.relation_fact
		 WHERE object_type = 'cluster' AND relation = 'system_admin' LIMIT 1`)

	// Мир судится ДВЕРЬЮ, а не своими строками: вопросы, на которые фикстура
	// опирается, заданы до предмета.
	rdRequireDoor(t, door, "user:usr-A", "v_get", "storage_volume:vol-1", true)
	rdRequireDoor(t, door, "user:usr-A", "v_get", "storage_volume:vol-20", false)
	rdRequireDoor(t, door, "user:usr-E", "v_get", "project:prj-1", true)
	rdRequireDoor(t, door, "user:usr-A", "v_get", "account:acc-1", true)
	rdRequireDoor(t, door, "user:usr-ca", "system_admin", "cluster:cluster_root", true)

	if withDirectoryReader {
		rdExec(t, db, "читатель справочника", `
			INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
			VALUES ($1, 'root', 'reader', 'service:notify')`, rdDirectoryType)
		require.Equal(t, 1, ntfFactCount(t, db, "service:notify", "reader", rdDirectoryType, "root"))
	}
}

// rdBind — привязка роли на область с субъектом и её строка субъекта.
func rdBind(t *testing.T, db *ntfDB, role, id, subjectType, subjectID, resourceType, resourceID, extra string) {
	t.Helper()
	switch extra {
	case "expired":
		rdExec(t, db, "истёкшая привязка "+id, `
			INSERT INTO kaname.access_bindings
			       (id, subject_type, subject_id, role_id, resource_type, resource_id, status, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', now() - interval '2 hours', now() - interval '1 hour')`,
			id, subjectType, subjectID, role, resourceType, resourceID)
	case "revoked":
		rdExec(t, db, "отозванная привязка "+id, `
			INSERT INTO kaname.access_bindings
			       (id, subject_type, subject_id, role_id, resource_type, resource_id, status, revoked_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'REVOKED', now())`,
			id, subjectType, subjectID, role, resourceType, resourceID)
	default:
		rdExec(t, db, "привязка "+id, `
			INSERT INTO kaname.access_bindings
			       (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`,
			id, subjectType, subjectID, role, resourceType, resourceID)
	}
	rdExec(t, db, "субъект привязки "+id, `
		INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id) VALUES ($1, $2, $3)`,
		id, subjectType, subjectID)
}

func rdRequireDoor(t *testing.T, door *service.AuthorizeService, subject, relation, object string, want bool) {
	t.Helper()
	res, err := door.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: subject, Relation: relation, Object: object,
	})
	require.NoError(t, err, "фикстура G0: дверь не ответила на {%s %s %s}", subject, relation, object)
	require.Equal(t, want, res.Allowed, "фикстура G0: дверь на {%s %s %s} ответила %v — мир не тот, что объявлен",
		subject, relation, object, res.Allowed)
}

// rdModelQuestions — операторы пула службы, задавшие модели вопрос о глаголе
// чтения (`v_get`), кроме вопроса о праве вызывающего на сам справочник.
// Положительный контроль — rdRequireWireSeesVGet.
func rdModelQuestions(w *ntfWire) []ntfStatement {
	var out []ntfStatement
	for _, s := range w.snapshot() {
		vget, directory := false, false
		for _, a := range s.args {
			if strings.Contains(a, "v_get") {
				vget = true
			}
			if strings.Contains(a, rdDirectoryType) {
				directory = true
			}
		}
		if vget && !directory {
			out = append(out, s)
		}
	}
	return out
}

// rdAsked — среди вопросов есть {subject, v_get, objectType:objectID}.
func rdAsked(qs []ntfStatement, subject, objectType, objectID string) bool {
	for _, s := range qs {
		var subj, typ, id bool
		for _, a := range s.args {
			subj = subj || strings.Contains(a, subject)
			typ = typ || strings.Contains(a, objectType)
			id = id || strings.Contains(a, objectID)
		}
		if subj && typ && id {
			return true
		}
	}
	return false
}

// rdRequireWireSeesVGet — положительный контроль журнала операторов: вопрос
// двери о `v_get`, заданный фикстурой, в журнале виден со своим субъектом и
// объектом. Без него «вопросов 0» в пробе было бы неотличимо от слепого счёта.
func rdRequireWireSeesVGet(t *testing.T, db *ntfDB, door *service.AuthorizeService) {
	t.Helper()
	db.wire.reset()
	rdRequireDoor(t, door, "user:usr-A", "v_get", "storage_volume:vol-1", true)
	qs := rdModelQuestions(db.wire)
	require.True(t, rdAsked(qs, "usr-A", "storage_volume", "vol-1"),
		"фикстура: журнал операторов не видит вопроса двери о v_get (вопросов %d, операторов %d) — "+
			"счёт вопросов к модели в пробе слеп", len(qs), len(db.wire.snapshot()))
	db.wire.reset()
}
