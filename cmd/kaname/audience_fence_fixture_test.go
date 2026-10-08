// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// audience_fence_fixture_test.go — ФИКСТУРА проб полосы K3 приёмки NTF-3
// (kacho#2918, редакция 42, отпечаток 1d7d2ad0…73ba): справочник отвечает на
// вопрос об аудитории версии события — `ListEventAudience` и
// `Resolve{audience = event}` (плюс `account_reader`, `via_subscription`) с
// оградой токена версии прав `R_E` (Р7, Р30).
//
// Предмета здесь нет. Файл собирается на дереве, где ни метода
// `ListEventAudience`, ни формы `event`, ни поколения объекта ещё нет, и
// каждое его средство проверяет СВОЙ исход раньше, чем проба спросит предмет
// (скил `change-graph` §2: «фикстура → близнец → предмет»).
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРИ ИСХОДА, И ОНИ РАЗЛИЧИМЫ ПО ТЕКСТУ ОТКАЗА
//
//	afNotRun  «НЕ ВЫПОЛНИЛОСЬ — условие не создано: …» — средство построения
//	          условия (§8 приёмки) в дереве отсутствует; вердикта нет;
//	afBroken  «ФИКСТУРА СЛОМАНА: …» — мир не тот, что объявлен; вердикта нет;
//	afAbsent  «КРАСНЫЙ — предмета нет: …» — испытуемый объявил свой набор
//	          возможностей (дескриптор контракта, закрытый перечень звена), и
//	          нужной в нём нет.
//
// Порядок несущий: всё «Дано» сценария — мир GW, применение поколений (С24),
// выдачи и снятия прав, токены — строится ДО первого вопроса о предмете;
// проба возможности стоит после всей фикстуры.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ВЫЗОВ ИДЁТ ЧЕРЕЗ ДЕСКРИПТОР, А НЕ ЧЕРЕЗ СГЕНЕРИРОВАННЫЙ КЛИЕНТ
//
// Типов `ListEventAudienceRequest` и поля `event` у `ResolveRecipientRequest`
// в дереве нет. Проба, написанная по сгенерированным типам, не собиралась бы
// вовсе — и уронила бы сборку всего пакета вместе с соседними пробами, а
// «не собралось» не различает «предмета нет» и «проба сломана». Здесь запрос
// строится по дескриптору, который регистрирует сам контракт
// (`protoregistry.GlobalFiles`), по ИМЕНАМ полей приёмки (Р7, Р3): до
// реализации проба исполняется и находит отсутствие метода; после — тот же
// файл строит тот же запрос из настоящего дескриптора без правки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ТОКЕН ВЕРСИИ ПРАВ И ПРИМЕНЕНИЕ ПОКОЛЕНИЯ (С24)
//
// `R_E` снимает его производитель — читатель, которым отвечает
// `InternalIAMService/CurrentAuthzRevision` (полоса K1), ПЕРЕД применением
// поколения. Поколение применяет сценарий использования регистрации тем же
// путём, что вызов модуля: набор события (структурный кортеж
// `project:<проект> project <object>`), метки, цепь и `generation` (полоса
// K2); снятие — объектом и поколением. Каждое применение судит свой исход
// головой объекта раньше вопроса о предмете. Сравнение ограды проба судит по
// снимку, а не по числу (`pg_visible_in_snapshot`).
//
// ─────────────────────────────────────────────────────────────────────────────
// МИР GW (§9 группа W приёмки) в форме службы доступа
//
//	acc-1 (владелец usr-own), prj-1 в acc-1; группа grp-1 (член usr-D);
//	роль «модуль storage целиком» — привязки usr-A, usr-B, usr-blk(BLOCKED)
//	и grp-1 на prj-1, usr-C на acc-1; у usr-M — своя роль той же формы на
//	prj-1; роль «тип тома» — usr-T на prj-1 и
//	sva-1 (сервисный аккаунт) на prj-1; роль «тип тома, метки env=prod» —
//	usr-L на prj-1; usr-E — право на project:prj-1 без правила на тома;
//	usr-ca — администратор облака (факт на кластере); usr-R, usr-O, usr-K,
//	usr-X, usr-P* — без привязок.
//
// Аудитория тома в prj-1 с метками {env: prod} — 9 субъектов
// {usr-A, usr-B, usr-C, usr-D, usr-L, usr-M, usr-T, usr-blk, usr-own}.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	internaliamapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kaname/pkg/ownerregister"
)

const (
	// afListMethod — метод перечня аудитории (Р7).
	afListMethod = "ListEventAudience"
	// afListKey — запись закрытого перечня звена Р2 в форме файла (Р28).
	afListKey = rdServiceName + "/" + afListMethod
	// afNamespace — пространство имён тома.
	afNamespace = "storage"
	// afVolume — тип модели тома.
	afVolume = "storage_volume"
)

// ── три исхода ──────────────────────────────────────────────────────────────

func afNotRun(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf("НЕ ВЫПОЛНИЛОСЬ — условие не создано: "+format, args...)
}

func afBroken(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf("ФИКСТУРА СЛОМАНА: "+format, args...)
}

func afAbsent(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf("КРАСНЫЙ — предмета нет: "+format, args...)
}

// ── мир GW ──────────────────────────────────────────────────────────────────

// afPeople — люди мира и их состояние.
var afPeople = []struct{ id, email, state string }{
	{"usr-own", "own@example.test", "ACTIVE"},
	{"usr-A", "a@example.test", "ACTIVE"},
	{"usr-B", "b@example.test", "ACTIVE"},
	{"usr-C", "c@example.test", "ACTIVE"},
	{"usr-D", "d@example.test", "ACTIVE"},
	{"usr-E", "e@example.test", "ACTIVE"},
	{"usr-L", "l@example.test", "ACTIVE"},
	{"usr-M", "m@example.test", "ACTIVE"},
	{"usr-T", "t@example.test", "ACTIVE"},
	{"usr-R", "r@example.test", "ACTIVE"},
	{"usr-O", "o@example.test", "ACTIVE"},
	{"usr-K", "k@example.test", "ACTIVE"},
	{"usr-X", "x@example.test", "ACTIVE"},
	{"usr-blk", "blk@example.test", "BLOCKED"},
	{"usr-ca", "ca@example.test", "ACTIVE"},
	{"usr-P0", "p0@example.test", "ACTIVE"},
	{"usr-P1", "p1@example.test", "ACTIVE"},
	{"usr-P2", "p2@example.test", "ACTIVE"},
	{"usr-P3", "p3@example.test", "ACTIVE"},
	{"usr-P4", "p4@example.test", "ACTIVE"},
	{"usr-P5", "p5@example.test", "ACTIVE"},
	{"usr-P6", "p6@example.test", "ACTIVE"},
	{"usr-P7", "p7@example.test", "ACTIVE"},
}

// Роли мира. Форма строк — та, что кладёт прод: роль системная (`cluster_id`),
// проекция глаголов — тип в форме КАТАЛОГА, глагол каталога (`get`);
// селектор — ветвь правила (`anchor` · `labels` · `names`).
const (
	afRoleModule = "rol-k3-module"
	// afRoleModuleM — та же форма правила «модуль storage целиком», но своя
	// роль usr-M: близнец NTF3-183 снимает `get` у роли ИМЕННО его привязки, и
	// прочие субъекты от этого факта не зависят.
	afRoleModuleM  = "rol-k3-module-m"
	afRoleType     = "rol-k3-type"
	afRoleLabels   = "rol-k3-labels"
	afRoleRegistry = "rol-k3-registry"
)

// afGWBindings — привязки мира: id, тип и id субъекта, роль, область.
var afGWBindings = []struct{ id, subjectType, subjectID, role, scopeType, scopeID string }{
	{"acb-k3-a", "user", "usr-A", afRoleModule, "project", "prj-1"},
	{"acb-k3-b", "user", "usr-B", afRoleModule, "project", "prj-1"},
	{"acb-k3-blk", "user", "usr-blk", afRoleModule, "project", "prj-1"},
	{"acb-k3-m", "user", "usr-M", afRoleModuleM, "project", "prj-1"},
	{"acb-k3-grp", "group", "grp-1", afRoleModule, "project", "prj-1"},
	{"acb-k3-c", "user", "usr-C", afRoleModule, "account", "acc-1"},
	{"acb-k3-t", "user", "usr-T", afRoleType, "project", "prj-1"},
	{"acb-k3-sva", "service_account", "sva-1", afRoleType, "project", "prj-1"},
	{"acb-k3-l", "user", "usr-L", afRoleLabels, "project", "prj-1"},
}

// afGW9 — аудитория тома prj-1 с метками {env: prod} в мире GW.
var afGW9 = []string{"usr-A", "usr-B", "usr-C", "usr-D", "usr-L", "usr-M", "usr-T", "usr-blk", "usr-own"}

// afWorld — служба доступа пробы K3.
type afWorld struct {
	db        *ntfDB
	door      *service.AuthorizeService
	relations *authzcascade.Client
	reg       *internaliamapp.RegisterResourceUseCase
	lis       *ntfListener
	pki       *ntfPKI
}

// afWorldOption — отступление мира от GW ровно одним фактом (близнецы).
type afWorldOption func(*afSeed)

type afSeed struct {
	skipBinding    map[string]bool
	extraBindings  []afBinding
	caOnCluster    bool
	blkReadsAcc    bool
	vgetProjectUsr bool
	adminOnAccount [][2]string
}

type afBinding struct{ id, subjectType, subjectID, role, scopeType, scopeID string }

// afWithout — привязка мира не кладётся (близнец буквы охвата).
func afWithout(bindingID string) afWorldOption {
	return func(s *afSeed) { s.skipBinding[bindingID] = true }
}

// afWith — дополнительная привязка до первого токена.
func afWith(b afBinding) afWorldOption {
	return func(s *afSeed) { s.extraBindings = append(s.extraBindings, b) }
}

// afAdminOnAccount — привязка системной роли администратора на acc-1 у
// пользователя userID (близнец «уровень права»: путь через account).
func afAdminOnAccount(bindingID, userID string) afWorldOption {
	return func(s *afSeed) { s.adminOnAccount = append(s.adminOnAccount, [2]string{bindingID, userID}) }
}

// afNoClusterAdmin — usr-ca не администратор облака (близнец NTF3-176).
func afNoClusterAdmin() afWorldOption { return func(s *afSeed) { s.caOnCluster = false } }

func newAFWorld(t *testing.T, opts ...afWorldOption) *afWorld {
	t.Helper()
	s := &afSeed{skipBinding: map[string]bool{}, caOnCluster: true, blkReadsAcc: true, vgetProjectUsr: true}
	for _, o := range opts {
		o(s)
	}
	db := newNTFDB(t)
	door, relations := ntfDoor(db)
	requireWireSeesDoorQuestions(t, db, door)
	afSeedGW(t, db, door, s)
	w := &afWorld{db: db, door: door, relations: relations, pki: newNTFPKI(t)}
	w.reg = internaliamapp.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(db.fixture),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		kanamepg.NewResidualTupleReader(),
	).WithReconcile(kanamepg.NewReconcileEventEmitter()).
		WithAccountResolver(kanamepg.NewProjectAccountResolver()).
		// Синхронная материализация после применения — как в корне: применение
		// поколения пишет материализованные кортежи привязок области (NTF3-174 (м)).
		WithObjectReconciler(reconcileapp.New(kanamepg.NewReconcileAdapter(db.fixture, catalogfixture.Source()),
			slog.New(slog.NewTextHandler(io.Discard, nil)), catalogfixture.Source()),
			slog.New(slog.NewTextHandler(io.Discard, nil)))
	return w
}

func afExec(t *testing.T, db *ntfDB, what, sql string, args ...any) {
	t.Helper()
	if _, err := db.fixture.Exec(context.Background(), sql, args...); err != nil {
		afBroken(t, "%s не легло: %v", what, err)
	}
}

func afCount(t *testing.T, db *ntfDB, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := db.fixture.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		afBroken(t, "перепись (%s): %v", sql, err)
	}
	return n
}

// afCatalog — тип в форме каталога; неизвестный тип — фикстура сломана.
func afCatalog(t *testing.T, modelType string) string {
	t.Helper()
	dotted, known := authzmap.DottedType(modelType)
	if !known {
		afBroken(t, "тип %q не объявлен в каталоге", modelType)
	}
	return dotted
}

// afSeedRole — роль, её проекция глаголов и селектор одной ветви. Правило
// кодируется кодером продукта (`domain.EncodeRules`): досев старта
// пересобирает селекторы системных ролей из правил, и правило, записанное не
// той формой, дало бы ДРУГОЙ селектор — фикстура судила бы не тот мир.
func afSeedRole(t *testing.T, db *ntfDB, roleID string, rule domain.Rule, modelTypes []string, arm, matchLabels string) {
	t.Helper()
	types := make([]string, 0, len(modelTypes))
	for _, mt := range modelTypes {
		types = append(types, afCatalog(t, mt))
	}
	rules, err := domain.EncodeRules(domain.Rules{rule})
	if err != nil {
		afBroken(t, "правило роли %s не кодируется: %v", roleID, err)
	}
	afExec(t, db, "роль "+roleID, `
		INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
		VALUES ($1, $2, '[]'::jsonb, $3::jsonb, 'cluster_root')`, roleID, roleID, string(rules))
	for _, ct := range types {
		afExec(t, db, "проекция глагола роли "+roleID,
			`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'get')`, roleID, ct)
	}
	names := rule.ResourceNames
	if names == nil {
		names = []string{}
	}
	afExec(t, db, "селектор роли "+roleID, `
		INSERT INTO kaname.role_rule_selectors (role_id, rule_fp, arm, object_types, match_labels, resource_names)
		VALUES ($1, $2, $3, $4::text[], $5::jsonb, $6::text[])`,
		roleID, rule.Fingerprint(), arm, types, matchLabels, names)
}

func afSeedGW(t *testing.T, db *ntfDB, door *service.AuthorizeService, s *afSeed) {
	t.Helper()
	var b strings.Builder
	b.WriteString("BEGIN;\nINSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ('acc-1', 'k3-acc', 'usr-own');\n")
	for _, p := range afPeople {
		fmt.Fprintf(&b, "INSERT INTO kaname.users (id, external_id, email, account_id, invite_status) "+
			"VALUES ('%s', 'ext-%s', '%s', 'acc-1', '%s');\n", p.id, p.id, p.email, p.state)
	}
	b.WriteString("COMMIT;")
	afExec(t, db, "аккаунт и люди", b.String())
	afExec(t, db, "отметки подтверждения адреса", `UPDATE kaname.users SET email_verified_at = now() WHERE account_id = 'acc-1'`)
	afExec(t, db, "проекты", `INSERT INTO kaname.projects (id, account_id, name) VALUES
		('prj-1', 'acc-1', 'k3-prj-1'), ('prj-2', 'acc-1', 'k3-prj-2')`)
	// Указатель проекта на аккаунт — В ЖУРНАЛ, как его кладёт `Project.Create`
	// той же транзакцией, что строку проекта: из него цепь областей выводит
	// звено «проект → аккаунт».
	for _, prj := range []string{"prj-1", "prj-2"} {
		afExec(t, db, "указатель "+prj+" → acc-1", `
			INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
			VALUES ('fga.tuple.write', jsonb_build_object('user', 'account:acc-1', 'relation', 'account',
			        'object', 'project:' || $1::text), now())`, prj)
		if afCount(t, db, `SELECT count(*) FROM kaname.relation_fact WHERE object_type = 'project' AND object_id = $1
			AND relation = 'account' AND subject = 'account:acc-1'`, prj) != 1 {
			afBroken(t, "указатель %s → acc-1 не спроецировался в факты", prj)
		}
	}
	afExec(t, db, "сервисный аккаунт", `INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ('sva-1', 'acc-1', 'k3-sva-1')`)
	afExec(t, db, "группа", `INSERT INTO kaname.groups (id, account_id, name) VALUES ('grp-1', 'acc-1', 'k3-grp-1')`)
	afExec(t, db, "член группы", `INSERT INTO kaname.group_members (group_id, member_type, member_id) VALUES ('grp-1', 'user', 'usr-D')`)
	afExec(t, db, "кластер", `INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho') ON CONFLICT DO NOTHING`)

	afSeedRole(t, db, afRoleModule, domain.Rule{Module: "storage", Resources: []string{"*"}, Verbs: []string{"get"}},
		[]string{"storage_volume", "storage_snapshot", "storage_image"}, "anchor", "{}")
	afSeedRole(t, db, afRoleModuleM, domain.Rule{Module: "storage", Resources: []string{"*"}, Verbs: []string{"get"}},
		[]string{"storage_volume", "storage_snapshot", "storage_image"}, "anchor", "{}")
	afSeedRole(t, db, afRoleType, domain.Rule{Module: "storage", Resources: []string{"volumes"}, Verbs: []string{"get"}},
		[]string{afVolume}, "anchor", "{}")
	afSeedRole(t, db, afRoleLabels, domain.Rule{Module: "storage", Resources: []string{"volumes"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"}}, []string{afVolume}, "labels", `{"env":"prod"}`)
	afSeedRole(t, db, afRoleRegistry, domain.Rule{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}},
		[]string{"registry_repository"}, "anchor", "{}")
	// Старт службы доступа — производителями продукта, в том порядке, что в
	// корне: досев выдачи владельца аккаунта (строка привязки, её субъект и
	// указатель иерархии одной транзакцией), затем пересчёт проекции глаголов
	// системных ролей из их правил (`cmd/kaname/serve.go`, досев старта).
	if err := seed.BackfillOwnerBindings(context.Background(), db.fixture); err != nil {
		afBroken(t, "выдача владельца аккаунта не посеяна: %v", err)
	}
	census, err := seed.ReseedSystemRoleVerbs(context.Background(), kanamepg.New(db.fixture, nil), db.fixture,
		catalogfixture.Facts(), nil)
	if err != nil || census.Failed > 0 || census.Reseeded == 0 {
		afBroken(t, "пересчёт проекции глаголов системных ролей: %+v, %v", census, err)
	}

	for _, role := range []string{afRoleModule, afRoleModuleM, afRoleType, afRoleLabels, afRoleRegistry} {
		if afCount(t, db, `SELECT count(*) FROM kaname.role_verb WHERE role_id = $1 AND verb = 'get'`, role) == 0 {
			afBroken(t, "у роли %s после пересчёта проекции нет глагола get", role)
		}
	}
	laid := 0
	for _, bd := range afGWBindings {
		if s.skipBinding[bd.id] {
			continue
		}
		rdBind(t, db, bd.role, bd.id, bd.subjectType, bd.subjectID, bd.scopeType, bd.scopeID, "")
		laid++
	}
	for _, bd := range s.extraBindings {
		rdBind(t, db, bd.role, bd.id, bd.subjectType, bd.subjectID, bd.scopeType, bd.scopeID, "")
		laid++
	}
	if len(s.adminOnAccount) > 0 {
		var admin string
		if err := db.fixture.QueryRow(context.Background(),
			`SELECT id FROM kaname.roles WHERE name = 'admin' AND is_system AND live`).Scan(&admin); err != nil {
			afBroken(t, "системной роли администратора нет: %v", err)
		}
		for _, b := range s.adminOnAccount {
			rdBind(t, db, admin, b[0], "user", b[1], "account", "acc-1", "")
			laid++
		}
	}
	if n := afCount(t, db, `SELECT count(*) FROM kaname.access_bindings WHERE id LIKE 'acb-k3-%'`); n != laid {
		afBroken(t, "привязок мира легло %d, ожидалось %d", n, laid)
	}
	if s.vgetProjectUsr {
		afExec(t, db, "право usr-E на проект",
			`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject) VALUES ('project', 'prj-1', 'v_get', 'user:usr-E')`)
	}
	if s.blkReadsAcc {
		// NTF3-173 (л): у usr-blk право v_get на account:acc-1.
		afExec(t, db, "право usr-blk на аккаунт",
			`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject) VALUES ('account', 'acc-1', 'v_get', 'user:usr-blk')`)
	}
	if s.caOnCluster {
		afExec(t, db, "администратор облака usr-ca", `
			INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
			SELECT object_type, object_id, 'system_admin', 'user:usr-ca' FROM kaname.relation_fact
			 WHERE object_type = 'cluster' AND relation = 'system_admin' LIMIT 1`)
		if afCount(t, db, `SELECT count(*) FROM kaname.relation_fact WHERE subject = 'user:usr-ca' AND relation = 'system_admin'`) != 1 {
			afBroken(t, "факт администратора облака usr-ca не лёг: на кластере нет посеянного system_admin")
		}
	}
	afExec(t, db, "читатель справочника", `
		INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		VALUES ($1, 'root', 'reader', 'service:notify')`, rdDirectoryType)

	// Мир судится ДВЕРЬЮ там, где ответ двери от тома не зависит.
	afRequireDoor(t, door, "user:usr-own", "v_get", "account:acc-1", true)
	afRequireDoor(t, door, "user:usr-X", "v_get", "account:acc-1", false)
	afRequireDoor(t, door, "user:usr-E", "v_get", "project:prj-1", true)
	afRequireDoor(t, door, "user:usr-X", "v_get", "project:prj-1", false)
	if s.blkReadsAcc {
		afRequireDoor(t, door, "user:usr-blk", "v_get", "account:acc-1", true)
	}
	if s.caOnCluster {
		afRequireDoor(t, door, "user:usr-ca", "system_admin", "cluster:cluster_root", true)
	}
}

func afRequireDoor(t *testing.T, door *service.AuthorizeService, subject, relation, object string, want bool) {
	t.Helper()
	res, err := door.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: subject, Relation: relation, Object: object,
	})
	if err != nil {
		afBroken(t, "дверь не ответила на {%s %s %s}: %v", subject, relation, object, err)
	}
	if res.Allowed != want {
		afBroken(t, "дверь на {%s %s %s} ответила %v, мир объявлял %v", subject, relation, object, res.Allowed, want)
	}
}

// afBind — привязка, выданная по ходу сценария (посев С1).
func (w *afWorld) afBind(t *testing.T, b afBinding) {
	t.Helper()
	rdBind(t, w.db, b.role, b.id, b.subjectType, b.subjectID, b.scopeType, b.scopeID, "")
}

// afClosedSet — выдача роли на проект с закрытым набором объектов
// `AccessTarget.resources = [storage_volume:<id>]` (форма строки — та, что
// пишет писатель продукта: `target` и его отпечаток).
func (w *afWorld) afClosedSet(t *testing.T, id, userID, role, volumeID string) {
	t.Helper()
	target := domain.AccessTarget{Resources: []domain.ResourceRef{{Type: afCatalog(t, afVolume), ID: volumeID}}}
	afExec(t, w.db, "выдача с закрытым набором "+id, `
		INSERT INTO kaname.access_bindings
		       (id, subject_type, subject_id, role_id, resource_type, resource_id, status, scope, target, target_digest)
		VALUES ($1, 'user', $2, $3, 'project', 'prj-1', 'ACTIVE', $4,
		        jsonb_build_object('resources', jsonb_build_array(jsonb_build_object('type', $5::text, 'id', $6::text))), $7)`,
		id, userID, role, int16(domain.ScopeProject), afCatalog(t, afVolume), volumeID, target.Digest())
	afExec(t, w.db, "субъект выдачи "+id, `
		INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id) VALUES ($1, 'user', $2)`, id, userID)
}

// afRevoke — снятие привязки (переход в REVOKED — та же форма, что снятие
// выдачи продуктом: строка остаётся, право уходит).
func (w *afWorld) afRevoke(t *testing.T, bindingID string) {
	t.Helper()
	afExec(t, w.db, "снятие привязки "+bindingID,
		`UPDATE kaname.access_bindings SET status = 'REVOKED', revoked_at = now() WHERE id = $1`, bindingID)
}

// afNamesRole — роль с правилом на тип тома, суженным закреплённым именем.
func (w *afWorld) afNamesRole(t *testing.T, roleID, volumeID string) {
	t.Helper()
	afSeedRole(t, w.db, roleID, domain.Rule{Module: "storage", Resources: []string{"volumes"}, Verbs: []string{"get"},
		ResourceNames: []string{volumeID}}, []string{afVolume}, "names", "{}")
}

// ── токен версии прав ───────────────────────────────────────────────────────

// afToken — `R`: токен версии прав его производителем (Р30 «Производитель
// токена», С24) — тем же читателем, которым отвечает
// `InternalIAMService/CurrentAuthzRevision`, снятым ПЕРЕД применением поколения.
func (w *afWorld) afToken(t *testing.T) string {
	t.Helper()
	r, err := kanamepg.NewAuthzRevisionReader(w.db.fixture).Current(context.Background())
	if err != nil {
		afBroken(t, "токен не снят: %v", err)
	}
	if r == "" {
		afBroken(t, "токен пуст")
	}
	return r
}

// afVisible — видна ли транзакция xid в снимке r (оракул ограды).
func (w *afWorld) afVisible(t *testing.T, xid, r string) bool {
	t.Helper()
	var v bool
	if err := w.db.fixture.QueryRow(context.Background(),
		`SELECT pg_visible_in_snapshot($1::xid8, $2::pg_snapshot)`, xid, r).Scan(&v); err != nil {
		afBroken(t, "оракул видимости (%s в %s): %v", xid, r, err)
	}
	return v
}

// ── С24: прямое применение поколения ────────────────────────────────────────

// afFacts — факты объекта на момент события (Р3).
type afFacts struct {
	project, account string
	labels           map[string]string
	prevLabels       map[string]string // nil — у события нет предыдущего поколения
	// chain — цепь предков события; nil — цепь проекта и аккаунта.
	chain []string
}

func (f afFacts) parentChain() []string {
	if f.chain != nil {
		return f.chain
	}
	return ownerregister.ParentChain(nil, f.project, f.account)
}

// afApply — регистрация поколения gen объекта typ:id с фактами f (С24): набор
// события — один структурный кортеж `project:<проект цепи> project <object>`,
// метки и цепь предков события.
func (w *afWorld) afApply(t *testing.T, typ, id string, gen int64, f afFacts) {
	t.Helper()
	labels := f.labels
	if labels == nil {
		labels = map[string]string{}
	}
	req := &iamv1.RegisterResourceRequest{
		Object:          typ + ":" + id,
		Tuples:          []*iamv1.RegisteredTuple{{SubjectId: "project:" + f.project, Relation: "project"}},
		Labels:          labels,
		ParentProjectId: f.project,
		ParentAccountId: f.account,
		// Цепь предков — той же общей функцией владельца, что шлют модули.
		ParentChain: ownerregister.ParentChain(nil, f.project, f.account),
		Generation:  gen,
	}
	if err := w.reg.Register(journalfixture.Writing(context.Background()), req); err != nil {
		afBroken(t, "С24: регистрация %s:%s поколения %d отказала: %v", typ, id, gen, err)
	}
	w.afRequireHead(t, typ, id, gen, false)
}

// afApplySet — регистрация поколения gen объекта с названным набором кортежей
// события и цепью предков (репозиторий реестра, NTF3-166).
func (w *afWorld) afApplySet(t *testing.T, object string, gen int64, tuples []*iamv1.RegisteredTuple, chain []string) {
	t.Helper()
	req := &iamv1.RegisterResourceRequest{
		Object: object, Tuples: tuples, Labels: map[string]string{}, ParentChain: chain, Generation: gen,
	}
	if err := w.reg.Register(journalfixture.Writing(context.Background()), req); err != nil {
		afBroken(t, "С24: регистрация %s поколения %d отказала: %v", object, gen, err)
	}
}

// afPublish — публикация объекта для анонимного чтения своим методом
// (`SetPublicReadPublication`, Р30 «Публикация для анонимного чтения»).
func (w *afWorld) afPublish(t *testing.T, object string, objectGeneration int64) {
	t.Helper()
	req := &iamv1.SetPublicReadPublicationRequest{
		Object: object, Published: true, PublicationVersion: timestamppb.Now(), ObjectGeneration: objectGeneration,
	}
	if err := w.reg.Publish(journalfixture.Writing(context.Background()), req); err != nil {
		afBroken(t, "публикация %s: %v", object, err)
	}
}

// afUnapply — снятие объекта поколением gen (С24): объект и поколение.
func (w *afWorld) afUnapply(t *testing.T, typ, id string, gen int64) {
	t.Helper()
	req := &iamv1.UnregisterResourceRequest{Object: typ + ":" + id, Generation: gen}
	if err := w.reg.Unregister(journalfixture.Writing(context.Background()), req); err != nil {
		afBroken(t, "С24: снятие %s:%s поколения %d отказало: %v", typ, id, gen, err)
	}
	w.afRequireHead(t, typ, id, gen, true)
}

// afRequireHead — голова объекта в службе доступа несёт применённое поколение
// (своё средство С24 судит свой исход раньше вопроса о предмете).
func (w *afWorld) afRequireHead(t *testing.T, typ, id string, gen int64, withdrawn bool) {
	t.Helper()
	var g int64
	var wd bool
	err := w.db.fixture.QueryRow(context.Background(),
		`SELECT generation, withdrawn FROM kaname.object_head WHERE object_type = $1 AND object_id = $2`,
		afCatalog(t, typ), id).Scan(&g, &wd)
	if err != nil {
		afBroken(t, "С24: голова %s:%s не прочитана: %v", typ, id, err)
	}
	if g != gen || wd != withdrawn {
		afBroken(t, "С24: голова %s:%s — поколение %d, надгробие %v; применение объявляло %d, %v", typ, id, g, wd, gen, withdrawn)
	}
}

// ── предмет: дескриптор контракта ───────────────────────────────────────────

func afService(t *testing.T) protoreflect.ServiceDescriptor {
	t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(rdServiceName))
	if err != nil {
		afBroken(t, "служба %s не зарегистрирована в процессе пробы: %v", rdServiceName, err)
	}
	return d.(protoreflect.ServiceDescriptor)
}

// afRequireListMethod — метод `ListEventAudience` объявлен контрактом.
func afRequireListMethod(t *testing.T) protoreflect.MethodDescriptor {
	t.Helper()
	sd := afService(t)
	md := sd.Methods().ByName(afListMethod)
	if md == nil {
		var have []string
		for i := 0; i < sd.Methods().Len(); i++ {
			have = append(have, string(sd.Methods().Get(i).Name()))
		}
		afAbsent(t, "у %s нет метода %s (Р7); методы контракта: %v", rdServiceName, afListMethod, have)
	}
	return md
}

// afRequireResolveForm — у `ResolveRecipientRequest.audience` есть форма form
// (Р7: `event`, `account_reader`).
func afRequireResolveForm(t *testing.T, form string) {
	t.Helper()
	m := (&iamv1.ResolveRecipientRequest{}).ProtoReflect().Descriptor()
	fd := m.Fields().ByName(protoreflect.Name(form))
	if fd == nil || fd.ContainingOneof() == nil || fd.ContainingOneof().Name() != "audience" {
		var have []string
		if o := m.Oneofs().ByName("audience"); o != nil {
			for i := 0; i < o.Fields().Len(); i++ {
				have = append(have, string(o.Fields().Get(i).Name()))
			}
		}
		afAbsent(t, "у %s.audience нет формы %q (Р7); формы контракта: %v", m.FullName(), form, have)
	}
}

// afServe — справочник за внутренним слушателем с перечнем звена Р28,
// знающим `Resolve` и `ListEventAudience`. Закрытый перечень корня, не
// знающий метода, — отсутствие предмета (Р28), а не поломка фикстуры.
func (w *afWorld) afServe(t *testing.T) {
	t.Helper()
	cfg, err := ntfConfig(t, ntfServiceIdentityYAML([]string{rdResolveKey, afListKey},
		[][2]string{{ntfNotifySAN, "notify"}}))
	if err != nil {
		afBroken(t, "настройка пробы не загрузилась: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := buildRecipientDirectoryServer(w.db.pool, w.door, w.relations, cfg, logger)
	if err != nil {
		afBroken(t, "справочник не собран: %v", err)
	}
	chain, err := internalUnaryChain(ntfChainDeps(t, &cfg, w.db))
	if err != nil {
		afAbsent(t, "цепочка внутреннего слушателя не собирается с методом %s в перечне звена (Р28): %v", afListKey, err)
	}
	w.lis = ntfServe(t, w.pki, chain, func(s grpc.ServiceRegistrar) {
		registerInternalServices(s, &services{recipientDirectoryHandler: srv}, nil, ntfMustConfig(t), nil)
	})
}

// ── построение запроса по дескриптору ───────────────────────────────────────

// afSet — поле по пути через точки; вложенные сообщения создаются.
func afSet(t *testing.T, m protoreflect.Message, path string, v any) {
	t.Helper()
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		fd := m.Descriptor().Fields().ByName(protoreflect.Name(p))
		if fd == nil || fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
			t.Fatalf("контракт Р7: у %s нет поля-сообщения %q (путь %s)", m.Descriptor().FullName(), p, path)
		}
		m = m.Mutable(fd).Message()
	}
	name := parts[len(parts)-1]
	fd := m.Descriptor().Fields().ByName(protoreflect.Name(name))
	if fd == nil {
		t.Fatalf("контракт Р7/Р3: у %s нет поля %q (путь %s)", m.Descriptor().FullName(), name, path)
	}
	switch val := v.(type) {
	case string:
		require.Equal(t, protoreflect.StringKind, fd.Kind(), "контракт: поле %s", fd.FullName())
		m.Set(fd, protoreflect.ValueOfString(val))
	case int64:
		switch fd.Kind() {
		case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
			m.Set(fd, protoreflect.ValueOfInt64(val))
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
			m.Set(fd, protoreflect.ValueOfInt32(int32(val)))
		default:
			t.Fatalf("контракт: поле %s — %s, ждали целое", fd.FullName(), fd.Kind())
		}
	case bool:
		require.Equal(t, protoreflect.BoolKind, fd.Kind(), "контракт: поле %s", fd.FullName())
		m.Set(fd, protoreflect.ValueOfBool(val))
	case map[string]string:
		require.True(t, fd.IsMap(), "контракт: поле %s не map", fd.FullName())
		mp := m.Mutable(fd).Map()
		for k, x := range val {
			mp.Set(protoreflect.ValueOfString(k).MapKey(), protoreflect.ValueOfString(x))
		}
	case []string:
		require.True(t, fd.IsList() && fd.Kind() == protoreflect.StringKind,
			"контракт: поле %s — не список строк (форма `<тип>:<id>`)", fd.FullName())
		l := m.Mutable(fd).List()
		for _, x := range val {
			l.Append(protoreflect.ValueOfString(x))
		}
	case struct{}:
		// Пустое сообщение: только выбрать форму oneof.
		require.Equal(t, protoreflect.MessageKind, fd.Kind(), "контракт: поле %s", fd.FullName())
		m.Mutable(fd)
	default:
		t.Fatalf("фикстура: значение %T не поддержано", v)
	}
}

// afSetFacts — факты события (Р3) под приставкой prefix.
func afSetFacts(t *testing.T, m protoreflect.Message, prefix string, f afFacts) {
	t.Helper()
	afSet(t, m, prefix+"facts.project_id", f.project)
	afSet(t, m, prefix+"facts.account_id", f.account)
	if len(f.labels) > 0 {
		afSet(t, m, prefix+"facts.labels", f.labels)
	} else {
		// Пустые метки выражены отсутствием элементов; поле обязано быть.
		afSet(t, m, prefix+"facts.labels", map[string]string{})
	}
	afSet(t, m, prefix+"facts.parent_chain", f.parentChain())
	if f.prevLabels != nil {
		afSet(t, m, prefix+"facts.previous_labels", f.prevLabels)
		afSet(t, m, prefix+"facts.previous_parent_chain", f.parentChain())
	}
}

// afEvent — вопрос о версии события: объект, поколение, токен, факты.
type afEvent struct {
	object string // "<тип>:<id>"; "" — поле не задано (буква отказа)
	gen    int64  // 0 — поле не задано
	rev    string // "" — поле не задано
	facts  *afFacts
}

func afVol(id string, gen int64, rev string, f afFacts) afEvent {
	return afEvent{object: afVolume + ":" + id, gen: gen, rev: rev, facts: &f}
}

// afListReq — запрос `ListEventAudience`.
func afListReq(t *testing.T, md protoreflect.MethodDescriptor, e afEvent, pageToken string, pageSize int64) *dynamicpb.Message {
	t.Helper()
	req := dynamicpb.NewMessage(md.Input())
	if e.object != "" {
		afSet(t, req, "object", e.object)
	}
	if e.gen != 0 {
		afSet(t, req, "source_version", e.gen)
	}
	if e.rev != "" {
		afSet(t, req, "authz_rev", e.rev)
	}
	if e.facts != nil {
		afSetFacts(t, req, "", *e.facts)
	}
	if pageToken != "" {
		afSet(t, req, "page_token", pageToken)
	}
	if pageSize != 0 {
		afSet(t, req, "page_size", pageSize)
	}
	return req
}

// afPage — ответ страницы: субъекты и курсор.
type afPage struct {
	subjects []string
	next     string
}

// afPageOf — субъекты — единственное повторяемое строковое поле ответа
// (имя Р7 не закрепляет), курсор — `next_page_token`.
func afPageOf(t *testing.T, resp *dynamicpb.Message) afPage {
	t.Helper()
	var p afPage
	var lists []protoreflect.FieldDescriptor
	fields := resp.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.IsList() && fd.Kind() == protoreflect.StringKind {
			lists = append(lists, fd)
		}
	}
	require.Len(t, lists, 1, "контракт Р7: у %s ровно один перечень субъектов (`user:<id>`); полей-перечней %d",
		resp.Descriptor().FullName(), len(lists))
	l := resp.Get(lists[0]).List()
	for i := 0; i < l.Len(); i++ {
		p.subjects = append(p.subjects, l.Get(i).String())
	}
	next := fields.ByName("next_page_token")
	require.NotNil(t, next, "контракт Р7: у %s нет next_page_token", resp.Descriptor().FullName())
	p.next = resp.Get(next).String()
	return p
}

// afConn — соединение пира san.
func (w *afWorld) afConn(t *testing.T, san string) *grpc.ClientConn {
	t.Helper()
	return w.lis.dial(t, san)
}

// afList — одна страница `ListEventAudience` пиром san.
func (w *afWorld) afList(t *testing.T, san string, md protoreflect.MethodDescriptor, req *dynamicpb.Message) (afPage, error) {
	t.Helper()
	resp := dynamicpb.NewMessage(md.Output())
	err := w.afConn(t, san).Invoke(context.Background(), "/"+rdServiceName+"/"+afListMethod, req, resp)
	if err != nil {
		return afPage{}, err
	}
	return afPageOf(t, resp), nil
}

// afAudience — обход всех страниц от notify; субъекты без приставки `user:`.
// Отказ на любой странице — ошибка вызова целиком (Р7 «единица — событие»).
func (w *afWorld) afAudience(t *testing.T, md protoreflect.MethodDescriptor, e afEvent) ([]string, error) {
	t.Helper()
	var all []string
	token := ""
	for i := 0; i < 64; i++ {
		page, err := w.afList(t, ntfNotifySAN, md, afListReq(t, md, e, token, 0))
		if err != nil {
			return nil, err
		}
		all = append(all, page.subjects...)
		if page.next == "" {
			return afUsers(t, all), nil
		}
		token = page.next
	}
	t.Fatalf("обход не дошёл до пустого next_page_token за 64 страницы")
	return nil, nil
}

// afMustAudience — обход без отказа.
func (w *afWorld) afMustAudience(t *testing.T, md protoreflect.MethodDescriptor, e afEvent) []string {
	t.Helper()
	got, err := w.afAudience(t, md, e)
	require.NoError(t, err, "ListEventAudience{%s, %d} отказал: %v", e.object, e.gen, err)
	return got
}

// afUsers — `user:<id>` → `<id>`; субъект иной формы — нарушение Р30.
func afUsers(t *testing.T, subjects []string) []string {
	t.Helper()
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		id, ok := strings.CutPrefix(s, "user:")
		require.True(t, ok && id != "" && id != "*",
			"субъект %q аудитории не формы user:<id> (Р30: подстановка, сервисный аккаунт, группа, system:* — не адресаты)", s)
		out = append(out, id)
	}
	return out
}

func afSorted(ids ...string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}

func afPlus(base []string, extra ...string) []string {
	return afSorted(append(append([]string(nil), base...), extra...)...)
}

func afMinus(base []string, drop ...string) []string {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	var out []string
	for _, b := range base {
		if !skip[b] {
			out = append(out, b)
		}
	}
	return afSorted(out...)
}

// ── Resolve{event} по дескриптору ───────────────────────────────────────────

// afResolveEvent — `Resolve{namespace, subject, audience = event{…}}`.
func afResolveEvent(t *testing.T, ns, subject string, e afEvent, viaSubscription bool) *iamv1.ResolveRecipientRequest {
	t.Helper()
	req := &iamv1.ResolveRecipientRequest{Namespace: ns, Subject: subject}
	m := req.ProtoReflect()
	afSet(t, m, "event", struct{}{})
	if e.object != "" {
		afSet(t, m, "event.object", e.object)
	}
	if e.gen != 0 {
		afSet(t, m, "event.source_version", e.gen)
	}
	if e.rev != "" {
		afSet(t, m, "event.authz_rev", e.rev)
	}
	if e.facts != nil {
		afSetFacts(t, m, "event.", *e.facts)
	}
	if viaSubscription {
		afSet(t, m, "event.via_subscription", true)
	}
	return req
}

// afResolveAccountReader — `Resolve{audience = account_reader{account_id}}`.
func afResolveAccountReader(t *testing.T, ns, subject, account string) *iamv1.ResolveRecipientRequest {
	t.Helper()
	req := &iamv1.ResolveRecipientRequest{Namespace: ns, Subject: subject}
	m := req.ProtoReflect()
	afSet(t, m, "account_reader", struct{}{})
	if account != "" {
		afSet(t, m, "account_reader.account_id", account)
	}
	return req
}

func (w *afWorld) afResolve(t *testing.T, san string, req *iamv1.ResolveRecipientRequest) (*iamv1.ResolveRecipientResponse, error) {
	t.Helper()
	resp, err := iamv1.NewInternalNotificationRecipientServiceClient(w.afConn(t, san)).Resolve(context.Background(), req)
	if err != nil {
		require.Nil(t, resp, "отказ с ответом: адрес не должен уходить вместе с ошибкой")
	}
	return resp, err
}

// ── отказы ──────────────────────────────────────────────────────────────────

// afRequireRefusal — код, текст (если задан), поле (если задано), причина
// ErrorInfo (если задана); субъектов и адреса при отказе нет by construction.
func afRequireRefusal(t *testing.T, err error, code, message, field, reason string) {
	t.Helper()
	require.Error(t, err, "ждали отказ %s %q", code, message)
	r := ntfRefusalOf(err)
	require.Equal(t, code, r.code, "код отказа; текст %q, причина %q", r.message, r.reason)
	if message != "" {
		require.Equal(t, message, r.message, "текст отказа")
	}
	if field != "" {
		require.Contains(t, r.fields, field, "поле нарушения; текст %q", r.message)
	}
	if reason != "" {
		require.Equal(t, reason, r.reason, "ErrorInfo.reason; текст %q", r.message)
	}
	_ = status.Code(err)
}

// ── журнал операторов: вопросы об аудитории ─────────────────────────────────

// afAudienceStatements — операторы пула службы, читающие исходные строки прав
// либо объектную сторону (вопрос об аудитории), кроме вопроса о праве
// вызывающего на справочник. Положительный контроль — базовый вызов пробы.
func afAudienceStatements(wire *ntfWire) int {
	n := 0
	for _, s := range wire.snapshot() {
		directory := false
		for _, a := range s.args {
			if strings.Contains(a, rdDirectoryType) {
				directory = true
			}
		}
		if directory {
			continue
		}
		for _, tbl := range []string{"access_bindings", "access_binding_subjects", "role_verb", "role_rule_selectors",
			"group_members", "relation_fact", "resource_mirror", "resource_parent_edge"} {
			if strings.Contains(s.sql, tbl) {
				n++
				break
			}
		}
	}
	return n
}

// ── класс исключения Р30 (паритет NTF3-181) ─────────────────────────────────

// afExclusionClass — класс, которым Р30 исключает субъекта `relverdict.Subjects`
// из аудитории; "" — класса нет (расхождение — дефект ограды).
func afExclusionClass(t *testing.T, db *ntfDB, subject string) string {
	t.Helper()
	switch {
	case subject == "user:*":
		return "подстановочное право"
	case strings.HasPrefix(subject, "service_account:"):
		return "сервисный аккаунт"
	case strings.HasPrefix(subject, "group:"):
		return "группа как адресат (раскрыта в членов)"
	case strings.HasPrefix(subject, "system:") || strings.HasPrefix(subject, "service:"):
		return "system:*"
	}
	if afCount(t, db, `SELECT count(*) FROM kaname.relation_fact WHERE subject = $1 AND object_type = 'cluster'`, subject) > 0 &&
		afCount(t, db, `SELECT count(*) FROM kaname.access_binding_subjects s JOIN kaname.access_bindings b ON b.id = s.binding_id
		 WHERE s.subject_type || ':' || s.subject_id = $1 AND b.status = 'ACTIVE'`, subject) == 0 {
		return "только уровень кластера"
	}
	if afCount(t, db, `SELECT count(*) FROM kaname.relation_fact WHERE subject = $1 AND condition_name <> ''`, subject) > 0 {
		return "условное право"
	}
	return ""
}

// afParity — расхождение ответа с живым перечислением: субъекты ответа вне
// перечисления (утечка) и субъекты перечисления вне ответа без класса.
func afParity(t *testing.T, db *ntfDB, live []string, answer []string) (leaked, unexplained []string, classes map[string]string) {
	t.Helper()
	inLive := map[string]bool{}
	for _, s := range live {
		inLive[s] = true
	}
	inAnswer := map[string]bool{}
	for _, id := range answer {
		inAnswer["user:"+id] = true
		if !inLive["user:"+id] {
			leaked = append(leaked, "user:"+id)
		}
	}
	classes = map[string]string{}
	for _, s := range live {
		if inAnswer[s] {
			continue
		}
		if c := afExclusionClass(t, db, s); c != "" {
			classes[s] = c
			continue
		}
		unexplained = append(unexplained, s)
	}
	sort.Strings(leaked)
	sort.Strings(unexplained)
	return leaked, unexplained, classes
}

// afLiveSubjects — `relverdict.Subjects` для v_get на объекте (вся выдача).
func afLiveSubjects(t *testing.T, db *ntfDB, objectType, objectID string) []string {
	t.Helper()
	ctx := context.Background()
	tx, err := db.fixture.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		afBroken(t, "транзакция перечисления: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var all []string
	after := ""
	for i := 0; i < 64; i++ {
		page, next, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
			ObjectType: objectType, ObjectID: objectID, Relation: "v_get", AfterID: after, Limit: 100,
		})
		if err != nil {
			afBroken(t, "relverdict.Subjects(%s:%s): %v", objectType, objectID, err)
		}
		all = append(all, page...)
		if next == "" {
			return all
		}
		after = next
	}
	afBroken(t, "relverdict.Subjects не дошёл до конца выдачи")
	return nil
}

// afHold — транзакция фикстуры, удерживаемая открытой (гонки ограды).
type afHold struct {
	tx  pgx.Tx
	xid string
}

// afBegin — удерживаемая транзакция гонки и её xid.
//
// Транзакция держится на СВОЁМ соединении, а не на соединении пула фикстуры.
// Удерживаемая транзакция занимает соединение до своего коммита, а предел пула
// по умолчанию — max(4, число процессоров исполнителя): проба, держащая
// одновременно больше транзакций, чем этот предел, на исполнителе с четырьмя
// процессорами ждала свободного соединения пула без срока, пока его не освободит
// она же. Число удерживаемых транзакций — предмет пробы, а не нагрузка пула, и от
// машины, на которой она исполняется, не зависит.
func (w *afWorld) afBegin(t *testing.T) *afHold {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, w.db.dsn)
	if err != nil {
		afBroken(t, "соединение транзакции гонки: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	tx, err := conn.Begin(ctx)
	if err != nil {
		afBroken(t, "транзакция гонки: %v", err)
	}
	h := &afHold{tx: tx}
	if err := tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&h.xid); err != nil {
		_ = tx.Rollback(ctx)
		afBroken(t, "xid транзакции гонки: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return h
}

// afBindIn — привязка внутри удерживаемой транзакции.
func (h *afHold) afBindIn(t *testing.T, role, id, userID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.tx.Exec(ctx, `
		INSERT INTO kaname.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', $2, $3, 'project', 'prj-1', 'ACTIVE')`, id, userID, role); err != nil {
		afBroken(t, "привязка %s в транзакции гонки: %v", id, err)
	}
	if _, err := h.tx.Exec(ctx, `
		INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id) VALUES ($1, 'user', $2)`,
		id, userID); err != nil {
		afBroken(t, "субъект привязки %s в транзакции гонки: %v", id, err)
	}
}

func (h *afHold) afCommit(t *testing.T) {
	t.Helper()
	if err := h.tx.Commit(context.Background()); err != nil {
		afBroken(t, "коммит транзакции гонки: %v", err)
	}
}
