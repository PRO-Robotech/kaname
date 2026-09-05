// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// cascade_from_committed_rows_integration_test.go — три уровня супер-доступа
// РЕШАЮТСЯ ИЗ ЗАКОММИЧЕННЫХ СТРОК, на той поверхности, которую спрашивает край.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ И ЧЕМ ОН ОТЛИЧАЕТСЯ ОТ СОСЕДНИХ ПРОБ
//
// Решение (`security.md` §«Три уровня супер-доступа») выбрало каскад вместо
// материализации ради ОДНОГО довода — аварийного пути: человек, обязанный
// починить платформу, не должен зависеть от состояния доставки. Пробы формы
// (`repo/kacho/pg/relverdict/derivation_integration_test.go` и соседи)
// утверждают этот вывод про САМУ ФОРМУ. Здесь тот же вывод спрашивается через
// `AuthorizeService.CheckRelation` — то есть через дверь, которую задаёт
// `InternalIAMService.Check`, а значит через ту, куда приходит КАЖДЫЙ запрос
// платформы. Свойство одно, поверхности разные, и разъехаться они могут молча:
// у края своя композиция вердикта (ответ формы плюс плоский надзор
// администратора облака), и провязана она в композиционном корне, а не в форме.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ИЗМЕНИЛОСЬ ПОСЛЕ СНЯТИЯ ВНЕШНЕГО ДВИЖКА
//
// Прежняя редакция файла называлась «независимость от очереди» и ставила
// конвейер в единственное состояние, различавшее два устройства: строки
// закоммичены, доставка кортежей не произошла. Такого состояния больше нет НИ
// ПРИ КАКОМ входе — цепь областей выводится из схемы (миграции 740001, 785001),
// а прямой факт приезжает проекцией журнала в той же базе. Проба, ставящая
// предпосылку, которой не бывает, утверждала бы о различии, которого нет.
//
// Живым остался сам каскад, и он проверяется здесь. Фикстуры сеются ТЕМ ЖЕ
// производителем, каким их производит продукт: строки — строками, прямой факт —
// строкой журнала, чей триггер проецирует его в `relation_fact`. Прямая вставка
// в проекцию дала бы состояние, которого продукт не производит.
//
// Настоящий Postgres. Пропускается под кратким режимом.

package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

const ciClusterObject = "cluster:cluster_kacho_root"

// ciVerbsOf — глаголы, которые ОБЪЯВЛЯЕТ этот тип, прочитанные из той же
// потиповой таблицы, которой пользуется эмиссия.
//
// Литеральный набор из пяти имён стоял здесь и перестал быть верным, когда
// `v_create` отозвали у всех типов, кроме реестра: создание вещи — не операция
// над вещью. Скопированный набор за своим предметом не следует; выведенный
// покрывает и то, о чём этот файл никогда не слышал.
func ciVerbsOf(t *testing.T, object string) []string {
	t.Helper()
	typ, _, ok := strings.Cut(object, ":")
	require.Truef(t, ok, "объект %q не имеет формы «тип:идентификатор»", object)
	verbs := authzmap.VerbRelationsOfType(typ)
	require.NotEmptyf(t, verbs, "тип %q не объявляет ни одного глагола — утверждение о нём "+
		"было бы вакуумным", typ)
	return verbs
}

// ciWorld — закоммиченное состояние iam и решатель края НАД ТОЙ ЖЕ базой.
//
// Дверь одна и та же в обоих полях сборщика: и вопрос об объекте, и плоский
// надзор администратора облака идут в неё. Именно так их провязывает
// композиционный корень (cmd/kacho-iam/wiring.go), и именно поэтому «два
// действующих источника ответа на один вопрос» здесь невозможны by construction.
type ciWorld struct {
	pool *pgxpool.Pool
	svc  *service.AuthorizeService
}

func newCIWorld(t *testing.T) *ciWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Postgres) в кратком режиме")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	door := authzcascade.Wrap(relverdict.NewAsker(pool))
	require.True(t, door.FormReachable(),
		"ПРЕДПОСЫЛКА: дверь собрана без формы — тогда КАЖДЫЙ вопрос ниже вернул бы ошибку, "+
			"а не вердикт, и ни одно утверждение файла не было бы о доступе")

	w := &ciWorld{
		pool: pool,
		svc: service.NewAuthorizeService(service.AuthorizeServiceConfig{
			Relations:           door,
			ClusterAdminChecker: door,
		}),
	}
	// Кластер — синглтон и верхнее звено цепи (миграция 740001 берёт его
	// идентификатор ИЗ СТРОКИ, а не литералом). Без строки звена нет, и весь
	// верхний ярус молча стал бы недостижим.
	w.exec(t, `INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_kacho_root', 'kacho')
	           ON CONFLICT DO NOTHING`)
	return w
}

func (w *ciWorld) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	_, err := w.pool.Exec(context.Background(), sql, args...)
	require.NoErrorf(t, err, "посев: %s", sql)
}

// seedAccountWithOwner / seedUser / seedRole / seedBinding / seedProject кладут
// ЗАКОММИЧЕННЫЕ строки и ничего больше — никакого факта отношения при них не
// заводится, и в этом весь смысл: право владельца обязано следовать из строки.
//
// `users.account_id → accounts.id` и `accounts.owner_user_id → users.id` —
// взаимная пара, и только второй ключ отложен, поэтому основатель аккаунта и его
// владелец обязаны лечь ОДНОЙ транзакцией (ровно как это делает создание
// аккаунта в проде).
func (w *ciWorld) seedAccountWithOwner(t *testing.T, accountID, ownerUserID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := w.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $1, $2)`,
		accountID, ownerUserID)
	require.NoErrorf(t, err, "посев аккаунта %s", accountID)
	_, err = tx.Exec(ctx, `INSERT INTO kacho_iam.users (id, external_id, email, account_id)
	                       VALUES ($1, $1, $1 || '@example.test', $2)`, ownerUserID, accountID)
	require.NoErrorf(t, err, "посев владельца %s", ownerUserID)
	require.NoError(t, tx.Commit(ctx))
}

func (w *ciWorld) seedUser(t *testing.T, id, accountID string) {
	t.Helper()
	w.exec(t, `INSERT INTO kacho_iam.users (id, external_id, email, account_id)
	           VALUES ($1, $1, $1 || '@example.test', $2)`, id, accountID)
}

// seedRole — аккаунт-областная роль. `name` обязано удовлетворять
// roles_custom_name_check (`^[a-z][a-z0-9_]{0,40}$`), поэтому выводится из
// идентификатора, а не равно ему.
func (w *ciWorld) seedRole(t *testing.T, id, accountID string) {
	t.Helper()
	name := strings.ReplaceAll(id, "-", "_")
	w.exec(t, `INSERT INTO kacho_iam.roles (id, account_id, name, permissions)
	           VALUES ($1, $2, $3, '["vpc.network.all.get"]'::jsonb)`, id, accountID, name)
}

func (w *ciWorld) seedBinding(t *testing.T, id, subjectID, roleID, resourceType, resourceID string) {
	t.Helper()
	w.exec(t, `INSERT INTO kacho_iam.access_bindings
	             (id, subject_type, subject_id, role_id, resource_type, resource_id)
	           VALUES ($1, 'user', $2, $3, $4, $5)`, id, subjectID, roleID, resourceType, resourceID)
}

func (w *ciWorld) seedProject(t *testing.T, id, accountID string) {
	t.Helper()
	w.exec(t, `INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ($1, $2, $1)`, id, accountID)
	// Указатель проекта на аккаунт берётся ПРОЕКЦИЕЙ ЖУРНАЛА (миграция 781001),
	// а не колонкой `projects.account_id`, поэтому сеется он тем же путём, каким
	// его кладёт продукт — строкой журнала.
	w.factThroughJournal(t, "account:"+accountID, "account", "project", id)
}

// factThroughJournal кладёт прямой факт отношения ТЕМ ЖЕ производителем, каким
// его производит продукт: строкой `fga_outbox`, которую триггер
// `relation_fact_follows_journal` проецирует в `relation_fact`.
//
// Перепись после вставки — предпосылка, а не вежливость: фикстура, ничего не
// посеявшая, дала бы пустое состояние, на котором каждое отрицание ниже зеленело
// бы даром.
func (w *ciWorld) factThroughJournal(t *testing.T, subject, relation, objectType, objectID string) {
	t.Helper()
	ctx := context.Background()
	w.exec(t, `INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
	           VALUES ('fga.tuple.write',
	                   jsonb_build_object('user', $1::text, 'relation', $2::text,
	                                      'object', $3::text || ':' || $4::text),
	                   now())`, subject, relation, objectType, objectID)
	var landed int
	require.NoError(t, w.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM kacho_iam.relation_fact
		  WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		objectType, objectID, relation, subject).Scan(&landed))
	require.Equalf(t, 1, landed,
		"ПРЕДПОСЫЛКА: факт %s:%s --%s--> %s не спроецировался в relation_fact — фикстура "+
			"ничего не посеяла", objectType, objectID, relation, subject)
}

// allowed — вопрос ТОЙ ЖЕ двери, что и у внутреннего звена платформы.
//
// Ошибка отделена от отказа намеренно: «не смог спросить» и «доступа нет» —
// разные миры, и представление первого отказом сделало бы недоступность базы
// неотличимой от законного решения.
func (w *ciWorld) allowed(t *testing.T, subject, relation, object string) bool {
	t.Helper()
	res, err := w.svc.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject:  subject,
		Relation: relation,
		Object:   object,
	})
	require.NoErrorf(t, err, "CheckRelation не вправе ошибаться (%s %s %s)", subject, relation, object)
	return res.Allowed
}

// TestCloudAdministratorReachesAnyObjectFromCommittedRows — уровень 1, тот самый
// аварийный путь, ради которого каскад и выбран.
//
// Прямой факт лежит на КЛАСТЕРЕ под именем `system_admin`, вопрос задан про
// глагол на привязке чужого аккаунта: между ними два звена цепи, и оба выводятся
// из схемы. Совпадение имён исключено by construction.
func TestCloudAdministratorReachesAnyObjectFromCommittedRows(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc        = "acc-cirows1"
		owner      = "usr-cirowsown1"
		cloudAdmin = "usr-cirowscloud1"
		stranger   = "usr-cirowsstr1"
		grantee    = "usr-cirowsgte1"
		role       = "rol-cirows1"
		binding    = "abn-cirows1"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, cloudAdmin, acc)
	w.seedUser(t, stranger, acc)
	w.seedUser(t, grantee, acc)
	w.seedRole(t, role, acc)
	w.seedBinding(t, binding, grantee, role, "account", acc)

	w.factThroughJournal(t, "user:"+cloudAdmin, "system_admin", "cluster", "cluster_kacho_root")

	for _, verb := range ciVerbsOf(t, "iam_access_binding:"+binding) {
		require.Truef(t, w.allowed(t, "user:"+cloudAdmin, verb, "iam_access_binding:"+binding),
			"уровень 1 обязан держать %s на любой привязке: аварийный путь — единственный "+
				"довод, ради которого выбран каскад", verb)
	}
	// Уровень 1 достаёт и до объекта, которым iam не владеет вовсе.
	require.True(t, w.allowed(t, "user:"+cloudAdmin, "v_delete", "vpc_network:net-cirows1"),
		"уровень 1 обязан достать до объекта, которого iam даже не владеет")

	// Отрицание рядом, и оно несущее: без него «достаёт» было бы неотличимо от
	// «разрешено всем», и проба зеленела бы на форме, не сужающей ничего.
	for _, verb := range ciVerbsOf(t, "iam_access_binding:"+binding) {
		require.Falsef(t, w.allowed(t, "user:"+stranger, verb, "iam_access_binding:"+binding),
			"член того же аккаунта БЕЗ выдачи обязан оставаться без %s", verb)
	}
	require.False(t, w.allowed(t, "user:"+grantee, "v_delete", "iam_access_binding:"+binding),
		"субъект самой привязки не становится тем самым её распорядителем")
}

// TestAccountOwnerReachesHisOwnAccountFromTheCommittedRow — владелец как
// СТРУКТУРНЫЙ источник права, и граница, которой уровни написаны.
//
// Аккаунт — собственная область пользователя: раз он заводится самообслуживанием,
// снос обязан быть так же надёжен, как заведение. Отдельно утверждается, что
// ДЕЛЕГИРОВАННЫЙ администратор аккаунта каскадит ВНУТРЬ аккаунта и никогда на сам
// аккаунт: снос арендности остаётся за владельцем и за облаком.
func TestAccountOwnerReachesHisOwnAccountFromTheCommittedRow(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc      = "acc-cirows2"
		owner    = "usr-cirowsown2"
		outsider = "usr-cirowsout2"
		delegate = "usr-cirowsdel2"
		grantee  = "usr-cirowsgte2"
		role     = "rol-cirows2"
		binding  = "abn-cirows2"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, outsider, acc)
	w.seedUser(t, delegate, acc)
	w.seedUser(t, grantee, acc)
	w.seedRole(t, role, acc)
	w.seedBinding(t, binding, grantee, role, "account", acc)

	// Право владельца — факт на аккаунте, и он появляется вместе с аккаунтом.
	w.factThroughJournal(t, "user:"+owner, "owner", "account", acc)

	for _, verb := range ciVerbsOf(t, "account:"+acc) {
		require.Truef(t, w.allowed(t, "user:"+owner, verb, "account:"+acc),
			"владелец обязан держать %s на СВОЁМ аккаунте", verb)
		require.Falsef(t, w.allowed(t, "user:"+outsider, verb, "account:"+acc),
			"посторонний член аккаунта не достаёт до объекта аккаунта (%s)", verb)
	}

	// ГРАНИЦА УРОВНЕЙ. Делегированный администратор — это выдача внутрь аккаунта,
	// а не право на сам аккаунт.
	w.factThroughJournal(t, "user:"+delegate, "admin", "account", acc)
	for _, verb := range ciVerbsOf(t, "account:"+acc) {
		require.Falsef(t, w.allowed(t, "user:"+delegate, verb, "account:"+acc),
			"делегированный администратор аккаунта не вправе достать до самого аккаунта (%s) — "+
				"снос арендности остаётся за её владельцем и за облаком", verb)
	}
	// И при этом он администратор ВНУТРИ аккаунта — иначе отрицание выше читалось
	// бы как «делегирование не работает вовсе».
	require.True(t, w.allowed(t, "user:"+delegate, "v_delete", "iam_access_binding:"+binding),
		"делегированный администратор обязан достать до выдачи ВНУТРИ своего аккаунта")
}

// TestForeignAccountAdminIsNotAdminHere — цепь называет ТОТ аккаунт, который
// назвала строка, поэтому администратор ДРУГОГО аккаунта не получает ничего.
//
// Проба отвечает на возражение «каскад разрешает слишком много»: он разрешает
// ровно по той цепи, которую даёт схема, и на соседнюю арендность не переходит.
func TestForeignAccountAdminIsNotAdminHere(t *testing.T) {
	w := newCIWorld(t)

	const (
		accA     = "acc-cirows3a"
		accB     = "acc-cirows3b"
		ownerA   = "usr-cirowsown3a"
		ownerB   = "usr-cirowsown3b"
		admB     = "usr-cirowsadm3b"
		grantee  = "usr-cirowsgte3"
		roleA    = "rol-cirows3a"
		bindingA = "abn-cirows3a"
	)
	w.seedAccountWithOwner(t, accA, ownerA)
	w.seedAccountWithOwner(t, accB, ownerB)
	w.seedUser(t, admB, accB)
	w.seedUser(t, grantee, accA)
	w.seedRole(t, roleA, accA)
	w.seedBinding(t, bindingA, grantee, roleA, "account", accA)

	w.factThroughJournal(t, "user:"+admB, "admin", "account", accB)

	// Положительный контроль: в СВОЁМ аккаунте та же выдача действует. Без него
	// отрицание ниже было бы истинно и на форме, которая не разрешает никому.
	const (
		roleB    = "rol-cirows3b"
		bindingB = "abn-cirows3b"
		granteeB = "usr-cirowsgte3b"
	)
	w.seedUser(t, granteeB, accB)
	w.seedRole(t, roleB, accB)
	w.seedBinding(t, bindingB, granteeB, roleB, "account", accB)
	require.True(t, w.allowed(t, "user:"+admB, "v_delete", "iam_access_binding:"+bindingB),
		"контроль: администратор аккаунта B достаёт до выдачи СВОЕГО аккаунта")

	for _, verb := range ciVerbsOf(t, "iam_access_binding:"+bindingA) {
		require.Falsef(t, w.allowed(t, "user:"+admB, verb, "iam_access_binding:"+bindingA),
			"администратор аккаунта B не вправе достать до привязки аккаунта A (%s)", verb)
	}
}

// TestProjectScopedBindingReachesTheAccountAdmin — цепь из ДВУХ звеньев:
// привязка → проект → аккаунт. Оба звена выводятся, ни одно не присылается
// владельцем ресурса, и именно на второй ступени обход прежде останавливался.
func TestProjectScopedBindingReachesTheAccountAdmin(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc      = "acc-cirows4"
		owner    = "usr-cirowsown4"
		accAdmin = "usr-cirowsadm4"
		stranger = "usr-cirowsstr4"
		grantee  = "usr-cirowsgte4"
		prj      = "prj-cirows4"
		role     = "rol-cirows4"
		binding  = "abn-cirows4"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, accAdmin, acc)
	w.seedUser(t, stranger, acc)
	w.seedUser(t, grantee, acc)
	w.seedProject(t, prj, acc)
	w.seedRole(t, role, acc)
	w.seedBinding(t, binding, grantee, role, "project", prj)

	w.factThroughJournal(t, "user:"+accAdmin, "admin", "account", acc)

	require.True(t, w.allowed(t, "user:"+accAdmin, "v_delete", "iam_access_binding:"+binding),
		"уровень 3 обязан достать до ПРОЕКТНОЙ привязки своего аккаунта через оба звена "+
			"цепи (привязка→проект и проект→аккаунт)")
	require.False(t, w.allowed(t, "user:"+stranger, "v_delete", "iam_access_binding:"+binding),
		"член того же аккаунта без делегирования обязан остаться без права")
}
