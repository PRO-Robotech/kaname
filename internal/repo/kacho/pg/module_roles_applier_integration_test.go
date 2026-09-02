// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// module_roles_applier_integration_test.go — ПРИМЕНИТЕЛЬ ролей модуля целиком
// доводится до настоящего Postgres (приёмка
// `services/iam/docs/engineering/acceptance/roles-come-as-data-not-migrations.md`,
// держатели Г1а, Г4, Г5 и сценарий MOD-RD-06; задача #1870).
//
// # Чем эта проба отличается от соседней, и почему её мало было
//
// `module_role_upsert_integration_test.go` доводит до сервера ОДИН ОПЕРАТОР —
// `UpsertSystemRole`. Этого мало ровно на ту величину, ради которой применитель
// и написан: между манифестом и строкой стоят ещё три вещи, и каждую производит
// база, а не Go, —
//
//  1. ВТОРАЯ запись той же транзакции (`ReplaceRuleRefs`), чьи ключи в каталог
//     решают, доедет ли правило вообще;
//  2. ГРАНИЦА транзакции: отказ на второй записи обязан унести и первую;
//  3. РАВЕНСТВО деривации `id` тому, чем адресуют строки применённые миграции.
//
// Все три невоспроизводимы в процессе: дублёр писателя
// (`moduleroles/apply_test.go`) переписывает семантику на Go и ни перечня
// столбцов, ни ключей каталога, ни границы транзакции не видит НИКОГДА. Он был
// зелёным при операторе, который Postgres не разбирал вовсе.
//
// # Что здесь утверждается — ИСХОД, а не вызов
//
// Ни одно утверждение ниже не спрашивает «позвали ли писателя». Каждое читает
// СТРОКИ, оставшиеся в базе после применения, и сверяет их с объявленным.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// applierOnLiveBase — применитель над НАСТОЯЩИМ репозиторием: тот же мост
// (`NewRepoTxRunner`), тот же паттерн писательской транзакции, что в проде.
// Подставлять сюда что-либо своё значило бы проверять свою подстановку.
func applierOnLiveBase(t *testing.T) (context.Context, *pgxpool.Pool, *moduleroles.Applier) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие — С ПРЕДЕЛОМ: проба, упавшая внутри открытой транзакции,
	// соединение не вернёт, и отложенное закрытие ждало бы его вечно, унося
	// вердикт ВСЕГО пакета.
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)
	return ctx, pool, moduleroles.NewApplier(moduleroles.NewRepoTxRunner(repo))
}

// declaredManifest — манифест модуля с одной ролью кластерного яруса. Ярус
// назван ДОСЛОВНО тем же токеном, который применитель отбирает: иной ярус он
// пропускает молча, и проба на нём утверждала бы про пустое множество.
func declaredManifest(module, roleID, description string, rules []manifest.Rule) *manifest.Manifest {
	return &manifest.Manifest{
		Module: module,
		Roles: []manifest.Role{{
			ID:          roleID,
			Description: description,
			Tier:        &manifest.Tier{TierType: domain.ScopeTypeClusterDotted, TierID: domain.ClusterSingletonID},
			Rules:       rules,
		}},
	}
}

// countRuleRefs — строк проекции объявленных сегментов у роли.
func countRuleRefs(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.RoleID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM role_rule_ref WHERE role_id = $1`, string(id)).Scan(&n))
	return n
}

// countRoleRows — строк роли по её идентификатору. Ноль означает, что
// транзакция не оставила ничего.
func countRoleRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.RoleID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM roles WHERE id = $1`, string(id)).Scan(&n))
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// Г4 · MOD-RD-13 — повторное применение против ОПЕРАТОРА, а не против дублёра
// ─────────────────────────────────────────────────────────────────────────────

// TestMODRD13ApplierAgainstTheLiveBaseWritesNothingOnTheSecondRun — применитель
// целиком, три захода подряд по одной базе.
//
// Дублёр это ПОВТОРЯЕТ, а не проверяет: «ноль записей при совпадении» у него
// написано на Go рядом с утверждением о том же. Здесь предикат отличия стоит в
// `WHERE` ветви `DO UPDATE`, и ноль затронутых строк производит сервер.
//
// Проекция сегментов проверяется на КАЖДОМ заходе: она пишется во второй записи
// той же транзакции, и заход, приведший строку и не тронувший проекцию, оставил
// бы правило без референта молча.
func TestMODRD13ApplierAgainstTheLiveBaseWritesNothingOnTheSecondRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool, applier := applierOnLiveBase(t)

	const roleID = "vpc.probe1870a.admin"
	id := domain.SystemRoleID(domain.RoleName(roleID))

	declared := declaredManifest("vpc", roleID, "Роль, объявленная манифестом модуля.",
		[]manifest.Rule{{Module: "vpc", Resources: []string{"network"}, Classes: []string{"get"}}})

	// ── 1. Строки не было: применитель её заводит ───────────────────────────
	rep, err := applier.Apply(ctx, declared)
	require.NoError(t, err, "объявленная роль обязана примениться: %s", rep)
	assert.Equal(t, 1, rep.Declared, "роль кластерного яруса обязана дойти до писателя")
	assert.Equal(t, 1, rep.Written, "первый заход обязан записать строку: %s", rep)
	assert.Equal(t, 0, rep.Unchanged, "строки не было — «без изменений» неоткуда взяться")
	assert.Equal(t, 1, countRoleRows(t, ctx, pool, id), "строка роли обязана остаться в базе")
	assert.Equal(t, 1, countRuleRefs(t, ctx, pool, id),
		"проекция объявленного сегмента пишется в ТОЙ ЖЕ транзакции, что строка роли")

	// ── 2. Объявление не менялось: ноль записей ─────────────────────────────
	rep, err = applier.Apply(ctx, declared)
	require.NoError(t, err, "повторное применение — ШТАТНЫЙ режим, а не отказ: %s", rep)
	assert.Equal(t, 0, rep.Written,
		"объявленное состояние уже стоит в строке — приведения быть не должно: %s", rep)
	assert.Equal(t, 1, rep.Unchanged, "заход обязан СКАЗАТЬ, что менять было нечего: %s", rep)
	assert.Equal(t, 1, countRuleRefs(t, ctx, pool, id),
		"проекция не переписывалась — строк столько же, сколько было")

	// ── 3. Манифест правлен: ровно одна запись ──────────────────────────────
	amended := declaredManifest("vpc", roleID, "Назначение, изменённое манифестом.",
		[]manifest.Rule{{Module: "vpc", Resources: []string{"network"}, Classes: []string{"get", "list"}}})
	rep, err = applier.Apply(ctx, amended)
	require.NoError(t, err, "правка манифеста обязана доехать: %s", rep)
	assert.Equal(t, 1, rep.Written, "объявление отличается — строка обязана быть приведена: %s", rep)
	assert.Equal(t, 0, rep.Unchanged, "отличие названо — «без изменений» здесь неверно")
	assert.Equal(t, 2, countRuleRefs(t, ctx, pool, id),
		"сегментов объявлено два — проекция обязана нести оба, иначе снятый глагол пережил бы правку")

	// Идентичность строки правкой НЕ меняется: `id` — функция имени, а имя
	// манифест не трогал. Ровно на этом держатся уже выданные права (Г5 ниже).
	var name, description string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT name, description FROM roles WHERE id = $1`, string(id)).Scan(&name, &description))
	assert.Equal(t, roleID, name, "имя роли приведением не переписывается")
	assert.Equal(t, "Назначение, изменённое манифестом.", description,
		"объявленное назначение обязано доехать до строки")
}

// ─────────────────────────────────────────────────────────────────────────────
// Г5 · MOD-RD-08 — выдача переживает применение
// ─────────────────────────────────────────────────────────────────────────────

// TestMODRD08AGrantSurvivesTheApplierRun — право, выданное на роль модуля, после
// применения указывает на ТУ ЖЕ строку.
//
// Это не педантизм. Иная деривация `id` дала бы идентификатор синтаксически
// верный и никому не соответствующий: выдача осталась бы на месте, её `role_id`
// прошёл бы проверку формы и не нашёл бы строки. Наблюдаемо это только по отказу
// в доступе у арендатора, у которого право не отзывали, — то есть позже всего и
// дальше всего от причины.
//
// Утверждается ПАРА: число строк выдачи и сам `role_id`. Одного числа мало —
// оно не изменится и тогда, когда выдача станет указывать в пустоту.
func TestMODRD08AGrantSurvivesTheApplierRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool, applier := applierOnLiveBase(t)
	repo := kachopg.New(pool, nil)

	const roleID = "vpc.probe1870b.admin"
	id := domain.SystemRoleID(domain.RoleName(roleID))

	declared := declaredManifest("vpc", roleID, "Роль, на которую выдано право.",
		[]manifest.Rule{{Module: "vpc", Resources: []string{"network"}, Classes: []string{"get"}}})
	rep, err := applier.Apply(ctx, declared)
	require.NoError(t, err, "роль обязана появиться до того, как на неё выдадут право: %s", rep)
	require.Equal(t, 1, rep.Written)

	// Право выдаётся ПОСЛЕ применителя и штатным путём: внешний ключ
	// `access_bindings_role_fk` сам удостоверяет, что строка роли существует.
	uid := mustSeedUser(t, ctx, pool, "rd08a")
	acc := seedAccount(t, ctx, repo, "acc-rd08a", uid)
	binding := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       id,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})

	before := grantsOn(t, ctx, pool, id)
	require.Equal(t, 1, before, "выдача обязана лечь на роль, иначе дальше нечего терять")

	// ── Применение с правкой: то самое место, где идентичность могла бы уехать ──
	amended := declaredManifest("vpc", roleID, "Назначение, изменённое манифестом.",
		[]manifest.Rule{{Module: "vpc", Resources: []string{"network"}, Classes: []string{"get", "list"}}})
	rep, err = applier.Apply(ctx, amended)
	require.NoError(t, err, "правка обязана примениться поверх выданного права: %s", rep)
	require.Equal(t, 1, rep.Written)

	assert.Equal(t, before, grantsOn(t, ctx, pool, id),
		"применение права не отбирает: число выдач на роль обязано остаться прежним")

	var roleIDAfter string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT role_id FROM access_bindings WHERE id = $1`, string(binding.ID)).Scan(&roleIDAfter))
	assert.Equal(t, string(id), roleIDAfter,
		"выдача обязана указывать на ТУ ЖЕ строку: иначе право осталось, а роли под ним нет")

	// Контроль в обратную сторону: строка, на которую указывает выдача, ЖИВА.
	// Без него равенство идентификаторов зеленело бы и на удалённой роли.
	assert.Equal(t, 1, countRoleRows(t, ctx, pool, domain.RoleID(roleIDAfter)),
		"идентификатор выдачи обязан находить существующую строку, а не быть верным по форме")
}

// grantsOn — сколько прав выдано на роль.
func grantsOn(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.RoleID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM access_bindings WHERE role_id = $1`, string(id)).Scan(&n))
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// MOD-RD-06 — правило на СНЯТОМ ресурсе каталога отвергается оператором вставки
// ─────────────────────────────────────────────────────────────────────────────

// TestMODRD06ARetiredTypeIsRefusedByTheDomainBeforeAnyWrite — правило,
// называющее СНЯТЫЙ ТИП (`compute.disk`), не доходит до писателя вовсе.
//
// # Здесь названы ДВА производителя одного отказа, и порядок между ними важен
//
// Приёмка (§«ресурс роли снят каталогом») называет производителем ключ
// `role_rule_ref_res_fk` — ограничение БАЗЫ на записи. Ключ существует и верен,
// но на ЭТОМ входе он недостижим: `compute.{disk,image,snapshot}` стоят ещё и в
// закрытом списке снятых типов домена (`domain.retiredTypes`), а проверка домена
// в применителе исполняется РАНЬШЕ писателя (`roleOf` → `Validate`). Значит
// отказ приходит от домена, и класс у него другой.
//
// Это не дефект: два рубежа об одном предмете здесь СОГЛАСОВАНЫ, и ближний к
// вызывающему называет правило, а не SQLSTATE. Но утверждать про ключ на этом
// входе было бы утверждением о недостижимой ветви — оно зеленело бы, не
// исполнив её. Ключ проверяется отдельно, на входе, который до него доходит
// (проба ниже).
//
// Предикат совпадения двух списков — им и держится «недостижим», а не этой
// фразой:
//
//	grep -c "'compute', '\(disk\|image\|snapshot\)'" \
//	  services/iam/internal/migrations/20260901113757_rule_segments_have_a_referent.sql
//	grep -c '"compute\.' services/iam/internal/domain/retired_types.go
func TestMODRD06ARetiredTypeIsRefusedByTheDomainBeforeAnyWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool, applier := applierOnLiveBase(t)

	const roleID = "vpc.probe1870c.admin"
	id := domain.SystemRoleID(domain.RoleName(roleID))

	retired := declaredManifest("vpc", roleID, "Роль, называющая снятый тип.",
		[]manifest.Rule{{Module: "compute", Resources: []string{"disk"}, Classes: []string{"get"}}})

	rep, err := applier.Apply(ctx, retired)
	require.Error(t, err,
		"правило называет снятый тип — применение обязано отказать: %s", rep)
	assert.ErrorIs(t, err, moduleroles.ErrRoleRejectedByDomain,
		"на ЭТОМ входе ближний рубеж — домен: он исполняется раньше писателя")
	assert.NotErrorIs(t, err, moduleroles.ErrWriteFailed,
		"до писателя дело не дошло — утверждать про ключ здесь значило бы "+
			"утверждать о ветви, которая не исполнялась")
	// Полоса — МАШИННО, тем же вопросом, что и у пробы ниже: без общего вопроса
	// «различимы» доказывалось бы двумя разными приёмами, и первый же, который
	// перестанет работать, оставил бы вторую полосу без ответа (задача #1880).
	assert.Equal(t, moduleroles.LaneRejectedByDomain, moduleroles.RefusalLane(err),
		"полоса домена обязана называться признаком, а не разбором прозы")
	assert.Equal(t, codes.InvalidArgument, status.Code(err),
		"негодна ВХОДЯЩАЯ строка манифеста, а не состояние платформы")
	assert.Contains(t, err.Error(), "compute.disk",
		"отказ обязан НАЗВАТЬ тип: без имени вызывающий не знает, что править в манифесте")

	assert.Equal(t, 0, countRoleRows(t, ctx, pool, id),
		"отказ до писателя не оставляет строки")
	assert.Equal(t, 0, countRuleRefs(t, ctx, pool, id),
		"проекции у неприменённой роли быть не может")
}

// TestMODRD06BAResourceWithdrawnByDataIsRefusedByTheKeyAndNothingLands — ресурс,
// снятый КАТАЛОГОМ (строкой, `live = false`) и не known списку домена,
// отвергается ключом `role_rule_ref_res_fk`, и транзакция не оставляет НИЧЕГО.
//
// # Почему вход заводится фикстурой, а не берётся готовым
//
// Сегодня оба списка совпадают по составу (проба выше называет предикат),
// поэтому у ключа нет ни одного готового входа: всё, что он отверг бы, домен
// отвергает раньше. Снятие ресурса — теперь ДАННЫЕ (`#1030`, `#1823`), то есть
// административный путь заведёт снятие, о котором литерал в Go не узнает. Ровно
// этот случай ключ и стережёт, и фикстура его воспроизводит.
//
// # Глагол — подстановка, и это несущее
//
// `*` даёт ЯКОРЬ: одну строку проекции с `verb IS NULL`. Ключ ГЛАГОЛА на такой
// строке пропускается `MATCH SIMPLE`, поэтому отвечает РОВНО ключ ресурса.
// Названный глагол дал бы два применимых ключа, порядок между ними не
// определён, и проба утверждала бы то один отказ, то другой.
//
// Утверждаются ТРИ вещи, и третья — та, ради которой проба интеграционная:
//
//  1. класс отказа — ПРЕДУСЛОВИЕ, а не поломка службы;
//  2. отказ НАЗЫВАЕТ ресурс;
//  3. строка роли НЕ ОСТАЛАСЬ. Первая запись транзакции прошла успешно, вторую
//     отверг ключ; граница транзакции обязана унести обе. Половина применения
//     здесь была бы ролью без объявленных сегментов — правилом без референта.
func TestMODRD06BAResourceWithdrawnByDataIsRefusedByTheKeyAndNothingLands(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool, applier := applierOnLiveBase(t)

	// Снятие заводится СТРОКОЙ — тем же путём, каким его заведёт администратор.
	const withdrawnResource = "probeWithdrawn"
	_, err := pool.Exec(ctx, `
		INSERT INTO catalog_resource (module, resource, dotted, retired_at, retired_reason, live)
		VALUES ('vpc', $1, 'vpc.' || $1, now(), 'снят каталогом ради пробы #1870', false)`,
		withdrawnResource)
	require.NoError(t, err, "фикстура снятия обязана лечь: без неё ключу нечего отвергать")

	const roleID = "vpc.probe1870d.admin"
	id := domain.SystemRoleID(domain.RoleName(roleID))

	withdrawn := declaredManifest("vpc", roleID, "Роль, называющая снятый каталогом ресурс.",
		[]manifest.Rule{{Module: "vpc", Resources: []string{withdrawnResource}, Classes: []string{"*"}}})

	rep, err := applier.Apply(ctx, withdrawn)
	require.Error(t, err,
		"ресурс снят каталогом — применение обязано отказать: %s", rep)

	// # Полоса ПИСАТЕЛЯ утверждается машинно — и именно здесь она терялась
	//
	// Исполнитель транзакций (`shared.DoWithWriteTxVoid`, единственное объявление
	// паттерна) приводит отказ действия к gRPC-статусу, собирая статус ЗАНОВО, —
	// и `%w`-цепочка применителя за этой границей не переживала: `errors.Is` на
	// `ErrWriteFailed` отвечал `false`, при том что на полосе ДОМЕНА (проба выше)
	// тот же приём работал, потому что отказ рождается ДО исполнителя. Две полосы
	// вызывающий машинно не различал, у него оставался разбор прозы (задача
	// #1880).
	//
	// Утверждается то, что вызывающий получает НА САМОМ ДЕЛЕ, и это тройка:
	// признак полосы (переживает приведение), класс кодом статуса и предмет
	// текстом базы. Сентинел утверждается рядом — вторым лицом того же отказа,
	// для вызывающего в процессе; проба на настоящем мосту и есть то место, где
	// его сохранность доказуема, а не заявлена.
	assert.Equal(t, moduleroles.LaneWriteFailed, moduleroles.RefusalLane(err),
		"полоса писателя обязана пережить исполнителя транзакций: признак живёт "+
			"в `ErrorInfo`, а не в цепочке, которую исполнитель пересобирает")
	assert.ErrorIs(t, err, moduleroles.ErrWriteFailed,
		"сентинел — второе лицо того же отказа: вызывающий в процессе спрашивает "+
			"его привычным `errors.Is`, не зная про признак")
	assert.NotErrorIs(t, err, moduleroles.ErrRoleRejectedByDomain,
		"отказ ключа не принадлежит полосе домена: без этой половины «различимы» "+
			"зеленело бы на применителе, метящем всё одной полосой")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err),
		"класс отказа — предусловие: манифест назвал то, чего в живом каталоге нет, "+
			"и это не поломка службы")
	assert.Contains(t, err.Error(), "moduleroles: writing the declared role failed",
		"отказ пришёл от ПИСАТЕЛЯ: домен этого снятия не знает, его знает только каталог")
	assert.Contains(t, err.Error(),
		fmt.Sprintf("resources: %s is not a live platform resource", withdrawnResource),
		"отказ обязан НАЗВАТЬ ресурс: без имени вызывающий не знает, что править в манифесте")

	assert.Equal(t, 0, countRoleRows(t, ctx, pool, id),
		"вторую запись отверг ключ — граница транзакции обязана унести и первую: "+
			"роль без объявленных сегментов есть правило, пережившее свой референт")
	assert.Equal(t, 0, countRuleRefs(t, ctx, pool, id),
		"проекции у неприменённой роли быть не может")

	// Контроль в паре: тот же применитель на ЖИВОМ ресурсе того же каталога
	// доезжает. Без него отказ выше зеленел бы и на применителе, отвергающем всё.
	const liveRoleID = "vpc.probe1870e.admin"
	liveID := domain.SystemRoleID(domain.RoleName(liveRoleID))
	live := declaredManifest("vpc", liveRoleID, "Роль на живом ресурсе каталога.",
		[]manifest.Rule{{Module: "vpc", Resources: []string{"network"}, Classes: []string{"get"}}})
	rep, err = applier.Apply(ctx, live)
	require.NoError(t, err, "живой ресурс каталога обязан проходить: %s", rep)
	assert.Equal(t, 1, countRoleRows(t, ctx, pool, liveID),
		"положительный контроль: применитель отвергает не всё подряд")
}

// ─────────────────────────────────────────────────────────────────────────────
// Г1а · MOD-RD-07 — деривация `id` сверяется с ЖИВЫМ набором, а не с литералами
// ─────────────────────────────────────────────────────────────────────────────

// TestMODRD07SystemRoleIDsInTheLiveBaseDeriveFromTheirNames — идентификатор
// каждой системной роли базы есть функция её имени.
//
// # Почему второй стороной служит БАЗА, а не текст миграций
//
// Задача предлагала извлечь имена разборщиком текста миграций. База лучше по
// двум причинам, и обе измеримы: разборщик — сам распознаватель, и форму, о
// которой он не знает, он пропускает МОЛЧА (так уже случилось: круг 1 приёмки
// знал одну форму записи идентификатора и не видел второй, рукописной); а
// сверяется здесь не то, что миграция НАПИСАЛА, а то, что в базу ЛЕГЛО, — и
// расходится с деривацией именно второе.
//
// # Граница нормы названа, иначе норма была бы ложью
//
// Деривации подчиняются не ВСЕ системные роли: у `kacho-system.admin` и
// `kacho-system.viewer` идентификаторы рукописные, и `0001_initial.sql` называет
// их такими своим комментарием. Обе — вне закрытого набора модулей платформы,
// поэтому манифестом невыразимы и применителю не достаются. Они считаются
// отдельно, а не прощаются молча: перепись печатает обе величины.
func TestMODRD07SystemRoleIDsInTheLiveBaseDeriveFromTheirNames(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool, _ := applierOnLiveBase(t)

	// Рукописные идентификаторы применённых миграций — ВЕДОМОСТЬ, а не «прочее».
	// Предикат её пополнения:
	//   grep -ohE "\(\s*'rol[A-Za-z0-9]{5,}'" services/iam/internal/migrations/*.sql | sort -u
	handRolled := map[string]string{
		"rol000000000sysadmin":  "kacho-system.admin",
		"rol000000000sysviewer": "kacho-system.viewer",
	}

	rows, err := pool.Query(ctx, `SELECT id, name FROM roles WHERE is_system ORDER BY name`)
	require.NoError(t, err)
	defer rows.Close()

	type liveRole struct{ id, name string }
	var live []liveRole
	for rows.Next() {
		var r liveRole
		require.NoError(t, rows.Scan(&r.id, &r.name))
		live = append(live, r)
	}
	require.NoError(t, rows.Err())

	// Перепись ОБЪЁМА осмотренного: без неё «ноль расхождений» неотличимо от
	// «ноль прочитанных строк», и проба зеленела бы на пустой таблице.
	var derived, exempt int
	var mismatched []string
	for _, r := range live {
		if want, ok := handRolled[r.id]; ok {
			assert.Equal(t, want, r.name,
				"рукописный идентификатор обязан стоять у той роли, у которой миграция его объявила")
			exempt++
			continue
		}
		derived++
		if got := string(domain.SystemRoleID(domain.RoleName(r.name))); got != r.id {
			mismatched = append(mismatched,
				fmt.Sprintf("%s: в базе %s, деривация имени даёт %s", r.name, r.id, got))
		}
	}

	t.Logf("перепись: системных ролей %d · производных %d · рукописных %d",
		len(live), derived, exempt)

	require.NotEmpty(t, live,
		"обход пуст — вердикт беспредметен: системных ролей в базе не прочитано ни одной")
	require.Positive(t, derived,
		"производных ролей не прочитано ни одной — сверять деривацию не с чем")
	assert.Empty(t, mismatched,
		"идентификатор системной роли обязан быть функцией её имени, иначе выданное на неё "+
			"право указывает в пустоту:\n%s", strings.Join(mismatched, "\n"))
	assert.Len(t, handRolled, exempt,
		"ведомость рукописных идентификаторов обязана истекать сама: запись, которой больше "+
			"нечего исключать, — находка, а не порядок")

	// ── Контроль в обратную сторону ────────────────────────────────────────
	//
	// Шестнадцать символов вместо семнадцати дают идентификатор ВЕРНОЙ ФОРМЫ,
	// не совпадающий ни с одной строкой. Без этого контроля сверка выше зеленела
	// бы и на деривации, случайно совпавшей по длине: она утверждает равенство,
	// а не то, что неравенство вообще представимо.
	liveIDs := make(map[string]bool, len(live))
	for _, r := range live {
		liveIDs[r.id] = true
	}
	var falseHits []string
	for _, r := range live {
		if _, ok := handRolled[r.id]; ok {
			continue
		}
		short := domain.PrefixRole + domain.DerivedIDSuffix(r.name)[:16]
		if liveIDs[short] {
			falseHits = append(falseHits, fmt.Sprintf("%s → %s", r.name, short))
		}
	}
	assert.Empty(t, falseHits,
		"усечённая деривация не смеет находить НИ ОДНОЙ строки — иначе сверка выше "+
			"измеряет длину, а не равенство:\n%s", strings.Join(falseHits, "\n"))

	// И положительный полюс того же контроля: усечённый идентификатор всё ещё
	// синтаксически годен как идентификатор роли. Именно поэтому расхождение
	// деривации не находится ни одной проверкой формы.
	require.NotEmpty(t, live)
	sample := domain.PrefixRole + domain.DerivedIDSuffix(live[0].name)[:16]
	assert.NotEqual(t, live[0].id, sample,
		"усечённая деривация обязана ОТЛИЧАТЬСЯ от настоящей — иначе контроль вакуумен")
	assert.True(t, strings.HasPrefix(sample, domain.PrefixRole),
		"усечённый идентификатор остаётся верным по форме: расхождение деривации "+
			"проверкой формы не находится")
}

// ─────────────────────────────────────────────────────────────────────────────
// Г11 · MOD-RD-26/27 — ПАРИТЕТ ЯРУСОВ судит и строки ПРИМЕНИТЕЛЯ
// ─────────────────────────────────────────────────────────────────────────────
//
// # Что здесь предмет, а что уже было верно
//
// Популяция паритета верна by construction и была верна до этой работы:
// `systemRolesOfBase` выбирает `WHERE is_system` БЕЗ различения писателя (П21
// приёмки `roles-come-as-data-not-migrations.md`). Не хватало не выборки —
// не хватало ТОГО, ЧТОБЫ В НЕЙ ЛЕЖАЛА ХОТЬ ОДНА СТРОКА ПРИМЕНИТЕЛЯ: единственная
// проба паритета читала базу сразу после миграций, поэтому свойство держалось
// только на строках миграций, а применитель писал мимо всякого наблюдения.
//
// Второй предмет — САМ ПРЕДИКАТ. До задачи #1894 оба свойства стояли внутри тела
// пробы посева, и позвать их отсюда было нечем. Копия развела бы два места об
// одном предмете, и разошлись бы они молча — обе зелёные, утверждающие разное.
// Предикат выделен (`evaluateTierParity`), и обе популяции идут через ОДИН вызов.
//
// # Инъекция обязана ронять ТОЛЬКО проверяемое
//
// Правила подложенной роли объявляют глаголы, которые тип ОБСЛУЖИВАЕТ
// (`get`/`list` — набор `iam_user` целиком). Это не осторожность: с глаголом
// `*` роль дала бы находку и второго свойства (свёрнутое разрешение
// `iam.user.*.*` относится к распорядителю, а правило — к наблюдателю), и
// красное перестало бы называть проверяемое. Здесь краснеет РОВНО свойство 1 и
// ровно один его пункт — тир, которому нечем быть.

// TestMODRD26TierParityRedsOnTheApplierRowPromisingAnUnservableTier —
// применитель записывает `iam.user.admin`, и паритет ярусов краснеет, называя
// ярус.
//
// Имя выбрано не произвольно: оно СНЯТО применённой миграцией
// `20260825003504_role_iam_user_admin_promises_a_tier_it_cannot_serve.sql`
// именно потому, что тип `iam_user` не объявляет ни одного глагола яруса
// администратора (набор `[get list]`, #1128 и #1189). Держателем снятия та
// миграция называет ЭТОТ гейт — а гейт до сих пор не видел ни одной строки,
// которую написал применитель, то есть держал не то, что обещал.
//
// Контроль стоит в этой же пробе и в обе стороны: та же популяция ДО
// применителя молчит, после — краснеет ровно одним пунктом. Без первой половины
// находка была бы неотличима от красноты посева; без второй — от красноты
// вообще всего.
func TestMODRD26TierParityRedsOnTheApplierRowPromisingAnUnservableTier(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool, applier := applierOnLiveBase(t)

	const roleID = "iam.user.admin"
	id := domain.SystemRoleID(domain.RoleName(roleID))

	// ── Контроль: популяция ДО применителя ──────────────────────────────────
	before := evaluateTierParity(systemRolesOfBase(t, ctx, pool))
	requireTierParityPremise(t, before)
	require.Empty(t, before.TierGaps,
		"посев обязан быть чист ДО инъекции — иначе находка ниже принадлежит миграциям, а не применителю:\n%s",
		strings.Join(before.TierGaps, "\n"))
	require.Empty(t, before.Mismatches,
		"то же и о свойстве 2: инъекция обязана ронять только проверяемое:\n%s",
		strings.Join(before.Mismatches, "\n"))
	require.Equal(t, 0, countRoleRows(t, ctx, pool, id),
		"имя снято применённой миграцией — строки быть не должно, иначе краснеет посев, а не запись применителя")

	// ── Инъекция: строку пишет ПРИМЕНИТЕЛЬ, а не миграция и не проба ────────
	declared := declaredManifest("iam", roleID,
		"Роль, обещающая ярус, которого тип обслужить не может.",
		[]manifest.Rule{{Module: "iam", Resources: []string{"user"}, Classes: []string{"get", "list"}}})

	rep, err := applier.Apply(ctx, declared)
	require.NoError(t, err, "объявленная роль обязана записаться: %s", rep)
	require.Equal(t, 1, rep.Written, "без записи популяция не изменилась бы, и находка ниже была бы про посев: %s", rep)
	require.Equal(t, 1, countRoleRows(t, ctx, pool, id), "строка применителя обязана остаться в базе")

	// ── Тот же предикат, та же выборка — популяция теперь несёт строку применителя ──
	after := evaluateTierParity(systemRolesOfBase(t, ctx, pool))
	requireTierParityPremise(t, after)

	require.Equal(t, before.Roles+1, after.Roles,
		"популяция обязана вырасти РОВНО на строку применителя — иначе предикат её не видит, "+
			"и утверждение ниже было бы о посеве")
	assert.Equal(t, before.OnAxis+1, after.OnAxis,
		"подложенное имя стоит на оси тиров: иначе свойство 1 его не рассматривает вовсе")
	assert.Len(t, after.Families, len(before.Families),
		"семейство `iam.user` в посеве уже есть — инъекция добавляет ему ТИР, а не заводит новое семейство")

	assert.Contains(t, strings.Join(after.TierGaps, "\n"), `iam.user: tier "admin"`,
		"паритет обязан НАЗВАТЬ ярус, которому нечем быть, — тем же отказом, каким он краснел до снятия роли;\n"+
			"находки:\n%s", strings.Join(after.TierGaps, "\n"))
	assert.Len(t, after.TierGaps, 1,
		"инъекция обязана ронять РОВНО один пункт: находки:\n%s", strings.Join(after.TierGaps, "\n"))
	assert.Empty(t, after.Mismatches,
		"свойство 2 инъекцией не затронуто — глаголы правила тип обслуживает, и ярус правил равен ярусу разрешений;\n"+
			"иначе красное перестало бы называть проверяемое:\n%s", strings.Join(after.Mismatches, "\n"))
}

// TestMODRD27TierParityStaysSilentOnTheApplierRowWhoseTierTheTypeServes —
// парный ПОЛОЖИТЕЛЬНЫЙ: тот же писатель, то же место, ярус обслуживаемый.
//
// Без него отрицание выше зеленело бы на предикате, который краснеет на всякой
// строке применителя, — и «паритет судит записи применителя» доказывалось бы
// красным, которое ничего не различает.
//
// «Строка есть» здесь одна ничего не доказывает: `iam.user.view` — имя ЖИВОЕ,
// его никто не снимал, и строка стоит в базе до всякого применителя. Поэтому
// утверждается ЗАПИСЬ: назначение объявлено иным, чем посеянное (`Read User`),
// значит приведение обязано состояться и `Written` обязан быть единицей.
func TestMODRD27TierParityStaysSilentOnTheApplierRowWhoseTierTheTypeServes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool, applier := applierOnLiveBase(t)

	const roleID = "iam.user.view"
	id := domain.SystemRoleID(domain.RoleName(roleID))

	before := evaluateTierParity(systemRolesOfBase(t, ctx, pool))
	requireTierParityPremise(t, before)
	require.Empty(t, before.TierGaps,
		"посев обязан быть чист до применителя:\n%s", strings.Join(before.TierGaps, "\n"))
	require.Equal(t, 1, countRoleRows(t, ctx, pool, id),
		"имя живое: строка обязана стоять в базе ещё до применителя — поэтому «строка есть» доказательством не является")

	declared := declaredManifest("iam", roleID,
		"Назначение, объявленное манифестом модуля iam.",
		[]manifest.Rule{{Module: "iam", Resources: []string{"user"}, Classes: []string{"get", "list"}}})

	rep, err := applier.Apply(ctx, declared)
	require.NoError(t, err, "роль обязана примениться: %s", rep)
	require.Equal(t, 1, rep.Written,
		"назначение отличается от посеянного — приведение обязано состояться; без записи проба зеленела бы "+
			"на применителе, который не делает НИЧЕГО: %s", rep)

	after := evaluateTierParity(systemRolesOfBase(t, ctx, pool))
	requireTierParityPremise(t, after)

	assert.Equal(t, before.Roles, after.Roles,
		"имя живое: применитель ПРИВОДИТ строку, а не заводит вторую")
	assert.Empty(t, after.TierGaps,
		"ярус, который тип обслуживает, находкой не является — иначе гейт краснел бы на всякой записи применителя:\n%s",
		strings.Join(after.TierGaps, "\n"))
	assert.Empty(t, after.Mismatches,
		"ярус правил обязан остаться равным ярусу разрешений после приведения:\n%s",
		strings.Join(after.Mismatches, "\n"))
	assert.Equal(t, 1, countRoleRows(t, ctx, pool, id),
		"приведение обязано оставить РОВНО одну строку под тем же идентификатором")
	assert.Equal(t, 2, countRuleRefs(t, ctx, pool, id),
		"проекция объявленных сегментов пишется в той же транзакции: два глагола — две строки")
}
