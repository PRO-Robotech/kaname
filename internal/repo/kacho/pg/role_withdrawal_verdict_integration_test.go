// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_withdrawal_verdict_integration_test.go — сценарий IAM-RW-1-10 приёмки
// `services/iam/docs/engineering/acceptance/role-withdrawal-has-a-producer.md`
// на уровне ВЕРДИКТА: выдача на снятую роль доступа не даёт.
//
// Задача продукта #2028.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТОГО НЕ ПОКАЗЫВАЕТ НИ ОДНА СОСЕДНЯЯ ПРОБА
//
// Отзыв роли покрыт тремя пробами МЕХАНИЗМА: ключ держит порядок снятия
// (`migrations/role_withdrawal_mark_integration_test.go`), реконсайлер снятую
// роль пропускает и её состав цели снимается
// (`reconcile_skips_a_retired_role_integration_test.go`), новая выдача на снятую
// роль отвергается стражем. Все три утверждают о СТРОКАХ.
//
// Утверждение о строках переживает свой предмет: цепь вердикта вправе начать
// читать другую таблицу, и все три пробы останутся зелёными, а право вернётся.
// Спрашивать надо у ТОГО ЖЕ кода, что отвечает арендатору, — `relverdict.Ask`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРЕЖНЯЯ ПОПЫТКА ПАДАЛА НА СОБСТВЕННОМ ПОЛОЖИТЕЛЬНОМ КОНТРОЛЕ
//
// Проба этого сценария писалась дважды и оба раза давала `Deny` ДО снятия роли —
// то есть её положительный контроль был недостижим, и причина не была
// установлена. Она установлена и названа здесь, потому что без неё следующий
// автор повторит ту же фикстуру.
//
// У правила роли ДВЕ стороны, и вердикт соединяет ОБЕ:
//
//	role_rule_selectors — «подходит ли объект»  (ветвь якоря/имён/меток)
//	role_verb           — «разрешено ли действие» (пара «тип × глагол»)
//
// Прежняя фикстура заводила роль писателями репозитория — `RolesW().Insert` плюс
// `ReplaceRuleSelectors`, — то есть клала ОДНУ сторону. Роль с одними
// селекторами адресует объект и не разрешает на нём НИЧЕГО, а вердикт по её
// выдаче отказывает МОЛЧА: ветвь выдач не находит строки `role_verb` и
// возвращает пустой набор. Отказ этот неотличим от честного, и потому выглядел
// дефектом фикстуры вообще, а не одной её половины. Ровно об этом предупреждает
// шапка `seed.SyncAllSystemRoleSelectors` — «зовущий эту функцию руками получает
// половину правила».
//
// Здесь обе стороны кладёт ПРОДУКТ, и обе — те же полосы, что исполняются на
// старте: `seed.SyncAllSystemRoleSelectors` и `seed.ReseedSystemRoleVerbs`.
// Роль при этом заводится ПРИМЕНЕНИЕМ МАНИФЕСТА — тем же путём, каким её заводит
// модуль, — и снимается тоже применением, как и требует сценарий.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ДОКАЗАНА СПОСОБНОСТЬ УПАСТЬ — инъекцией, а не прочтением
//
// Писательская сторона такой дефект породить НЕ МОЖЕТ: ключи живости
// (`role_verb_role_live_fk`, `role_rule_selectors_role_live_fk`) отвергают
// пометку роли, у которой осталась хоть одна проекция, поэтому состояние «роль
// снята, а проекции целы» невыразимо. Значит инъекция делается на стороне
// ЧИТАТЕЛЯ, и это ровно тот класс, ради которого проба написана.
//
//	ИНЪЕКЦИЯ А (класс). Ветвь выдач `relverdict.grantArmSQL` перестаёт ТРЕБОВАТЬ
//	живых проекций роли: оба соединения становятся левыми. Эта проба краснеет на
//	несущем утверждении — «роль снята, а выдача на неё продолжает давать доступ»,
//	— а `TestReconcileSkipsARetiredRole` и
//	`TestIAMRW1TheProducerRetiresWhatTheManifestStoppedDeclaring` остаются
//	ЗЕЛЁНЫМИ. Это и есть мера того, что проба добавляет: они о строках, она — об
//	ответе.
//
//	ИНЪЕКЦИЯ Б (диагноз). Досев проекции глаголов не зовётся — форма прежней
//	фикстуры. Проба краснеет на ПОЛОЖИТЕЛЬНОМ КОНТРОЛЕ с тем же симптомом, что
//	наблюдался дважды: `Deny` ДО снятия роли. Причина, объяснённая выше, тем
//	самым измерена, а не заявлена.
//
// Первая редакция инъекции А была ОТВЕРГНУТА: она роняла пробу ошибкой разбора
// («cannot scan NULL into *string»), то есть третьей категорией — «не
// выполнилось», — а не отказом по существу. Инъекция обязана проверяться не
// только тем, что покраснело, но и тем, ЧТО НАПЕЧАТАЛО.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕТЫРЕ УТВЕРЖДЕНИЯ, И НИ ОДНО НЕ ВЫВОДИТСЯ ИЗ ОСТАЛЬНЫХ
//
//	до снятия      → Allow   положительный контроль: без него отказ ниже
//	                         зеленел бы на субъекте, у которого прав не было
//	после снятия   → Deny    предмет сценария
//	              → и отказ дан ПО ПРАВУ, а не по незнанию типа: иначе «Deny»
//	                         зеленел бы и на вердикте, переставшем понимать вопрос
//	живой сосед    → Allow   роль ЧУЖОГО модуля цела: без этого «Deny» выше
//	                         зеленел бы на цепи, отказывающей ВСЕМУ
//	строка выдачи  → цела    отзыв есть пометка РОЛИ, а не снятие выдачи; без
//	                         этого «Deny» был бы выполним удалением выдачи

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/moduleroles"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// TestIAMRW110AGrantOnARetiredRoleYieldsNoVerdict — IAM-RW-1-10.
func TestIAMRW110AGrantOnARetiredRoleYieldsNoVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx, pool, applier := applierOnLiveBase(t)
	repo := kachopg.New(pool, nil)
	catRepo := kachopg.NewCatalogRepo(pool)

	census, err := seed.AssertCatalogParity(ctx, catRepo, seed.ImageAnchor())
	require.NoError(t, err, "страж паритета каталога")
	snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
	require.NoError(t, err, "снимок каталога")

	mods, res, verbs := liveCatalogCounts(t, ctx, pool)
	t.Logf("перепись каталога: модулей %d, ресурсов %d, действий %d", mods, res, verbs)

	const (
		// Роль-ПРЕДМЕТ: её манифест перестанет объявлять.
		subjectRoleName = "vpc.rwverdict.admin"
		// Роль-ДЕРЖАТЕЛЬ: остаётся объявленной, чтобы раздел `roles:` был непуст
		// и снятие относилось к ОДНОЙ роли, а не ко всем ролям модуля.
		keeperRoleName = "vpc.rwkeeper.admin"
		// Роль ЧУЖОГО модуля — живой сосед. Иной модуль намеренно: роль того же
		// модуля адресует ТОТ ЖЕ тип объекта, поэтому её выдача разрешала бы тот
		// же вопрос и предмет пробы был бы неразличим.
		neighbourRoleName = "compute.rwneighbour.admin"
	)
	subject := domain.SystemRoleID(domain.RoleName(subjectRoleName))
	neighbour := domain.SystemRoleID(domain.RoleName(neighbourRoleName))

	// ── ОБЪЯВЛЕНИЕ ролей применением манифестов ─────────────────────────────
	rep, err := applier.Apply(ctx,
		withdrawalManifest(t, "vpc", subjectRoleName, keeperRoleName), moduleroles.BootActorID)
	require.NoErrorf(t, err, "объявленные роли vpc обязаны примениться: %s", rep)
	require.Equalf(t, 2, rep.Written, "обе роли vpc обязаны лечь: %s", rep)

	repNb, err := applier.Apply(ctx,
		withdrawalManifest(t, "compute", neighbourRoleName), moduleroles.BootActorID)
	require.NoErrorf(t, err, "роль чужого модуля обязана лечь: %s", repNb)
	require.Equalf(t, 1, repNb.Written, "роль соседа обязана лечь: %s", repNb)

	// ── ОБЕ СТОРОНЫ ПРАВИЛА кладёт ПРОДУКТ, теми же полосами, что старт ─────
	//
	// Порознь ни одна не даёт вердикта: селекторы адресуют объект и не разрешают
	// на нём ничего, проекция глаголов разрешает действие и не адресует объекта.
	// Прежняя попытка этой пробы клала одну — см. шапку файла.
	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool),
		"досев селекторов системных ролей")
	vcensus, err := seed.ReseedSystemRoleVerbs(ctx, repo, pool, snap.Facts(), nil)
	require.NoError(t, err, "досев проекции глаголов системных ролей")
	t.Logf("перепись досева глаголов: осмотрено %d, пересеяно %d, пар %d, отказало %d",
		vcensus.Examined, vcensus.Reseeded, vcensus.Pairs, vcensus.Failed)

	// ── ВЫДАЧИ ──────────────────────────────────────────────────────────────
	tn := seedVerdictTenant(t, ctx, pool)
	grantOnProject(t, ctx, pool, tn, "acb-rw110", string(subject), "vpc_network", "net-rw110")
	grantOnProject(t, ctx, pool, tn, "acb-rw110-nb", string(neighbour),
		"compute_instance", "ins-rw110")

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: право действует ДО снятия ───────────────────
	got, grounds, aerr := askVerdict(t, ctx, pool, tn.granted, "vpc_network", "net-rw110", "v_get")
	require.NoError(t, aerr,
		"вердикт до снятия не вычислен — это «не выполнилось», а не отказ")
	require.Equalf(t, relverdict.Allow, got,
		"выдача на ЖИВУЮ роль модуля не даёт права (тип не объявлен моделью: %t) — "+
			"положительного контроля нет, и отрицание ниже зеленело бы на субъекте, "+
			"у которого прав не было НИКОГДА", grounds.TypeNotDeclared)

	nGot, nGrounds, nErr := askVerdict(t, ctx, pool, tn.granted,
		"compute_instance", "ins-rw110", "v_get")
	require.NoError(t, nErr, "вердикт по соседу до снятия не вычислен")
	require.Equalf(t, relverdict.Allow, nGot,
		"роль чужого модуля не даёт права ДО всякого снятия (тип не объявлен моделью: %t) — "+
			"контроль живого соседа стал бы беспредметен", nGrounds.TypeNotDeclared)

	// ── СНЯТИЕ применением манифеста, где роли-предмета больше нет ──────────
	rep, err = applier.Apply(ctx, withdrawalManifest(t, "vpc", keeperRoleName),
		moduleroles.BootActorID)
	require.NoErrorf(t, err, "применение обязано пройти, а не отказать: %s", rep)
	require.Equalf(t, 1, rep.Retired, "снятой обязана быть ровно одна роль: %s", rep)
	require.Equalf(t, []string{subjectRoleName}, rep.RetiredNames,
		"снята не та роль: %s", rep)
	live, reason, _ := roleLiveness(t, ctx, pool, subject)
	require.Falsef(t, live, "роль-предмет не помечена снятой — снимать было нечего")
	require.NotEmpty(t, reason, "причина снятия обязана быть непуста")

	// ── НЕСУЩЕЕ: право не действует ─────────────────────────────────────────
	got, grounds, aerr = askVerdict(t, ctx, pool, tn.granted, "vpc_network", "net-rw110", "v_get")
	require.NoError(t, aerr,
		"вердикт после снятия не вычислен — это «не выполнилось», а не отказ")
	assert.Equalf(t, relverdict.Deny, got,
		"роль снята, а выдача на неё продолжает давать доступ: отзыв не доезжает до "+
			"вердикта (тип не объявлен моделью: %t)", grounds.TypeNotDeclared)
	// Отказ ПО ПРАВУ, а не по незнанию типа: без этого «Deny» зеленел бы и там,
	// где цепь перестала понимать вопрос, — а это другой отказ и другой дефект.
	assert.False(t, grounds.TypeNotDeclared,
		"отказ дан основанием «типа нет в словаре модели» — это НЕ обычная полоса "+
			"отсутствия права, которой требует сценарий")

	// ── ЖИВОЙ СОСЕД: цепь отказывает не всему подряд ────────────────────────
	nGot, nGrounds, nErr = askVerdict(t, ctx, pool, tn.granted,
		"compute_instance", "ins-rw110", "v_get")
	require.NoError(t, nErr, "вердикт по соседу после снятия не вычислен")
	assert.Equalf(t, relverdict.Allow, nGot,
		"снятие роли vpc унесло и право по роли чужого модуля (тип не объявлен "+
			"моделью: %t) — отказ выше зеленел бы на цепи, отказывающей ВСЕМУ",
		nGrounds.TypeNotDeclared)

	// ── ВЫДАЧА ЦЕЛА: отзыв есть пометка РОЛИ ────────────────────────────────
	//
	// Три поля, а не существование строки: выдачу можно погасить сменой
	// состояния, отзывом и сроком, и утверждение, спрашивающее только `count`,
	// зеленело бы на всех трёх.
	var (
		status  string
		revoked *string
		expires *string
	)
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT status, revoked_at::text, expires_at::text
		  FROM kacho_iam.access_bindings WHERE id = $1`, "acb-rw110").
		Scan(&status, &revoked, &expires),
		"строки выдачи на снятую роль нет вовсе — отзыв роли снял выдачу, а обязан её пережить")
	assert.Equal(t, "ACTIVE", status, "выдача на снятую роль сменила состояние")
	assert.Nil(t, revoked, "выдача на снятую роль помечена отозванной")
	assert.Nil(t, expires, "выдаче на снятую роль проставлен срок")
}
