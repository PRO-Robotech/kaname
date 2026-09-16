// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// parity_test.go — держатель второй половины #1891: манифест модуля ОБЪЯВЛЯЕТ
// посев, который у модуля есть, и объявление сходится с живой базой.
//
// # Почему прогон против базы, а не разбор миграций
//
// Так требует предикат снятия задачи, и требует по существу. Разбор SQL —
// распознаватель: форму записи, которой он не знает, он пропускает МОЛЧА, и его
// молчание неотличимо от согласия. Здесь миграции исполняются, применитель
// зовётся, а строки читаются оттуда, где лежат.
//
// # ЖИВУЮ сторону производит ПРИМЕНИТЕЛЬ, а не миграция (#2452)
//
// Здесь стояло «действующий посев есть НАЛОЖЕНИЕ применённых миграций», и это
// перестало быть верным вместе со своим предметом: служебные учётки модулей
// платформы ушли из цепочки миграций службы доступа
// (`20260909202745_module_identities_leave_the_baseline.sql`) — самостоятельная
// установка заводила пять личностей чужого продукта. Строки заводит применитель
// `internal/apps/kaname/moduleseed` из ТОГО ЖЕ раздела `seed`, который эта
// сверка и судит.
//
// Из этого следует, ЧТО ИМЕННО гейт держит теперь, и это сильнее прежнего:
// прежде он сверял два независимых объявления (манифест и миграцию), и его
// зелёный означал «два места об одном предмете ещё не разошлись». Теперь
// объявление ОДНО, а сверяется, доезжает ли оно до базы: применитель зовётся
// здесь ровно так, как его зовёт композиционный корень, и расхождение означает
// «объявленное не применилось», а не «две копии разъехались».
//
// Цена названа честно: сверка перестала быть независимой от применителя —
// красное у неё теперь бывает и от его дефекта. Это правильный размен: копии,
// которая могла бы разойтись, больше нет, а дефект применителя обязан быть
// виден кому-то, и до этой задачи он не был виден никому.
//
// # Почему НЕ общий стенд
//
// Общий стенд отстаёт от линии и несёт данные чужих прогонов; вердикт по нему
// был бы вердиктом о ЧУЖОМ дереве. База поднимается из миграций ЭТОГО дерева.
//
// # Судятся ВСЕ ЧЕТЫРЕ подраздела; из-под вердикта выведен один ВИД строки
//
// Здесь сверялись два подраздела из четырёх, а два оставшихся объяснялись одним
// числом на все живые строки — «выдач живых 8, из них выразимых формой 0».
// Число складывало два разных предмета и потому скрывало ровно тот случай, ради
// которого граница названа:
//
//   - строка БЕЗ модуля-владельца (`kacho-api-gateway`, `kacho-bootstrap-admin`,
//     `user:*`, владельческая привязка системного аккаунта) манифестом МОДУЛЯ
//     невыразима by construction — объявлять её некому, и её отсутствие среди
//     объявленного верно, а не пробел;
//   - строка С владельцем, которой не умеет ФОРМА, — вот это пробел, и таких из
//     восьми две (#1936).
//
// Сверх того выразимая формой выдача РОЛЬЮ модуля не судилась вовсе: сегодня
// таких живых строк ноль, и «выразимых формой 0» читалось как «судить нечего»,
// а перестало бы быть верным в тот прогон, когда первая такая строка появится, —
// молча.
//
// Теперь судятся все четыре подраздела, живое относится к модулю-владельцу, а
// невыразимого вида строки не осталось (#1936): проба предпосылки снята вместе
// со своим предметом.
//
// # Владелец живой ГРУППЫ — тот, чей манифест её ОБЪЯВЛЯЕТ (приёмка MRW-1, Р5)
//
// Служебная запись относится к модулю по своему имени (`kacho-<служба>`) — имя
// назначает сам модуль. Группа так не именуется: обе живые группы платформы
// носят приставку `module-`, а объявляет их манифест СЛУЖБЫ (`manifest.yaml`,
// раздел `seed`). Поэтому группа относится к модулю по ОБЪЯВЛЕНИЮ — паре
// (аккаунт, имя) в прочитанных манифестах, — а выдача, чей субъект группа, по
// объявлению этой группы. Ключ атрибуции — пара; ключ СРАВНЕНИЯ остаётся тройкой
// с назначением: дрейф назначения тогда даёт находку в обе стороны, а не
// молчание разряда «без владельца». Группа, которую не объявил никто, владельца
// не имеет и считается отдельно, как и прежде.
//
// # Написания объявленной стороны приводятся ОКНОМ ПЕРЕИМЕНОВАНИЙ (kaname#110)
//
// Приёмка MRW-1 (Р5) писала: «сверка сравнивает написания сырыми, окна в неё не
// заводится — второй читатель пережил бы предмет окна молча». Линия #140
// (kaname#110) это решение ОТОЗВАЛА замером: на дереве платформы объявленный
// ключ с ПРЕЖНИМ написанием аккаунта против живого `system/…` давал 30 находок
// из 30 (литерал здесь не пишется намеренно: он двигал бы ведро «живой» соседа). Окно
// читается у ЕДИНСТВЕННОГО объявления (`domain.SeedIdentityWindow()`,
// `declaredSpelling` ниже), а не копируется, — снятие записи окна из объявления
// снимает её и здесь, так что «читатель, переживший предмет» не заводится.
// Атрибуция Р5 идёт по тем же приведённым ключам: иначе на дереве платформы
// объявленная пара не нашла бы живой строки при верном продукте. Расхождение
// текста Р5 с деревом названо в отчёте слияния #169 с линией — решение о записи
// ревью к приёмке за владельцем, не за этой пробой.
//
// # Порог чтения — ЯКОРЬ, а не число (kaname#110), и его дополняет атрибуция
//
// Здесь стояли полы `3 · 3 · 1` и `NotZero(Joins.Live)`, снятые с базы ДО
// `20260909202745`; ветка #106 привела их к базе после всех миграций
// (`2 · 1 · 3`, §6 S1 п. 9 приёмки MRW-1), линия #140 сняла числа вовсе — см.
// разбор у `TestModuleManifestDeclaresTheSeedTheLiveBaseHolds`. Обвал чтения
// различим и без чисел: якорь по имени стережёт служебные записи, а
// `NotZero(Groups.Owned)` и `NotZero(Bindings.Owned)` (положительная сторона Р5)
// — группы и выдачи: ноль прочитанных групп и ноль выдач по-прежнему красны.
package moduleseedparity_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/corelib/platformmodules"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/moduleseedparity"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/modulemanifests"
)

// ПОРОГИ ЧИСЛАМИ СНЯТЫ — У НИХ НЕ БЫЛО НЕЗАВИСИМОГО ПРОИЗВОДИТЕЛЯ.
//
// Здесь стояли три числа (`3`, `3`, `1`), снятые с живой базы «с запасом вниз».
// Запас был свойством ТОЙ базы: пять личностей модулей ушли из применённой
// цепочки в доставку (`20260909202745_module_identities_leave_the_baseline`), и
// служебных записей в самостоятельном клоне осталось ДВЕ. Порог 3 стал
// утверждением о состоянии, которого больше нет, — проба краснела «чтение
// перестало видеть предмет» там, где чтение исправно.
//
// Увидеть это было нечем: пакет не исполняло НИ ОДНО задание (kaname#19), а
// сама проба вдобавок спрашивала дерево платформы и пропускала себя (kaname#108).
//
// Вместо порога — ЯКОРЬ. Непустота трёх из четырёх чтений зависит от того, что
// ДОСТАВИЛА установка: без манифестов модулей ни групп модулей, ни их вступлений
// в базе нет законно, и порог на них был бы утверждением об окружении. Свойством
// ПРИМЕНЁННОЙ ЦЕПОЧКИ является ровно одно: собственная посевная личность службы
// лежит в базе в обеих посадках. Её и спрашиваем поимённо — у имени один
// владелец (`domain.BootstrapAdminSAName`), а держит её в базе гейт дерева
// `internal/check/module_identity_seeded_only_by_baseline.go`.

// seededNamePrefix — приставка, которой посев называет служебную запись модуля:
// `kacho-<служба>`, служба — из словаря платформы.
//
// Это НЕ «узнавание по бренду»: переводится приставкой только то, что ею
// названо, а написания, переведённые решением о бренде, приводятся к
// действующему ОКНОМ ПЕРЕИМЕНОВАНИЙ (`declaredSpelling` ниже) — тем же, которым
// их приводит применитель. Пока платформа называет свои личности `kacho-<…>`,
// приставка остаётся верной; переведёт — окно примет оба написания, как принимает
// их сегодня для аккаунта и для собственной личности службы.
const seededNamePrefix = "kacho-"

// declaredSpelling — ДЕЙСТВУЮЩЕЕ написание посевного имени.
//
// Манифест платформы продолжает называть аккаунт `kacho-system`, а базу мы
// перевели на `system` (`20260913144108_seed_identity_leaves_the_platform_brand`).
// Применитель различие снимает окном (`domain.SeedIdentitySpellings`), а сверка
// — нет: она сравнивала объявленный ключ `kacho-system/…` с живым `system/…` и
// находила расхождение на КАЖДОЙ строке. Замер: 30 находок из 30, все одного
// рода — «объявлено и не живёт» плюс «живёт и не объявлено» об одной и той же
// строке.
//
// Окно читается у ЕДИНСТВЕННОГО объявления, а не копируется: второе место об
// одном предмете разошлось бы с применителем молча, и сверка снова судила бы
// написание вместо строки.
func declaredSpelling(name string) string {
	for _, r := range domain.SeedIdentityWindow() {
		if name == r.Previous {
			return r.Declared
		}
	}
	return name
}

// TestModuleManifestDeclaresTheSeedTheLiveBaseHolds — сам гейт (MRW-11).
func TestModuleManifestDeclaresTheSeedTheLiveBaseHolds(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: вердикт этого гейта даёт ПРОГОН против живой базы, " +
			"а не разбор миграций")
	}
	ctx := context.Background()
	set := manifestSet(t)

	states, census, anchors := moduleStates(ctx, t, set, nil)

	// Перепись — ДО всякого вердикта и независимо от него. Посадка называется
	// ОТДЕЛЬНОЙ строкой: «расхождений 0» на одном прочитанном манифесте и на
	// шести — разные утверждения, и различить их обязан читатель, а не автор.
	t.Logf("перепись: %s; %s", set.Census(), census)
	for _, st := range states {
		t.Logf("  модуль %-13s записей %d/%d · групп %d/%d · выдач %d/%d · вступлений %d/%d "+
			"(объявлено/живых) · манифест %s",
			st.Module, len(st.DeclaredSA), len(st.LiveSA),
			len(st.DeclaredGroup), len(st.LiveGroup),
			len(st.DeclaredBinding), len(st.LiveBinding),
			len(st.DeclaredJoin), len(st.LiveJoin), st.ManifestFile)
	}

	require.NotZero(t, census.Manifests,
		"манифестов модулей прочитано ноль — каталог переехал, и гейт стережёт координату, "+
			"которой больше нет")
	// ЯКОРЬ ЧТЕНИЯ — собственная посевная личность службы. Она лежит в базе в
	// ОБЕИХ посадках, потому что её кладёт применённая цепочка, а не доставка;
	// всё остальное живое зависит от того, что доставила установка, и порог на
	// нём был бы утверждением об окружении, а не о чтении.
	require.Truef(t, liveNamesInclude(anchors, domain.BootstrapAdminSAName),
		"чтение служебных записей не нашло собственную посевную личность службы %q "+
			"(прочитано имён: %d, среди них: %s) — чтение перестало видеть предмет, "+
			"и «расхождений 0» было бы сказано ни о чём",
		domain.BootstrapAdminSAName, len(anchors), strings.Join(anchors, ", "))

	res := moduleseedparity.Compare(states)

	if len(res.Findings) > 0 {
		t.Fatalf("раздел `seed` расходится с живой базой — %d место(а):\n  %s\n\n"+
			"Снятие: объявить `seed` модуля так, чтобы он сходился со строками, которые уже "+
			"лежат в базе (#1891). Выведенных из-под вердикта строк больше НЕТ: форма "+
			"научилась выражать выдачу отношением (#1936), и всякая живая строка модуля "+
			"судится наравне с остальными.",
			len(res.Findings), strings.Join(res.Findings, "\n  "))
	}

	// Положительная сторона атрибуции (Р5): группа службы и её выдача отнесены
	// к модулю `iam` по объявлению. Без этого реализация, отбрасывающая обе из
	// сравнения, была бы зелена по «находок ноль».
	require.NotZero(t, census.Groups.Owned,
		"перепись групп печатает «с владельцем 0» — объявленная манифестом службы группа не отнесена к нему")
	require.NotZero(t, census.Bindings.Owned,
		"перепись выдач печатает «с владельцем 0» — выдача группе службы не отнесена к модулю по объявлению группы")
}

// removeServiceGroup снимает строку группы службы ВМЕСТЕ с её выдачей: иного
// порядка схема не допускает (`groups_subject_ref_before_delete_trg`, 23503).
func removeServiceGroup(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	tag, err := pool.Exec(ctx, `
		DELETE FROM kaname.access_bindings b
		 USING kaname.groups g JOIN kaname.accounts a ON a.id = g.account_id
		 WHERE b.subject_type = 'group' AND b.subject_id = g.id
		   AND a.name = 'system' AND g.name = 'module-relation-writers'`)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "выдачи группы службы в базе не оказалось — дом не построен")
	tag, err = pool.Exec(ctx, `
		DELETE FROM kaname.groups g
		 USING kaname.accounts a
		 WHERE a.id = g.account_id AND a.name = 'system' AND g.name = 'module-relation-writers'`)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "группы службы в базе не оказалось — дом не построен")
}

func findingsAbout(findings []string, needle string) []string {
	var out []string
	for _, f := range findings {
		if strings.Contains(f, needle) {
			out = append(out, f)
		}
	}
	return out
}

// TestMRW12_DeclaredGroupMissingFromTheBaseIsAFinding — объявленной строки нет:
// находка «группа ОБЪЯВЛЕНА и не живёт» ровно одна по подразделу групп, и рядом
// — «выдача ОБЪЯВЛЕНА и не живёт», потому что выдача ушла вместе с группой.
func TestMRW12_DeclaredGroupMissingFromTheBaseIsAFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	states, census, _ := moduleStates(ctx, t, manifestSet(t), removeServiceGroup)
	t.Logf("перепись: %s", census)
	res := moduleseedparity.Compare(states)
	t.Logf("находки: %s", strings.Join(res.Findings, " · "))

	groups := findingsAbout(res.Findings, "группа ОБЪЯВЛЕНА и не живёт")
	require.Len(t, groups, 1, "находка о снятой группе не ровно одна: %v", res.Findings)
	require.Contains(t, groups[0], "модуль iam")
	require.Contains(t, groups[0], "manifest.yaml")
	require.Empty(t, findingsAbout(res.Findings, "группа ЖИВЁТ и не объявлена"),
		"вторая сторона сработала при отсутствии живой строки")
	require.NotEmpty(t, findingsAbout(res.Findings, "выдача ОБЪЯВЛЕНА и не живёт"),
		"выдача ушла вместе с группой, а сверка об этом молчит")
}

// TestMRW13_LiveGroupDeclaredByNobodyHasNoOwner — живая группа, которую не
// объявляет ни один прочитанный манифест, находки не даёт и считается в разряде
// «без модуля-владельца»; её выдача — в том же разряде подраздела выдач.
func TestMRW13_LiveGroupDeclaredByNobodyHasNoOwner(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	const stray = "module-declared-by-nobody"
	var baseline moduleseedparity.Census
	set := manifestSet(t)
	_, baseline, _ = moduleStates(ctx, t, set, nil)

	states, census, _ := moduleStates(ctx, t, set, func(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
		t.Helper()
		var groupID string
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO kaname.groups (id, account_id, name, description, labels, created_at)
			SELECT 'grp' || substr(md5($1), 1, 17), a.id, $1, 'группа, которую не объявляет никто', '{}', now()
			  FROM kaname.accounts a WHERE a.name = 'system'
			RETURNING id`, stray).Scan(&groupID))
		_, err := pool.Exec(ctx, `
			INSERT INTO kaname.access_bindings (id, subject_type, subject_id, granted_relation, is_system,
			    resource_type, resource_id, status, deletion_protection, granted_by_user_id)
			VALUES ('acb' || substr(md5('stray-grant:' || $1), 1, 17), 'group', $1, 'fga_writer', true,
			        'cluster', 'cluster_root', 'ACTIVE', true, '')`, groupID)
		require.NoError(t, err)
	})
	t.Logf("перепись: %s", census)
	res := moduleseedparity.Compare(states)
	require.Empty(t, findingsAbout(res.Findings, stray), "группа без объявления дала находку: %v", res.Findings)
	require.Equal(t, baseline.Groups.Ownerless+1, census.Groups.Ownerless,
		"группа без объявления не попала в разряд «без модуля-владельца»")
	require.Equal(t, baseline.Bindings.Ownerless+1, census.Bindings.Ownerless,
		"выдача группе без объявления не попала в разряд «без модуля-владельца» подраздела выдач")
	require.Equal(t, baseline.Groups.Owned, census.Groups.Owned, "разряд «с владельцем» сдвинулся от группы без объявления")
}

// TestMRW22_LiveGroupWithADriftedDescriptionIsAFindingBothWays — назначение
// живой строки разошлось с объявленным: две находки, обе о модуле `iam`, и
// «с владельцем» не ноль — строка отнесена по паре, а не по тройке.
func TestMRW22_LiveGroupWithADriftedDescriptionIsAFindingBothWays(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	states, census, _ := moduleStates(ctx, t, manifestSet(t), func(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
		t.Helper()
		tag, err := pool.Exec(ctx, `
			UPDATE kaname.groups g SET description = 'назначение, разошедшееся с объявленным'
			  FROM kaname.accounts a
			 WHERE a.id = g.account_id AND a.name = 'system' AND g.name = 'module-relation-writers'`)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected(), "живой группы службы нет — дом не построен")
	})
	t.Logf("перепись: %s", census)
	res := moduleseedparity.Compare(states)
	t.Logf("находки: %s", strings.Join(res.Findings, " · "))

	liveOnly := findingsAbout(res.Findings, "группа ЖИВЁТ и не объявлена")
	declaredOnly := findingsAbout(res.Findings, "группа ОБЪЯВЛЕНА и не живёт")
	require.Len(t, liveOnly, 1)
	require.Len(t, declaredOnly, 1)
	require.Contains(t, liveOnly[0], "модуль iam")
	require.Contains(t, liveOnly[0], "разошедшееся с объявленным")
	require.Contains(t, declaredOnly[0], "модуль iam")
	require.NotZero(t, census.Groups.Owned,
		"«с владельцем 0»: строка ушла в разряд без владельца по тройке, и обе находки погасли бы разом")
}

// ЗДЕСЬ СТОЯЛА ПРОБА ПРЕДПОСЫЛКИ `TestBindingFormStillCannotExpressARelationGrant`
// — она СНЯТА ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ (#1936).
//
// Проба утверждала, что у формы выдачи нет ключа, чьё имя содержит `relation`, и
// сама объявляла своё истечение: «появится ключ — эта проба покраснеет и
// потребует научить предикат новому ключу, а не оставит слепую зону молча».
// Предикат сработал ровно так, как обещал: ключ `grantedRelation` заведён, проба
// покраснела, сверка расширена на весь предмет, и проба снята — не ослаблена.
//
// Оставить её, перевернув утверждение («ключ ЕСТЬ»), значило бы завести проверку
// без предмета: она стерегла ГРАНИЦУ сверки, а границы больше нет.
//
// Вместе с ней снят её помощник `yamlKeysOf`: других вызывающих у него не
// осталось ни одного, а помощник без вызывающего есть мёртвый код, который
// следующий читатель примет за действующий.

// between — правка живой базы МЕЖДУ применением и чтением: так строятся дома
// сценариев, у которых живая строка снята, дописана либо изменена. nil — база
// читается как её оставил применитель.
type between func(ctx context.Context, t *testing.T, pool *pgxpool.Pool)

// moduleStates — обе стороны сверки по каждому модулю.
func moduleStates(ctx context.Context, t *testing.T, set modulemanifests.Set, edit between) (
	[]moduleseedparity.ModuleState, moduleseedparity.Census, []string,
) {
	t.Helper()

	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Манифесты разбираются ДО чтения живого: их же получает применитель, и
	// второго разбора здесь не заводится — он разошёлся бы с первым молча.
	loaded := loadManifests(t, set)
	applyDeliveredSeed(ctx, t, pool, loaded)
	if edit != nil {
		edit(ctx, t, pool)
	}

	// Владелец группы — по ОБЪЯВЛЕНИЮ в тех же прочитанных манифестах (Р5).
	ownership := moduleseedparity.GroupOwnership{}
	for _, m := range loaded {
		if m.Seed == nil {
			continue
		}
		for _, g := range m.Seed.Groups {
			ownership.Declare(m.Module, declaredSpelling(g.Account), declaredSpelling(g.Name))
		}
	}

	liveSA, saByOwner, ownerlessSA, liveSANames := readLiveServiceAccounts(ctx, t, pool)
	liveJoin, joinByOwner, ownerlessJoin := readLiveJoins(ctx, t, pool)
	liveGroup, groupByOwner, ownerlessGroup := readLiveGroups(ctx, t, pool, ownership)
	liveBinding, bindingByOwner, ownerlessBinding := readLiveBindings(ctx, t, pool, ownership)

	census := moduleseedparity.Census{
		SA:       moduleseedparity.Subsection{Live: liveSA, Ownerless: ownerlessSA},
		Groups:   moduleseedparity.Subsection{Live: liveGroup, Ownerless: ownerlessGroup},
		Bindings: moduleseedparity.Subsection{Live: liveBinding, Ownerless: ownerlessBinding},
		Joins:    moduleseedparity.Subsection{Live: liveJoin, Ownerless: ownerlessJoin},
	}

	var (
		states  []moduleseedparity.ModuleState
		claimed = map[string]bool{}
	)
	for i, file := range set.Files {
		m := loaded[i]
		census.Manifests++
		claimed[m.Module] = true
		states = append(states, stateOf(m.Module, file, m,
			saByOwner, groupByOwner, bindingByOwner, joinByOwner, &census))
	}
	// Модуль закрытого набора, у которого живой посев есть, а манифеста нет,
	// молчал бы иначе: его строки не попали бы ни в одно состояние.
	//
	// НО ТОЛЬКО В ПОСАДКЕ, ГДЕ МАНИФЕСТ МОГ БЫ БЫТЬ ПРОЧИТАН (#2377). В
	// самостоятельном клоне манифестов соседей нет BY CONSTRUCTION — они
	// доезжают доставкой в рантайме, а не деревом сборки, — поэтому КАЖДЫЙ
	// чужой модуль попадал бы сюда всегда, и сверка краснела бы при любом
	// дереве. Проверка, краснеющая всегда, перестаёт читаться, и первым снимут
	// её саму.
	//
	// Поэтому чужие модули здесь не судятся, а СЧИТАЮТСЯ: их число печатается
	// отдельной строкой переписи, и «сверено меньше» остаётся отличимо от
	// «расхождений нет».
	outOfPosture := 0
	for _, mod := range authzmap.CatalogSeedModules() {
		if claimed[mod] {
			continue
		}
		if len(saByOwner[mod])+len(groupByOwner[mod])+len(bindingByOwner[mod])+len(joinByOwner[mod]) == 0 {
			continue
		}
		if set.Posture != modulemanifests.PlatformTree {
			outOfPosture++
			continue
		}
		states = append(states, stateOf(mod, "(манифеста в дереве нет)", nil,
			saByOwner, groupByOwner, bindingByOwner, joinByOwner, &census))
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Module < states[j].Module })
	if outOfPosture > 0 {
		t.Logf("вне посадки: модулей с живым посевом и без манифеста %d — их манифесты "+
			"доезжают ДОСТАВКОЙ, а не деревом сборки, и здесь они не судятся", outOfPosture)
	}

	// «С владельцем» считается по ТОМУ ЖЕ множеству, что судит сверка: второе
	// выражение разошлось бы с первым молча, и перепись обещала бы не то, что
	// судится. Прежде здесь считалась ещё и «формой невыразимая» часть — она
	// снята вместе со своим предметом (#1936).
	for _, st := range states {
		census.SA.Owned += len(st.LiveSA)
		census.Joins.Owned += len(st.LiveJoin)
		census.Groups.Owned += len(st.LiveGroup)
		census.Bindings.Owned += len(st.LiveBinding)
	}
	return states, census, liveSANames
}

// loadManifests разбирает манифесты перечня В ТОМ ЖЕ ПОРЯДКЕ, в каком они в нём
// стоят: применитель и сверка обязаны говорить об одних документах, а не о двух
// независимо собранных множествах.
func loadManifests(t *testing.T, set modulemanifests.Set) []*manifest.Manifest {
	t.Helper()
	out := make([]*manifest.Manifest, 0, len(set.Files))
	for _, file := range set.Files {
		// #nosec G304 -- путь получен обходом дерева ЭТОГО прогона, снаружи не приходит
		src, rerr := os.ReadFile(filepath.Join(set.Root, filepath.FromSlash(file)))
		require.NoErrorf(t, rerr, "манифест %s не прочитан", file)

		m, lerr := manifest.Load(src)
		require.NoErrorf(t, lerr, "манифест %s не разобран: сверять нечем", file)
		out = append(out, m)
	}
	return out
}

// applyDeliveredSeed зовёт применитель посева ровно так, как его зовёт
// композиционный корень, и печатает перепись — ВСЕГДА, независимо от исхода.
//
// Свой манифест службы (`module: iam`) подаётся ОТДЕЛЬНЫМ доводом и первым, как
// в корне (Р3): среди прочитанных он один, остальные — доставленные. Перечень
// не делится по посадке: в самостоятельном клоне он состоит из одного своего,
// в дереве платформы свой лежит среди `services/*`.
//
// Перепись здесь несущая, а не украшение: «расхождений нет» на применителе,
// который не записал НИ ОДНОЙ строки, читалось бы как согласие, а означало бы,
// что сверять было нечего с обеих сторон.
func applyDeliveredSeed(ctx context.Context, t *testing.T, pool *pgxpool.Pool, manifests []*manifest.Manifest) {
	t.Helper()
	var own *manifest.Manifest
	delivered := make([]*manifest.Manifest, 0, len(manifests))
	for _, m := range manifests {
		if m.Module == "iam" {
			require.Nil(t, own, "манифест службы прочитан дважды — перечень несёт копию")
			own = m
			continue
		}
		delivered = append(delivered, m)
	}
	applier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))
	census, err := applier.Apply(ctx, own, delivered)
	t.Logf("перепись применения посева: %s", census)
	require.NoError(t, err, "применитель посева отказал — живой стороны сверки не существует")
}

// stateOf — обе стороны одного модуля. Объявленное считается ЗДЕСЬ же, поэтому
// перепись объявленного и вход сверки не могут разойтись.
func stateOf(module, file string, m *manifest.Manifest,
	saByOwner map[string][]moduleseedparity.ServiceAccount,
	groupByOwner map[string][]moduleseedparity.Group,
	bindingByOwner map[string][]moduleseedparity.Binding,
	joinByOwner map[string][]moduleseedparity.Join,
	census *moduleseedparity.Census,
) moduleseedparity.ModuleState {
	sa, groups, bindings, joins := declaredSeed(m)
	census.SA.Declared += len(sa)
	census.Groups.Declared += len(groups)
	census.Bindings.Declared += len(bindings)
	census.Joins.Declared += len(joins)

	return moduleseedparity.ModuleState{
		Module:          module,
		ManifestFile:    file,
		DeclaredSA:      sa,
		LiveSA:          saByOwner[module],
		DeclaredGroup:   groups,
		LiveGroup:       groupByOwner[module],
		DeclaredBinding: bindings,
		LiveBinding:     bindingByOwner[module],
		DeclaredJoin:    joins,
		LiveJoin:        joinByOwner[module],
	}
}

// declaredSeed — сторона манифеста, все четыре подраздела.
func declaredSeed(m *manifest.Manifest) ([]moduleseedparity.ServiceAccount, []moduleseedparity.Group,
	[]moduleseedparity.Binding, []moduleseedparity.Join,
) {
	if m == nil || m.Seed == nil {
		return nil, nil, nil, nil
	}
	sa := make([]moduleseedparity.ServiceAccount, 0, len(m.Seed.ServiceAccounts))
	for _, s := range m.Seed.ServiceAccounts {
		sa = append(sa, moduleseedparity.ServiceAccount{
			Account: declaredSpelling(s.Account), Name: declaredSpelling(s.Name),
			Description: s.Description,
		})
	}
	groups := make([]moduleseedparity.Group, 0, len(m.Seed.Groups))
	for _, g := range m.Seed.Groups {
		groups = append(groups, moduleseedparity.Group{
			Account: declaredSpelling(g.Account), Name: declaredSpelling(g.Name),
			Description: g.Description,
		})
	}
	// Выдача манифеста несёт СПИСОК субъектов, а в базе каждый субъект — своя
	// строка со своей линией отзыва. Раскладываем здесь, иначе сверка сравнивала
	// бы одно объявление с N живыми строками и находила расхождение всегда.
	var bindings []moduleseedparity.Binding
	for _, b := range m.Seed.AccessBindings {
		for _, subj := range b.Subjects {
			bindings = append(bindings, moduleseedparity.Binding{
				SubjectType: subj.Type, SubjectName: declaredSpelling(subj.Name),
				RoleID: b.RoleID, Relation: b.GrantedRelation,
				ScopeType: b.ScopeType, ScopeID: b.ScopeID,
			})
		}
	}
	joins := make([]moduleseedparity.Join, 0, len(m.Seed.Joins))
	for _, j := range m.Seed.Joins {
		joins = append(joins, moduleseedparity.Join{
			AccountName:  declaredSpelling(j.ServiceAccount.Account),
			SAName:       declaredSpelling(j.ServiceAccount.Name),
			GroupAccount: declaredSpelling(j.Group.Account),
			GroupName:    declaredSpelling(j.Group.Name),
		})
	}
	return sa, groups, bindings, joins
}

// readLiveServiceAccounts читает служебные записи живой базы и раскладывает их
// по модулю-владельцу — имени `kacho-<служба>`.
func readLiveServiceAccounts(ctx context.Context, t *testing.T, pool *pgxpool.Pool) (
	total int, byOwner map[string][]moduleseedparity.ServiceAccount, ownerless int, names []string,
) {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT a.name, sa.name, sa.description
		   FROM kaname.service_accounts sa
		   JOIN kaname.accounts a ON a.id = sa.account_id
		  ORDER BY a.name, sa.name`)
	require.NoError(t, err)
	defer rows.Close()

	byOwner = map[string][]moduleseedparity.ServiceAccount{}
	for rows.Next() {
		var account, name, description string
		require.NoError(t, rows.Scan(&account, &name, &description))
		total++
		names = append(names, name)

		owner, ok := ownerOfSeededName(name)
		if !ok {
			ownerless++
			continue
		}
		byOwner[owner] = append(byOwner[owner], moduleseedparity.ServiceAccount{
			Account: account, Name: name, Description: description,
		})
	}
	require.NoError(t, rows.Err())
	return total, byOwner, ownerless, names
}

// liveNamesInclude — есть ли названное имя среди прочитанных.
//
// Отдельной функцией, а не выражением на месте: якорь читается в теле пробы, и
// вынесенный предикат называет, ЧТО именно спрашивается.
func liveNamesInclude(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// ownerOfSeededName — модуль-владелец СЛУЖЕБНОЙ ЗАПИСИ по её ИМЕНИ: имя вида
// `kacho-<служба>`, служба — из закрытого набора платформы. Имя назначает сам
// модуль, поэтому оно и есть его подпись.
//
// Здесь стояло «Правило ОДНО на служебную запись и на группу … Второе правило
// для второго предмета разошлось бы с первым молча». Довод верен для двух правил
// об ОДНОМ предмете; здесь предметы разные: группу относит к модулю тот, кто её
// ОБЪЯВИЛ (`moduleseedparity.GroupOwnership`, Р5), а не форма имени — обе живые
// группы платформы правилу имени не отвечали никогда, и владельцем их не был
// никто. У одной строки по-прежнему ровно один ответ: правило выбирается видом
// строки, и разойтись им не на чем.
func ownerOfSeededName(name string) (string, bool) {
	service, ok := strings.CutPrefix(name, seededNamePrefix)
	if !ok {
		return "", false
	}
	module, ok := platformmodules.CatalogModuleOfService(service)
	if !ok || !domain.ModuleSetOf(authzmap.CatalogSeedModules()...).IsKnownModule(module) {
		return "", false
	}
	return module, true
}

// readLiveJoins читает членство живой базы и раскладывает его по владельцу
// ВСТУПАЮЩЕЙ записи: членство заявляет вступающий, а не владелец группы.
func readLiveJoins(ctx context.Context, t *testing.T, pool *pgxpool.Pool) (
	total int, byOwner map[string][]moduleseedparity.Join, ownerless int,
) {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT sa_acc.name, sa.name, grp_acc.name, g.name
		   FROM kaname.group_members gm
		   JOIN kaname.groups g ON g.id = gm.group_id
		   JOIN kaname.accounts grp_acc ON grp_acc.id = g.account_id
		   JOIN kaname.service_accounts sa ON sa.id = gm.member_id
		   JOIN kaname.accounts sa_acc ON sa_acc.id = sa.account_id
		  WHERE gm.member_type = 'service_account'
		  ORDER BY sa.name, g.name`)
	require.NoError(t, err)
	defer rows.Close()

	byOwner = map[string][]moduleseedparity.Join{}
	for rows.Next() {
		var j moduleseedparity.Join
		require.NoError(t, rows.Scan(&j.AccountName, &j.SAName, &j.GroupAccount, &j.GroupName))
		total++

		owner, ok := ownerOfSeededName(j.SAName)
		if !ok {
			ownerless++
			continue
		}
		byOwner[owner] = append(byOwner[owner], j)
	}
	require.NoError(t, rows.Err())
	return total, byOwner, ownerless
}

// readLiveGroups читает группы живой базы и относит их к модулю, ЧЕЙ МАНИФЕСТ
// ИХ ОБЪЯВЛЯЕТ, — по паре (аккаунт, имя) в прочитанных манифестах (Р5).
// Группа, которую не объявил никто, владельца не имеет и считается отдельно.
//
// Здесь стояло «относит их … ТЕМ ЖЕ правилом имени, что и служебные записи …
// ни одна живая группа этому правилу не отвечает … „объявлено групп 0“ — верное
// объявление». Утверждение истекло вместе с разделом `seed` манифеста службы:
// он объявляет `module-relation-writers`, и правило имени дало бы ложную
// находку «группа ОБЪЯВЛЕНА и не живёт» на верном дереве.
func readLiveGroups(ctx context.Context, t *testing.T, pool *pgxpool.Pool, ownership moduleseedparity.GroupOwnership) (
	total int, byOwner map[string][]moduleseedparity.Group, ownerless int,
) {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT a.name, g.name, g.description
		   FROM kaname.groups g
		   JOIN kaname.accounts a ON a.id = g.account_id
		  ORDER BY a.name, g.name`)
	require.NoError(t, err)
	defer rows.Close()

	byOwner = map[string][]moduleseedparity.Group{}
	for rows.Next() {
		var g moduleseedparity.Group
		require.NoError(t, rows.Scan(&g.Account, &g.Name, &g.Description))
		total++

		owner, ok := ownership.OwnerOf(g.Account, g.Name)
		if !ok {
			ownerless++
			continue
		}
		byOwner[owner] = append(byOwner[owner], g)
	}
	require.NoError(t, rows.Err())
	return total, byOwner, ownerless
}

// readLiveBindings читает выдачи живой базы и относит их к модулю-владельцу по
// СУБЪЕКТУ: выдачу заводит установка того модуля, чью личность или группу она
// наделяет. Служебная запись относит по имени, группа — по объявлению этой
// группы (Р5, второе следствие). Выдача человеку владельца не имеет никогда —
// людей посев не заводит.
func readLiveBindings(ctx context.Context, t *testing.T, pool *pgxpool.Pool, ownership moduleseedparity.GroupOwnership) (
	total int, byOwner map[string][]moduleseedparity.Binding, ownerless int,
) {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT ab.subject_type,
		        COALESCE(sa.name, ''), COALESCE(g.name, ''), COALESCE(ga.name, ''),
		        COALESCE(ab.role_id, ''), ab.granted_relation,
		        ab.resource_type, ab.resource_id
		   FROM kaname.access_bindings ab
		   LEFT JOIN kaname.service_accounts sa
		          ON sa.id = ab.subject_id AND ab.subject_type = 'service_account'
		   LEFT JOIN kaname.groups g
		          ON g.id = ab.subject_id AND ab.subject_type = 'group'
		   LEFT JOIN kaname.accounts ga ON ga.id = g.account_id
		  ORDER BY ab.subject_type, ab.subject_id, ab.role_id, ab.granted_relation`)
	require.NoError(t, err)
	defer rows.Close()

	byOwner = map[string][]moduleseedparity.Binding{}
	for rows.Next() {
		var subjectType, saName, groupName, groupAccount, bareScope string
		var b moduleseedparity.Binding
		require.NoError(t, rows.Scan(&subjectType, &saName, &groupName, &groupAccount,
			&b.RoleID, &b.Relation, &bareScope, &b.ScopeID))
		total++

		// Якорь области переводится в точечную форму ТЕМ ЖЕ переводчиком, что
		// применяет край (`domain.ScopeTypeToDotted`): своя копия перевода была
		// бы вторым словарём об одном предмете.
		b.ScopeType = domain.ScopeTypeToDotted(bareScope)

		owner, name, ok := ownerOfBindingSubject(ownership, subjectType, saName, groupAccount, groupName)
		if !ok {
			ownerless++
			continue
		}
		b.SubjectType, b.SubjectName = subjectTypeOfManifest(subjectType), name
		byOwner[owner] = append(byOwner[owner], b)
	}
	require.NoError(t, rows.Err())
	return total, byOwner, ownerless
}

// ownerOfBindingSubject — модуль-владелец выдачи по её субъекту: служебная
// запись — по имени, группа — по объявлению пары (аккаунт, имя).
func ownerOfBindingSubject(ownership moduleseedparity.GroupOwnership,
	subjectType, saName, groupAccount, groupName string,
) (owner, name string, ok bool) {
	switch subjectType {
	case "service_account":
		owner, ok = ownerOfSeededName(saName)
		return owner, saName, ok
	case "group":
		owner, ok = ownership.OwnerOf(groupAccount, groupName)
		return owner, groupName, ok
	default:
		// Человек и подстановочный субъект посевом модуля не заводятся вовсе.
		return "", "", false
	}
}

// subjectTypeOfManifest — вид субъекта в написании МАНИФЕСТА. Перевод делается
// здесь, на чтении, один раз: сравнение по месту тащило бы два написания.
func subjectTypeOfManifest(live string) string {
	if live == "service_account" {
		return moduleseedparity.SubjectTypeServiceAccount
	}
	return live
}

// manifestSet — манифесты, доступные пробе В ЭТОЙ ПОСАДКЕ, и корень, от которого
// они отсчитаны.
//
// Перечень по-прежнему ВЫВОДИТСЯ, а не выписывается: выписанный разошёлся бы с
// деревом молча в день появления седьмого манифеста. Изменилось одно — обход
// каталога модулей ПЛАТФОРМЫ заменён источником, который отвечает в ОБЕИХ
// посадках (#2377): после разреза службы `services/` рядом с модулем нет, и
// прежний обход отказывал бы из os.ReadDir, то есть выглядел бы поломкой пробы,
// а не сдвигом дерева. Что именно прочитано и в какой посадке — печатает
// перепись вызывающего.
func manifestSet(t *testing.T) modulemanifests.Set {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err, "рабочий каталог не установлен: посадку назвать нечем")
	set, err := modulemanifests.Available(wd)
	require.NoError(t, err, "перечень манифестов не снят — проверка НЕ ИСПОЛНЯЛАСЬ")
	return set
}
