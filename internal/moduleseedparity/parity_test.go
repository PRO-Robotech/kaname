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
// невыразимое ПЕЧАТАЕТСЯ поимённо и считается по владельцу. Проба предпосылки
// требует, чтобы у выдачи по-прежнему не было ключа для отношения, и краснеет в
// тот прогон, когда ключ появится.
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

// Пороги чтения: ниже них молчание гейта сказано ни о чём. Числа взяты у живой
// базы этого дерева с запасом вниз — порог стережёт ОБВАЛ чтения, а не
// сегодняшнее состояние посева, которое законно меняется миграциями.
const (
	liveServiceAccountFloor = 3
	liveBindingFloor        = 3
	liveGroupFloor          = 1
)

// seededNamePrefix — по этому написанию живая строка переводится в
// модуль-владелец: `kacho-<служба>`, служба — из словаря платформы.
const seededNamePrefix = "kacho-"

// TestModuleManifestDeclaresTheSeedTheLiveBaseHolds — сам гейт.
func TestModuleManifestDeclaresTheSeedTheLiveBaseHolds(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: вердикт этого гейта даёт ПРОГОН против живой базы, " +
			"а не разбор миграций")
	}
	ctx := context.Background()
	set := manifestSet(t)

	states, census := moduleStates(ctx, t, set)

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
	require.GreaterOrEqual(t, census.SA.Live, liveServiceAccountFloor,
		"служебных записей прочитано %d при пороге %d — чтение перестало видеть предмет",
		census.SA.Live, liveServiceAccountFloor)
	require.NotZero(t, census.Joins.Live,
		"вступлений прочитано ноль — чтение членства перестало видеть предмет")
	require.GreaterOrEqual(t, census.Bindings.Live, liveBindingFloor,
		"выдач прочитано %d при пороге %d — чтение выдач перестало видеть предмет",
		census.Bindings.Live, liveBindingFloor)
	require.GreaterOrEqual(t, census.Groups.Live, liveGroupFloor,
		"групп прочитано %d при пороге %d — чтение групп перестало видеть предмет",
		census.Groups.Live, liveGroupFloor)

	res := moduleseedparity.Compare(states)

	if len(res.Findings) > 0 {
		t.Fatalf("раздел `seed` расходится с живой базой — %d место(а):\n  %s\n\n"+
			"Снятие: объявить `seed` модуля так, чтобы он сходился со строками, которые уже "+
			"лежат в базе (#1891). Выведенных из-под вердикта строк больше НЕТ: форма "+
			"научилась выражать выдачу отношением (#1936), и всякая живая строка модуля "+
			"судится наравне с остальными.",
			len(res.Findings), strings.Join(res.Findings, "\n  "))
	}
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

// moduleStates — обе стороны сверки по каждому модулю.
func moduleStates(ctx context.Context, t *testing.T, set modulemanifests.Set) (
	[]moduleseedparity.ModuleState, moduleseedparity.Census,
) {
	t.Helper()

	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Манифесты разбираются ДО чтения живого: их же получает применитель, и
	// второго разбора здесь не заводится — он разошёлся бы с первым молча.
	loaded := loadManifests(t, set)
	applyDeliveredSeed(ctx, t, pool, loaded)

	liveSA, saByOwner, ownerlessSA := readLiveServiceAccounts(ctx, t, pool)
	liveJoin, joinByOwner, ownerlessJoin := readLiveJoins(ctx, t, pool)
	liveGroup, groupByOwner, ownerlessGroup := readLiveGroups(ctx, t, pool)
	liveBinding, bindingByOwner, ownerlessBinding := readLiveBindings(ctx, t, pool)

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
	return states, census
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
// Перепись здесь несущая, а не украшение: «расхождений нет» на применителе,
// который не записал НИ ОДНОЙ строки, читалось бы как согласие, а означало бы,
// что сверять было нечего с обеих сторон.
func applyDeliveredSeed(ctx context.Context, t *testing.T, pool *pgxpool.Pool, manifests []*manifest.Manifest) {
	t.Helper()
	applier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))
	census, err := applier.ApplyAll(ctx, manifests)
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
			Account: s.Account, Name: s.Name, Description: s.Description,
		})
	}
	groups := make([]moduleseedparity.Group, 0, len(m.Seed.Groups))
	for _, g := range m.Seed.Groups {
		groups = append(groups, moduleseedparity.Group{
			Account: g.Account, Name: g.Name, Description: g.Description,
		})
	}
	// Выдача манифеста несёт СПИСОК субъектов, а в базе каждый субъект — своя
	// строка со своей линией отзыва. Раскладываем здесь, иначе сверка сравнивала
	// бы одно объявление с N живыми строками и находила расхождение всегда.
	var bindings []moduleseedparity.Binding
	for _, b := range m.Seed.AccessBindings {
		for _, subj := range b.Subjects {
			bindings = append(bindings, moduleseedparity.Binding{
				SubjectType: subj.Type, SubjectName: subj.Name,
				RoleID: b.RoleID, Relation: b.GrantedRelation,
				ScopeType: b.ScopeType, ScopeID: b.ScopeID,
			})
		}
	}
	joins := make([]moduleseedparity.Join, 0, len(m.Seed.Joins))
	for _, j := range m.Seed.Joins {
		joins = append(joins, moduleseedparity.Join{
			AccountName:  j.ServiceAccount.Account,
			SAName:       j.ServiceAccount.Name,
			GroupAccount: j.Group.Account,
			GroupName:    j.Group.Name,
		})
	}
	return sa, groups, bindings, joins
}

// readLiveServiceAccounts читает служебные записи живой базы и раскладывает их
// по модулю-владельцу — имени `kacho-<служба>`.
func readLiveServiceAccounts(ctx context.Context, t *testing.T, pool *pgxpool.Pool) (
	total int, byOwner map[string][]moduleseedparity.ServiceAccount, ownerless int,
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
	return total, byOwner, ownerless
}

// ownerOfSeededName — модуль-владелец заведённой посевом строки по её ИМЕНИ.
//
// Правило ОДНО на служебную запись и на группу: имя вида `kacho-<служба>`,
// служба — из закрытого набора платформы. Второе правило для второго предмета
// разошлось бы с первым молча, а строка, имени не отвечающая, принадлежит
// платформе, а не модулю, и считается отдельно.
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

// readLiveGroups читает группы живой базы и относит их к модулю-владельцу ТЕМ
// ЖЕ правилом имени, что и служебные записи: другого правила в дереве нет, а
// второе разошлось бы с первым молча.
//
// Сегодня ни одна живая группа этому правилу не отвечает — обе принадлежат
// платформе (`module-quota-readers`, `module-relation-writers` в аккаунте
// `kacho-system`) и модулями лишь ИСПОЛЬЗУЮТСЯ, о чём говорит подраздел
// вступлений. Поэтому «объявлено групп 0» — верное объявление, а не недостача.
func readLiveGroups(ctx context.Context, t *testing.T, pool *pgxpool.Pool) (
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

		owner, ok := ownerOfSeededName(g.Name)
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
// наделяет. Выдача человеку владельца не имеет никогда — людей посев не заводит.
func readLiveBindings(ctx context.Context, t *testing.T, pool *pgxpool.Pool) (
	total int, byOwner map[string][]moduleseedparity.Binding, ownerless int,
) {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT ab.subject_type,
		        COALESCE(sa.name, ''), COALESCE(g.name, ''),
		        COALESCE(ab.role_id, ''), ab.granted_relation,
		        ab.resource_type, ab.resource_id
		   FROM kaname.access_bindings ab
		   LEFT JOIN kaname.service_accounts sa
		          ON sa.id = ab.subject_id AND ab.subject_type = 'service_account'
		   LEFT JOIN kaname.groups g
		          ON g.id = ab.subject_id AND ab.subject_type = 'group'
		  ORDER BY ab.subject_type, ab.subject_id, ab.role_id, ab.granted_relation`)
	require.NoError(t, err)
	defer rows.Close()

	byOwner = map[string][]moduleseedparity.Binding{}
	for rows.Next() {
		var subjectType, saName, groupName, bareScope string
		var b moduleseedparity.Binding
		require.NoError(t, rows.Scan(&subjectType, &saName, &groupName,
			&b.RoleID, &b.Relation, &bareScope, &b.ScopeID))
		total++

		// Якорь области переводится в точечную форму ТЕМ ЖЕ переводчиком, что
		// применяет край (`domain.ScopeTypeToDotted`): своя копия перевода была
		// бы вторым словарём об одном предмете.
		b.ScopeType = domain.ScopeTypeToDotted(bareScope)

		owner, name, ok := ownerOfBindingSubject(subjectType, saName, groupName)
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

// ownerOfBindingSubject — модуль-владелец выдачи по её субъекту.
func ownerOfBindingSubject(subjectType, saName, groupName string) (owner, name string, ok bool) {
	switch subjectType {
	case "service_account":
		owner, ok = ownerOfSeededName(saName)
		return owner, saName, ok
	case "group":
		owner, ok = ownerOfSeededName(groupName)
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
