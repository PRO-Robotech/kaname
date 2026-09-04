// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// parity_test.go — держатель второй половины #1891: манифест модуля ОБЪЯВЛЯЕТ
// посев, который у модуля есть, и объявление сходится с живой базой.
//
// # Почему прогон против базы, а не разбор миграций
//
// Так требует предикат снятия задачи, и требует по существу. Действующий посев
// есть НАЛОЖЕНИЕ применённых миграций: запись, заведённая одной, снимается
// другой (служебная запись сетевого оператора была заведена и снята, и в базе
// её нет). Разбор SQL — распознаватель: форму записи, которой он не знает, он
// пропускает МОЛЧА, и его молчание неотличимо от согласия. Здесь миграции
// исполняются, а строки читаются оттуда, где лежат.
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

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/pkg/platformmodules"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/moduleseedparity"
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
	root := repoRoot(t)

	states, census := moduleStates(ctx, t, root)

	// Перепись — ДО всякого вердикта и независимо от него.
	t.Logf("перепись: %s", census)
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
func moduleStates(ctx context.Context, t *testing.T, root string) (
	[]moduleseedparity.ModuleState, moduleseedparity.Census,
) {
	t.Helper()

	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

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
	for _, file := range manifestFiles(t, root) {
		// #nosec G304 -- путь получен обходом каталога сервисов ЭТОГО репозитория
		src, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		require.NoErrorf(t, rerr, "манифест %s не прочитан", file)

		m, lerr := manifest.Load(src)
		require.NoErrorf(t, lerr, "манифест %s не разобран: сверять нечем", file)

		census.Manifests++
		claimed[m.Module] = true
		states = append(states, stateOf(m.Module, file, m,
			saByOwner, groupByOwner, bindingByOwner, joinByOwner, &census))
	}
	// Модуль закрытого набора, у которого живой посев есть, а манифеста нет,
	// молчал бы иначе: его строки не попали бы ни в одно состояние.
	for _, mod := range authzmap.CatalogSeedModules() {
		if claimed[mod] {
			continue
		}
		if len(saByOwner[mod])+len(groupByOwner[mod])+len(bindingByOwner[mod])+len(joinByOwner[mod]) == 0 {
			continue
		}
		states = append(states, stateOf(mod, "(манифеста в дереве нет)", nil,
			saByOwner, groupByOwner, bindingByOwner, joinByOwner, &census))
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Module < states[j].Module })

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
		   FROM kacho_iam.service_accounts sa
		   JOIN kacho_iam.accounts a ON a.id = sa.account_id
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
		   FROM kacho_iam.group_members gm
		   JOIN kacho_iam.groups g ON g.id = gm.group_id
		   JOIN kacho_iam.accounts grp_acc ON grp_acc.id = g.account_id
		   JOIN kacho_iam.service_accounts sa ON sa.id = gm.member_id
		   JOIN kacho_iam.accounts sa_acc ON sa_acc.id = sa.account_id
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
		   FROM kacho_iam.groups g
		   JOIN kacho_iam.accounts a ON a.id = g.account_id
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
		   FROM kacho_iam.access_bindings ab
		   LEFT JOIN kacho_iam.service_accounts sa
		          ON sa.id = ab.subject_id AND ab.subject_type = 'service_account'
		   LEFT JOIN kacho_iam.groups g
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

// manifestFiles — манифесты модулей, ВЫВЕДЕННЫЕ обходом каталога сервисов.
func manifestFiles(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "services"))
	require.NoError(t, err)

	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rel := filepath.ToSlash(filepath.Join("services", e.Name(), "manifest.yaml"))
		if _, serr := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); serr == nil {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// repoRoot — корень монорепо: ближайший вверх каталог с go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqualf(t, parent, dir, "go.mod не найден выше %s", dir)
		dir = parent
	}
}
