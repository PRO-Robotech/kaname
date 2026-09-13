// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subordinate_resource_test.go — гейт на КЛАСС «второй источник имён стал
// самозаявлением» (задача #1191, приёмка §3.3, утверждения G1–G4).
//
// # Предмет
//
// Вид учёта обязан называть реальные типы модели прав. Удостоверение типом не
// является и не должно им стать, поэтому заведён второй закрытый перечень —
// подчинённые ресурсы. Закрытость сама по себе ничего не держит: перечень, чьи
// записи ничем не проверяются, отличается от свободного текста только видом.
//
// Здесь проверяется ВНУТРЕННЯЯ согласованность записи (G1–G4). Её АНКЕР в
// дереве — существование таблиц и стоящих на них триггеров списания — живёт
// рядом с миграциями (G5–G7), потому что судит SQL.
//
// # Способность упасть доказывается инъекцией, а не прочтением
//
// Судья вынесен отдельной функцией именно затем, чтобы его можно было покормить
// синтетическим перечнем. Проверка, которую нельзя покормить настоящим дефектом,
// о своей способности упасть не утверждает ничего.

package authzmap_test

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// authzmapResolves — членство двухчастного токена в закрытой таблице типов
// модели прав.
//
// ЖИЛ В `limit_kind_catalog_test.go` — гейте, чей предмет (закрытый каталог
// видов авторитета величин) снят стадией S4 (`PRO-Robotech/kacho#2117`).
// Помощник переехал сюда вместе с единственным оставшимся вызывающим: оставить
// его в снятом файле значило бы удержать файл ради помощника, а завести второй —
// два места об одном предмете.
func authzmapResolves(dotted string) bool {
	module, resource, ok := authzmap.SplitObjectType(dotted)
	if !ok {
		return false
	}
	_, known := authzmap.ObjectType(module, resource)
	return known
}

// resolvesKindPart — токен называет либо тип модели прав, либо ОБЪЯВЛЕННЫЙ
// подчинённый ресурс.
//
// Переехал вместе с `authzmapResolves` из снятого `limit_kind_catalog_test.go`
// по той же причине.
func resolvesKindPart(dotted string) bool {
	if authzmapResolves(dotted) {
		return true
	}
	_, ok := domain.SubordinateResourceOf(domain.LimitKind(dotted))
	return ok
}

// subordinateFindings — судья записей подчинённых ресурсов.
//
// resolves отвечает, называет ли токен тип модели прав; counted — виды, которые
// служба считает. Оба переданы параметрами, а не взяты из пакета: инъекция
// подаёт сюда синтетику, и судья, ходящий за фактами сам, на ней бы не работал.
//
// НОСИТЕЛЬ ВЫВОДИТСЯ ИЗ ИМЕНИ ВИДА, а не приезжает рядом с ним. Прежде пара
// «вид + носитель» приходила из закрытого каталога авторитета величин; каталог
// ушёл вместе с авторитетом (`PRO-Robotech/kacho#2117`, стадия S4), и носителем
// вложенного вида стал его родитель — `iam.user.credential` считается в
// `iam.user`, и прочесть это можно из самого имени.
func subordinateFindings(
	records []domain.SubordinateResource,
	counted []domain.LimitKind,
	resolves func(string) bool,
) []string {
	var out []string
	byKind := map[domain.LimitKind]domain.SubordinateResource{}
	for _, r := range records {
		byKind[r.Kind] = r

		// G1 — два имени одной вещи запрещены.
		if resolves(string(r.Kind)) {
			out = append(out, fmt.Sprintf(
				"%s — объявлен подчинённым ресурсом И является типом модели прав: "+
					"одна вещь названа дважды, и следующий читатель не узнает, какое имя действует",
				r.Kind))
		}
		// G2 — родитель обязан быть настоящим типом.
		if len(r.Parents) == 0 {
			out = append(out, fmt.Sprintf(
				"%s — не назвал ни одного родителя: доступ производен неизвестно от чего", r.Kind))
		}
		for _, parent := range r.Parents {
			if !resolves(string(parent)) {
				out = append(out, fmt.Sprintf(
					"%s — родитель %q не найден в закрытой таблице типов модели прав",
					r.Kind, parent))
			}
		}
		// G3 — причина обязательна.
		if r.Why == "" {
			out = append(out, fmt.Sprintf(
				"%s — запись без причины неотличима от записи без предмета", r.Kind))
		}
		// Анкер обязан быть назван; ЧТО он называет, судят G5/G6 у миграций.
		if len(r.Tables) == 0 {
			out = append(out, fmt.Sprintf(
				"%s — не назвал ни одной таблицы: имя осталось самозаявлением, и опечатка "+
					"в нём доживёт до первой выдачи", r.Kind))
		}
	}

	// G4 — вложенный вид, чей ребёнок подчинён, считается в СВОЁМ родителе.
	for _, k := range counted {
		child := k.ChildKind()
		if child == "" {
			continue
		}
		rec, ok := byKind[child]
		if !ok {
			continue
		}
		carrier := k.ParentKind()
		var among bool
		for _, parent := range rec.Parents {
			if parent == carrier {
				among = true
				break
			}
		}
		if !among {
			out = append(out, fmt.Sprintf(
				"%s — носитель %q не среди родителей подчинённого ресурса %q: удостоверения "+
					"одного принципала считались бы в другом", k, carrier, child))
		}
	}
	sort.Strings(out)
	return out
}

// На сегодняшнем дереве находок нет — и перепись говорит, сколько прочитано.
func TestSubordinateResourcesAreConsistent(t *testing.T) {
	t.Parallel()

	records := domain.SubordinateResources()
	require.NotEmpty(t, records,
		"подчинённых ресурсов не объявлено — предпосылка гейта сломана, и его молчание "+
			"неотличимо от согласия")

	counted := domain.PostureStatedKinds()
	require.NotEmpty(t, counted,
		"служба не считает НИ ОДНОГО вида — предпосылка G4 пуста, и её молчание "+
			"неотличимо от согласия")
	require.Empty(t, subordinateFindings(records, counted, authzmapResolves))

	nested := 0
	for _, k := range counted {
		if _, ok := domain.SubordinateResourceOf(k.ChildKind()); ok {
			nested++
		}
	}
	require.NotZero(t, nested,
		"ни один вид не опирается на подчинённый ресурс: G4 не исполнялась ни разу, "+
			"и её ноль находок вынесен об обходе, а не о записях")
	t.Logf("перепись: записей подчинённых ресурсов %d, видов службы %d, из них опирающихся на подчинённый ресурс %d",
		len(records), len(counted), nested)
}

// Инъекция в ОБЕ стороны, по одному дефекту на утверждение. Рядом с каждым
// дефектом — законный близнец: без него «гейт краснеет» неотличимо от «гейт
// краснеет всегда».
func TestSubordinateResourceGateCanFail(t *testing.T) {
	t.Parallel()

	lawful := domain.SubordinateResource{
		Kind:    "iam.credential",
		Parents: []domain.LimitKind{"iam.user", "iam.serviceAccount"},
		Tables:  []string{"kaname.user_oauth_clients"},
		Why:     "право вычисляется от принципала",
	}
	lawfulCounted := []domain.LimitKind{"iam.user.credential"}

	t.Run("G1: имя, которое И подчинённый ресурс, И тип модели прав", func(t *testing.T) {
		bad := lawful
		bad.Kind = "iam.user" // настоящий тип модели прав
		bad.Parents = []domain.LimitKind{"iam.serviceAccount"}
		require.NotEmpty(t,
			subordinateFindings([]domain.SubordinateResource{bad}, nil, authzmapResolves),
			"запись, дублирующая тип модели прав, обязана быть находкой")
		require.Empty(t,
			subordinateFindings([]domain.SubordinateResource{lawful}, nil, authzmapResolves),
			"законный близнец: сегодняшняя запись — молчание")
	})

	t.Run("G2: родитель, которого нет среди типов", func(t *testing.T) {
		bad := lawful
		bad.Parents = []domain.LimitKind{"iam.nonesuch"}
		found := subordinateFindings([]domain.SubordinateResource{bad}, nil, authzmapResolves)
		require.Len(t, found, 1)
		require.Contains(t, found[0], "iam.nonesuch",
			"находка обязана НАЗВАТЬ родителя, которого нет")
		require.Empty(t,
			subordinateFindings([]domain.SubordinateResource{lawful}, nil, authzmapResolves),
			"законный близнец: настоящие родители — молчание")
	})

	t.Run("G3: пустая причина", func(t *testing.T) {
		bad := lawful
		bad.Why = ""
		require.NotEmpty(t,
			subordinateFindings([]domain.SubordinateResource{bad}, nil, authzmapResolves))
		require.Empty(t,
			subordinateFindings([]domain.SubordinateResource{lawful}, nil, authzmapResolves))
	})

	t.Run("анкер: запись без таблиц", func(t *testing.T) {
		bad := lawful
		bad.Tables = nil
		require.NotEmpty(t,
			subordinateFindings([]domain.SubordinateResource{bad}, nil, authzmapResolves))
		require.Empty(t,
			subordinateFindings([]domain.SubordinateResource{lawful}, nil, authzmapResolves))
	})

	t.Run("G4: носитель вида не среди родителей записи", func(t *testing.T) {
		// Удостоверения считаются в принципале, которого запись родителем не
		// называет: списание писало бы их в счёт чужого носителя.
		//
		// ДЕФЕКТ ВНОСИТСЯ ИМЕНЕМ ВИДА, а не парой «вид + носитель»: носитель
		// выводится из имени, и подать «тот же вид с другим носителем» стало
		// невыразимо by construction. Дельта против близнеца по-прежнему ОДИН
		// факт — первая часть имени.
		wrong := []domain.LimitKind{"iam.group.credential"}
		found := subordinateFindings([]domain.SubordinateResource{lawful}, wrong, authzmapResolves)
		require.Len(t, found, 1)
		require.Contains(t, found[0], "iam.group.credential")
		require.Contains(t, found[0], "iam.group",
			"находка обязана НАЗВАТЬ носителя, которого нет среди родителей")

		require.Empty(t,
			subordinateFindings([]domain.SubordinateResource{lawful}, lawfulCounted, authzmapResolves),
			"законный близнец: носитель среди родителей — молчание")
	})
}

// CRED-CAP-33 — расширенный резолвер частей вида по-прежнему ОТВЕРГАЕТ то, что
// отвергал до расширения.
//
// Это вторая половина утверждения «расширение, а не ослабление»: первая
// (подчинённый ресурс принимается) без неё неотличима от «принимается всё».
// Действующий гейт каталога проверяет старый предикат и о новом не утверждает
// ничего — он был написан раньше.
func TestResolvesKindPartAcceptsSubordinatesAndStillRefusesInventions(t *testing.T) {
	t.Parallel()

	for _, dotted := range []string{"iam.user", "iam.serviceAccount", "vpc.network"} {
		require.Truef(t, resolvesKindPart(dotted),
			"настоящий тип модели прав %q перестал резолвиться: расширение сломало то, "+
				"ради чего гейт существует", dotted)
	}
	require.True(t, resolvesKindPart("iam.credential"),
		"объявленный подчинённый ресурс не резолвится: вид `iam.user.credential` не пройдёт "+
			"гейт каталога, и потолок нельзя будет назвать")

	for _, dotted := range []string{
		"iam.nonesuch",    // выдуманное имя
		"iam.credentials", // множественное — та форма, на которой уже спотыкались
		"vpc.serviceEndpoint",
	} {
		require.Falsef(t, resolvesKindPart(dotted),
			"имя %q резолвится, хотя его нет НИ В ОДНОМ из двух источников: расширение "+
				"стало ослаблением, и опечатка доедет до арендатора", dotted)
	}
}
