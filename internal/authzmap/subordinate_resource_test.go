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

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// subordinateFindings — судья записей подчинённых ресурсов.
//
// resolves отвечает, называет ли токен тип модели прав; countable — состоит ли
// вид в каталоге. Оба переданы параметрами, а не взяты из пакета: инъекция
// подаёт сюда синтетику, и судья, ходящий за фактами сам, на ней бы не работал.
func subordinateFindings(
	records []domain.SubordinateResource,
	catalogue []domain.CountableKind,
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
	for _, e := range catalogue {
		child := e.Kind.ChildKind()
		if child == "" {
			continue
		}
		rec, ok := byKind[child]
		if !ok {
			continue
		}
		var among bool
		for _, parent := range rec.Parents {
			if domain.LimitCarrier(parent) == e.Carrier {
				among = true
				break
			}
		}
		if !among {
			out = append(out, fmt.Sprintf(
				"%s — носитель %q не среди родителей подчинённого ресурса %q: удостоверения "+
					"одного принципала считались бы в другом", e.Kind, e.Carrier, child))
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

	require.Empty(t, subordinateFindings(records, domain.CountableEntries(), authzmapResolves))

	nested := 0
	for _, e := range domain.CountableEntries() {
		if _, ok := domain.SubordinateResourceOf(e.Kind.ChildKind()); ok {
			nested++
		}
	}
	t.Logf("перепись: записей подчинённых ресурсов %d, видов каталога %d, из них опирающихся на подчинённый ресурс %d",
		len(records), len(domain.CountableEntries()), nested)
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
	lawfulCatalogue := []domain.CountableKind{{Kind: "iam.user.credential", Carrier: "iam.user"}}

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
		// Вид человека объявил носителем служебную учётку — списание писало бы
		// удостоверения человека в счёт машины.
		wrong := []domain.CountableKind{{Kind: "iam.user.credential", Carrier: "iam.group"}}
		found := subordinateFindings([]domain.SubordinateResource{lawful}, wrong, authzmapResolves)
		require.Len(t, found, 1)
		require.Contains(t, found[0], "iam.user.credential")

		require.Empty(t,
			subordinateFindings([]domain.SubordinateResource{lawful}, lawfulCatalogue, authzmapResolves),
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
