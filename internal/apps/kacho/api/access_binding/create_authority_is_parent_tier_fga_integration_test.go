// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// create_authority_is_parent_tier_fga_integration_test.go — наблюдаемая проба к
// снятию `v_create` с типов, у которых его никто не спрашивал.
//
// ЧТО ДОКАЗЫВАЕТСЯ. После снятия отношения тенант ПО-ПРЕЖНЕМУ может создать ресурс
// в СВОЁМ проекте и ПО-ПРЕЖНЕМУ не может в чужом. То есть право создавать не
// зависело от снятого отношения ни на йоту — оно и не могло зависеть: ни одна
// запись каталога прав не гейтит создание на `v_*`.
//
// ПОЧЕМУ ЭТО НЕ ПЕРЕСКАЗ ГЕЙТА. Соседний гейт (authzmap) читает ДЕРЕВО и говорит,
// что читателя нет. Эта проба задаёт вопрос НАСТОЯЩЕМУ хранилищу прав, поднятому
// на канонической модели, тем же способом, каким его задаёт край, и на состоянии,
// которое реконсайлер РЕАЛЬНО материализует для роли-редактора: ярусный кортеж на
// проекте и ничего больше. Ни одного `v_create` не пишется вообще — и создание
// работает. Именно это и означает «ничего не изменилось».
//
// ПРЕДПОСЫЛКА ПРОВЕРЯЕТСЯ. Population берётся из каталога прав по ГЛАГОЛУ токена
// права (`<module>.<resources>.create`), а не по имени метода: имя — привычка
// автора, глагол — то, что энфорсится. Если каталог вдруг начнёт гейтить создание
// на `v_*`, проба покраснеет на предпосылке, а не отчитается зелёным.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// createGate — (тип объекта области, требуемое отношение) одной записи каталога,
// чей глагол — `create`.
type createGate struct {
	ObjectType string
	Relation   string
}

// createGatesFromCatalog читает вшитую копию каталога прав и возвращает
// различные пары для записей с глаголом `create`.
func createGatesFromCatalog(t *testing.T) []createGate {
	t.Helper()
	root := monorepoRootForCreateAuthority(t)
	raw, err := os.ReadFile(filepath.Join(root,
		"services/iam/internal/apps/kacho/seed/embedded/permission_catalog.json"))
	require.NoError(t, err, "каталог прав не прочитан — у пробы нет population")

	var rows []struct {
		FQN            string `json:"fqn"`
		Permission     string `json:"permission"`
		RequiredRel    string `json:"required_relation"`
		ScopeExtractor struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}
	require.NoError(t, json.Unmarshal(raw, &rows))
	require.NotEmpty(t, rows, "каталог разобран в ноль записей")

	seen := map[createGate]bool{}
	for _, r := range rows {
		i := strings.LastIndexByte(r.Permission, '.')
		if i < 0 || r.Permission[i+1:] != "create" {
			continue
		}
		seen[createGate{ObjectType: r.ScopeExtractor.ObjectType, Relation: r.RequiredRel}] = true
	}
	out := make([]createGate, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObjectType != out[j].ObjectType {
			return out[i].ObjectType < out[j].ObjectType
		}
		return out[i].Relation < out[j].Relation
	})
	return out
}

func monorepoRootForCreateAuthority(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("корень монорепо (go.mod) не найден от %s", wd)
		}
		dir = parent
	}
}

// TestCreateAuthority_IsTheParentWriteTier_NotAPerObjectVerb — несущая проба.
func TestCreateAuthority_IsTheParentWriteTier_NotAPerObjectVerb(t *testing.T) {
	gates := createGatesFromCatalog(t)
	require.NotEmpty(t, gates, "в каталоге нет ни одной записи с глаголом `create` — "+
		"предикат population перестал читать свой предмет")

	// ПРЕДПОСЫЛКА: создание не гейтится пообъектным глаголом. Это и есть причина, по
	// которой `v_create` можно было снять; если она перестанет быть верной, всё
	// нижеследующее рассуждение недействительно, и проба обязана сказать об этом
	// здесь, а не отчитаться зелёным.
	var verbGated []string
	for _, g := range gates {
		if strings.HasPrefix(g.Relation, "v_") {
			verbGated = append(verbGated, g.ObjectType+"#"+g.Relation)
		}
	}
	require.Emptyf(t, verbGated,
		"каталог гейтит создание на пообъектном глаголе: %s. Создание в Kachō авторизуется "+
			"ярусом записи на РОДИТЕЛЕ — если это изменилось, снятие `v_create` надо пересмотреть, "+
			"а не подтверждать этой пробой", strings.Join(verbGated, ", "))
	t.Logf("перепись: различных гейтов создания в каталоге: %d — %v", len(gates), gates)

	c := startOpenFGA(t)

	const (
		subj        = "user:usr_createauth"
		stranger    = "user:usr_createauth_none"
		homeAccount = "account:acc_createauth_home"
		homeProject = "project:prj_createauth_home"
		fgnAccount  = "account:acc_createauth_fgn"
		fgnProject  = "project:prj_createauth_fgn"
	)

	// Ровно то, что реконсайлер материализует для роли-редактора, привязанной на
	// СВОЁМ проекте, плюс структурные указатели, которые пишут Create аккаунта и
	// проекта. НИ ОДНОГО кортежа `v_*` — ни на проекте, ни на аккаунте, нигде.
	c.write(t, []abrepo.RelationTuple{
		{User: homeAccount, Relation: "account", Object: homeProject},
		{User: fgnAccount, Relation: "account", Object: fgnProject},
		{User: subj, Relation: "editor", Object: homeProject},
		{User: subj, Relation: "editor", Object: homeAccount},
	})

	checkedPos, checkedNeg := 0, 0
	for _, g := range gates {
		var home, foreign string
		switch g.ObjectType {
		case "project":
			home, foreign = homeProject, fgnProject
		case "account":
			home, foreign = homeAccount, fgnAccount
		default:
			// `cluster` (админское создание) и родитель-лист (слушатель в своём
			// балансировщике) — не про арендаторскую пару «свой / чужой проект»;
			// их гейтят соседние пробы. Пропуск объявлен, а не молчалив.
			t.Logf("пропущен гейт %s#%s — область не тенантская пара «свой/чужой»", g.ObjectType, g.Relation)
			continue
		}

		require.Truef(t, c.check(t, subj, g.Relation, home),
			"тенант с ярусом редактора на своей области НЕ резолвит %q на %s — создание ресурса "+
				"в СВОЁМ проекте сломано, притом что ни одного кортежа `v_create` в хранилище нет "+
				"вовсе: значит право создавать от снятого отношения не зависело и не зависит",
			g.Relation, home)
		checkedPos++

		require.Falsef(t, c.check(t, subj, g.Relation, foreign),
			"тот же тенант резолвит %q на ЧУЖОЙ области %s — сужение исчезло", g.Relation, foreign)
		require.Falsef(t, c.check(t, stranger, g.Relation, home),
			"субъект без единого кортежа резолвит %q на %s — гейт создания ничего не сужает",
			g.Relation, home)
		checkedNeg += 2
	}
	require.Positive(t, checkedPos, "ни один гейт создания не был проверен положительно — "+
		"проба ничего не утверждает")

	// И ровно то отношение, которое сняли: тип его НЕ ОБЪЯВЛЯЕТ. Утверждается
	// именно это, а не «не разрешено»: булев ответ хранилища на неопределённое
	// отношение — `false`, неотличимый от «объявлено, но не выдано», поэтому
	// `require.False(check(...))` был бы истинным в обоих состояниях. Ключуемся на
	// отказ хранилища принять вопрос (`Defined`) — он бывает ровно в одном.
	if o := c.checkOutcome(t, subj, "v_create", homeProject); o.Defined {
		t.Fatalf("тип `project` ОБЪЯВЛЯЕТ `v_create` (хранилище приняло вопрос, ответ allowed=%v) — "+
			"отношение вернулось туда, где его никто не спрашивает", o.Allowed)
	}

	t.Logf("перепись: положительных проверок: %d, отрицательных: %d", checkedPos, checkedNeg)
}

// TestCreateAuthority_RegistryNamespaceKeepsItsReader — вторая половина: у
// единственного оставшегося носителя `v_create` он РАБОТАЕТ.
//
// Без этой пробы «сняли отношение везде» было бы неотличимо от «сняли отношение
// вообще»: первая проба зеленела бы одинаково в обоих случаях, потому что она
// утверждает ОТСУТСТВИЕ. Здесь утверждается присутствие — и именно там, где у
// отношения есть читатель (хендлер CreateRepository / RenameRepository и docker
// data-plane спрашивают `v_create` на `registry_registry`).
func TestCreateAuthority_RegistryNamespaceKeepsItsReader(t *testing.T) {
	c := startOpenFGA(t)

	const (
		owner    = "user:usr_regowner_ca"
		outsider = "user:usr_regoutsider_ca"
		project  = "project:prj_regca"
		registry = "registry_registry:reg_ca000000000000"
	)

	// Ровно то, что пишет регистрация ресурса реестром: структурный указатель на
	// проект и кортеж владельца. Ни одного `v_*` не пишется.
	c.write(t, []abrepo.RelationTuple{
		{User: project, Relation: "project", Object: registry},
		{User: owner, Relation: "owner", Object: registry},
	})

	require.True(t, c.check(t, owner, "v_create", registry),
		"владелец реестра не резолвит `v_create` на своём пространстве имён — CreateRepository "+
			"и docker-push в новый repo отказали бы владельцу на его собственном реестре (#64 Defect A)")
	require.False(t, c.check(t, outsider, "v_create", registry),
		"посторонний резолвит `v_create` на чужом реестре — сужение исчезло")

	// Парный контроль формы: то же отношение на обычном ресурсном типе НЕ
	// ОБЪЯВЛЕНО. Иначе «оставили одному реестру» было бы неотличимо от «оставили
	// всем» — проба выше зеленела бы и в том, и в другом случае.
	//
	// Утверждается отказ хранилища ПРИНЯТЬ вопрос, а не отрицательный ответ на
	// него. Прежняя редакция стояла здесь в форме `require.False(check(...))` и
	// была ЗЕЛЁНОЙ на инъекции `v_create` обратно в `vpc_network` — то есть ровно
	// на том состоянии, которое обещала поймать: булев ответ хранилища одинаков в
	// обоих (см. `checkOutcome`). Проверено инъекцией в обе стороны 2026-08-06.
	o := c.checkOutcome(t, owner, "v_create", "vpc_network:net_ca000000000000")
	require.Falsef(t, o.Defined,
		"тип `vpc_network` ОБЪЯВЛЯЕТ `v_create` (хранилище приняло вопрос, ответ allowed=%v) — "+
			"отношение вернулось туда, где его никто не спрашивает: «оставили одному реестру» "+
			"снова неотличимо от «оставили всем»", o.Allowed)
	require.Equalf(t, "validation_error", o.Code,
		"хранилище отвергло вопрос НЕ как неопределённое отношение, а иначе: %s %s — "+
			"дискриминатор этого контроля перестал быть дискриминатором", o.Code, o.Message)
}
