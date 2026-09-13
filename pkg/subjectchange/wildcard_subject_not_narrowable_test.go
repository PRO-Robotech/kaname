// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package subjectchange_test

// wildcard_subject_not_narrowable_test.go — какие строки ОБЯЗАНЫ гасить кэш
// решений ЦЕЛИКОМ, даже если сброс когда-нибудь станет поимённым (kacho#1395).
//
// # Что здесь защищается
//
// Кэш решений края ключуется КОНКРЕТНЫМ предъявителем (`user:<id>` /
// `service_account:<id>`, `middleware.buildCacheKey`). Поимённый сброс годится
// ровно для той строки, чьё имя совпадает с ключом задетых записей. Строка,
// чьё имя таким ключом НЕ является, задевает записи, которых по её имени не
// найти, — и поимённый сброс по ней не снимает НИЧЕГО.
//
// Таких видов три, и вид «подстановка» опаснее двух других тем, что он
// объявляет себя НАЗВАННЫМ:
//
//	user:*         → SubjectNamed     — задевает КАЖДОГО конкретного пользователя
//	group          → SubjectUserset   — задевает участников множества
//	тип потерян    → SubjectUnnameable— задевает неизвестно кого
//
// Размен, предложенный телом kacho#1395 («поимённо для строк с НАЗВАННЫМ типом,
// сплошной — для тех, кого назвать не удалось»), отделяет по `Subject == ""`.
// Подстановка это условие НЕ выполняет: имя у неё непустое. То есть предложенный
// размен уводит `user:*` в поимённую полосу, где по нему не гасится ничего, а
// вердикты, выданные по системной привязке `user:*`, переживают её снятие.
//
// # Чего гейт НАМЕРЕННО не требует
//
// Он НЕ утверждает, что конкретная строка (`user:usr-…`) гасит кэш целиком.
// Сегодня она гасит — сброс безусловен, — но правильное сужение вправе это
// изменить, и запрещать его здесь значило бы пинить нынешнее устройство вместо
// свойства. Гейт запрещает ровно ОДНУ форму сужения: ту, что считает подстановку
// адресуемым субъектом.
//
// Решение целиком — gateway/docs/engineering/architecture/decision-cache-invalidation-radius.md

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/authz"
	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// wildcardSubjectType/ID — системная подстановка «любой аутентифицированный».
//
// Взята не литералом «на глаз»: домен владельца прав допускает `subject_id = "*"`
// РОВНО для неё (`services/iam/internal/domain/access_binding.go`, условие
// `b.SubjectID == "*" && b.System && b.SubjectType == "user"`).
const (
	wildcardSubjectType = "user"
	wildcardSubjectID   = "*"
)

// nonAddressableRow — вид строки, по имени которой задетых записей НЕ НАЙТИ.
type nonAddressableRow struct {
	name   string
	change subjectchange.SubjectChange
	why    string
}

func nonAddressableRows(t *testing.T) []nonAddressableRow {
	t.Helper()
	wildcard, naming := authz.NameTenantSubject(wildcardSubjectType, wildcardSubjectID)

	// ПРЕДПОСЫЛКА ГЕЙТА, проверяемая, а не подразумеваемая.
	//
	// Гейт существует потому, что подстановка проходит дверь именования как
	// НАЗВАННЫЙ субъект и потому попадает в поимённую полосу любого сужения,
	// отделяющего по `Subject == ""`. Перестанет проходить — предпосылка
	// изменилась, и решение обязано быть перечитано, а не унаследовано молча.
	if naming != authz.SubjectNamed {
		t.Fatalf("предпосылка гейта изменилась: NameTenantSubject(%q, %q) даёт naming=%s, "+
			"а гейт писался на naming=named. Подстановка больше не выдаёт себя за адресуемого "+
			"субъекта — значит сужение по `Subject == \"\"` перестало быть опасным именно этим. "+
			"Перечитай решение (decision-cache-invalidation-radius.md) прежде чем править гейт",
			wildcardSubjectType, wildcardSubjectID, naming)
	}

	return []nonAddressableRow{
		{
			name:   "подстановка user:*",
			change: subjectchange.SubjectChange{ID: 2, Subject: wildcard, Naming: naming},
			why: "системная привязка `user:*` выдаёт право КАЖДОМУ аутентифицированному; " +
				"вердикты по ней лежат под конкретными предъявителями, и по имени `user:*` " +
				"не найдётся ни один",
		},
		{
			name:   "выдача группе",
			change: subjectchange.SubjectChange{ID: 2, Subject: "", Naming: authz.SubjectUserset},
			why:    "право выдано множеству; вердикты лежат под участниками, а участники строкой не названы",
		},
		{
			name:   "имя потеряно производителем",
			change: subjectchange.SubjectChange{ID: 2, Subject: "", Naming: authz.SubjectUnnameable},
			why:    "кого задело — неизвестно; это ровно тот дефект, который сплошной сброс прикрывал в kacho#1022",
		},
	}
}

// TestNonAddressableSubjectFlushesTheWholeCache — три вида строк, по имени
// которых задетых записей не найти, обязаны гасить кэш целиком.
func TestNonAddressableSubjectFlushesTheWholeCache(t *testing.T) {
	for _, row := range nonAddressableRows(t) {
		t.Run(row.name, func(t *testing.T) {
			flushes := 0
			poller := &scriptedPoller{batches: [][]subjectchange.SubjectChange{
				// Праймящий проход: курсор принимается, сброса нет.
				{{ID: 1, Subject: "user:usr00000000000000009", Naming: authz.SubjectNamed}},
				{row.change},
			}}
			w, err := subjectchange.New(subjectchange.Config{
				Poller: poller, Flush: func() { flushes++ }, Closer: &closerStub{},
				Interval: time.Second, StaleAfter: time.Minute, Logger: quietLogger(),
			})
			if err != nil {
				t.Fatalf("сборка читателя: %v", err)
			}
			w.Poll(context.Background()) // праймящий
			if flushes != 0 {
				t.Fatalf("праймящий проход сбросил кэш %d раз — сброса на нём быть не должно", flushes)
			}
			w.Poll(context.Background()) // разбираемая строка

			if flushes != 1 {
				t.Errorf("строка вида «%s» сбросила кэш %d раз, ожидался 1 сплошной сброс.\n"+
					"ПОЧЕМУ ЦЕЛИКОМ: %s.\n"+
					"Если сюда привело сужение сброса — оно отделяет не по тому признаку: "+
					"адресуемость субъекта не равна непустоте его имени. "+
					"Условия допустимого сужения — "+
					"gateway/docs/engineering/architecture/decision-cache-invalidation-radius.md",
					row.name, flushes, row.why)
			}
		})
	}
}

// TestEmptyBatchFlushesNothing — вторая сторона: счётчик умеет стоять на нуле.
//
// Без неё утверждение выше зеленело бы на устройстве, которое сбрасывает кэш
// всегда и по любому поводу, — то есть не различало бы «гасит, потому что
// обязано» и «гасит, потому что иначе не умеет».
func TestEmptyBatchFlushesNothing(t *testing.T) {
	flushes := 0
	poller := &scriptedPoller{batches: [][]subjectchange.SubjectChange{
		{{ID: 1, Subject: "user:usr00000000000000009", Naming: authz.SubjectNamed}},
		{}, // пустая порция: гасить нечего
	}}
	w, err := subjectchange.New(subjectchange.Config{
		Poller: poller, Flush: func() { flushes++ }, Closer: &closerStub{},
		Interval: time.Second, StaleAfter: time.Minute, Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("сборка читателя: %v", err)
	}
	w.Poll(context.Background())
	w.Poll(context.Background())

	if flushes != 0 {
		t.Errorf("пустая порция сбросила кэш %d раз — сброс без причины выселяет вердикты "+
			"всех арендаторов даром", flushes)
	}
}
