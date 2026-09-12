// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_admission_calls_test.go — допуск однократности обращается к базе
// РОВНО ОДИН раз (приёмка F2, сценарий F2-28). Порт с монорепо, см. годок
// `assertion_admission_calls.go`.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// assertionAdmissionFile — файл владельца хранилища однократности, ОТ
	// КОРНЯ своего модуля (было `services/iam/internal/repo/kaname/pg/...`).
	assertionAdmissionFile = "internal/repo/kaname/pg/client_assertion_replay_repo.go"
	// assertionAdmissionFunc — функция ДОПУСКА.
	assertionAdmissionFunc = "ClientAssertionReplayRepo.Redeem"
	// assertionReaperFunc — законный близнец: сборщик.
	assertionReaperFunc = "ClientAssertionReplayRepo.Reap"
	// assertionAdmissionCallBudget — сколько обращений к базе допуску положено.
	assertionAdmissionCallBudget = 1
)

// TestAssertionAdmissionIsASingleDatabaseCall — сам гейт. Имя сохранено
// дословно из монорепо; на него уже ссылается прод-комментарий
// `client_assertion_replay_repo.go`.
func TestAssertionAdmissionIsASingleDatabaseCall(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}
	full := filepath.Join(root, filepath.FromSlash(assertionAdmissionFile))

	src, err := os.ReadFile(full) // #nosec G304 -- путь-константа своего дерева
	if err != nil {
		t.Fatalf("файла владельца однократности (%s) НЕТ: %v. Либо хранилище снято — "+
			"тогда снимается и этот гейт вместе с ним, — либо оно переехало, и гейт "+
			"стережёт координату, которой больше не существует.", assertionAdmissionFile, err)
	}
	byFunc, census, err := check.ScanDatabaseCallsByFunction(assertionAdmissionFile, src)
	if err != nil {
		t.Fatalf("разбор %s: %v", assertionAdmissionFile, err)
	}

	t.Logf("перепись: файл %s, объявлений структур %d, полей-носителей соединения %d (%s), "+
		"функций осмотрено %d, вызовов осмотрено %d, из них обращений к базе %d",
		assertionAdmissionFile, census.Structs, len(census.Handles),
		strings.Join(census.Handles, ", "), census.Functions, census.Calls, census.DBCalls)

	if len(census.Handles) == 0 {
		t.Fatalf("в %s не опознано ни одного поля-носителя соединения — признак «обращение "+
			"к базе» не производится, поэтому ноль обращений сказано ни о чём", assertionAdmissionFile)
	}
	if census.DBCalls == 0 {
		t.Fatalf("в %s осмотрено %d вызовов и признано обращениями к базе НОЛЬ — хранилище "+
			"перестало ходить в базу либо разбор перестал видеть предмет",
			assertionAdmissionFile, census.Calls)
	}

	admission, ok := byFunc[assertionAdmissionFunc]
	if !ok {
		t.Fatalf("функция допуска %s в %s не найдена; разобраны: %v",
			assertionAdmissionFunc, assertionAdmissionFile, check.SortedFuncNames(byFunc))
	}
	reaper, ok := byFunc[assertionReaperFunc]
	if !ok {
		t.Fatalf("сборщик %s в %s не найден; разобраны: %v",
			assertionReaperFunc, assertionAdmissionFile, check.SortedFuncNames(byFunc))
	}

	if len(admission.Calls) != assertionAdmissionCallBudget {
		var where []string
		for _, c := range admission.Calls {
			where = append(where, fmt.Sprintf("%s:%d  %s через %s", c.File, c.Line, c.Verb, c.Handle))
		}
		t.Fatalf("допуск однократности (%s:%d) обращается к базе %d раз(а) при бюджете %d:\n  %s\n\n"+
			"Допуск обязан быть ОДНИМ оператором: «не предъявлялось ли уже» и «погасить» "+
			"неделимы, и неделимыми их делает первичный ключ таблицы.",
			admission.Name, admission.Line, len(admission.Calls), assertionAdmissionCallBudget,
			strings.Join(where, "\n  "))
	}

	t.Logf("допуск %s:%d — обращений к базе %d (бюджет %d)",
		assertionAdmissionFile, admission.Line, len(admission.Calls), assertionAdmissionCallBudget)
	t.Logf("законный близнец %s:%d — обращений к базе %d, число ему НЕ предписано",
		assertionAdmissionFile, reaper.Line, len(reaper.Calls))
}
