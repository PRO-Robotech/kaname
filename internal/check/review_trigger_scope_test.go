// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// review_trigger_scope_test.go — ГЕЙТ: запрос в ветку линии (волны, эпика)
// идёт тем же конвейером, что запрос в ствол, а `push` судит только ствол
// (задача PRO-Robotech/kaname#394).
//
// Предмет и оси — в шапке `review_trigger_scope.go`; здесь они не
// пересказываются. Способность гейта упасть и смолчать доказана инъекцией
// настоящим входом — review_trigger_scope_injection_test.go.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestReviewIntoALineRunsTheTrunkPipeline — НЕСУЩЕЕ утверждение.
//
// Свойство принадлежит КОРПУСУ процессов: сужен был каждый из трёх, и снятие
// сужения в одном оставило бы запрос в линию без двух третей контекстов —
// заметить это по исправному файлу нельзя. Поэтому корпус выводится обходом
// каталога объявлений (тем же, что у гейта держателя ствола), а не выписывается.
func TestReviewIntoALineRunsTheTrunkPipeline(t *testing.T) {
	t.Parallel()

	corpus, _ := readTrunkCorpus(t)

	findings, census, err := check.AuditReviewTriggers(corpus)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: %s · находок %d", census, len(findings))

	// ПРЕДПОСЫЛКИ — своими утверждениями, а не одной строкой.
	//
	// Пола по числу процессов на запросе здесь нет: литерал «не меньше двух»
	// падения с трёх до двух не замечал. Выпадение процесса из запроса судит
	// ось 1 находкой по каждому процессу ствола; её предпосылка — процессы
	// ствола есть.
	if census.OnBranchPush == 0 {
		t.Fatal("процессов, идущих по push в ветки, ноль — требование «процесс ствола идёт на " +
			"запросе» сказано ни о чём")
	}
	if census.Conditions == 0 {
		t.Fatal("условий `if:` осмотрено ноль — разбор не дошёл до заданий, и молчание оси " +
			"«задание не различает базу» сказано ни о чём")
	}
	if census.ConditionLinks == 0 {
		t.Fatal("условия `if:` осмотрены, а звеньев в них прочитано ноль — разбор лексем слеп, " +
			"и молчание оси 4 сказано ни о чём")
	}
	if census.ReviewAtLine != census.OnReview {
		t.Errorf("с базами {%s} идут %d процессов из %d, идущих на запросе — запрос в "+
			"ветку-номер приходит без их контекстов",
			strings.Join(check.ReviewBaseBranches(), ", "), census.ReviewAtLine, census.OnReview)
	}

	for _, f := range findings {
		t.Error(f)
	}
}
