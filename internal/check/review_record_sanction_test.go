// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// review_record_sanction_test.go — гейт записей ревью по дереву СВОЕГО модуля
// (предмет — годок `review_record_sanction.go`).
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// reviewSanctionLedger — расхождения, существующие в каталоге на день
// заведения гейта (kaname `092bee4fb`): путь записи → форма. Точным перечнем,
// а не потолком: запись ведомости, не встретившая своего расхождения той же
// формы, — находка, и снимается тем же изменением, что приводит запись к факту
// события. Новое расхождение вне ведомости краснит сразу.
//
// Исторические расхождения сверены с опубликованными событиями и сняты
// metadata-only коррекцией (PRO-Robotech/kaname#302).
//
// Предикат снятия (PRO-Robotech/kaname#302, п. 1): ведомость пуста, и
// `TestReviewRecordWithPerformedEventAssertsItsSanction` печатает «расхождений
// 0» при «в ведомости 0».
var reviewSanctionLedger = map[string]string{}

// TestReviewRecordWithPerformedEventAssertsItsSanction — несущее утверждение:
// ни одна запись с санкционирующим вердиктом и исполненным событием не молчит
// о выданной санкции и не отрицает её.
func TestReviewRecordWithPerformedEventAssertsItsSanction(t *testing.T) {
	t.Parallel()
	if len(reviewSanctionLedger) != 0 {
		t.Fatal("историческая ведомость снята: новые расхождения не допускают baseline")
	}
	root, prefix := platformtree.RequireCorpus(t)
	ownDir := root
	if prefix != "" {
		ownDir = root + "/" + prefix
	}

	findings, census, err := check.AuditReviewRecordSanction(ownDir, check.ReviewRecordsDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.Judged == 0 {
		t.Fatalf("ни одной записи с санкционирующим вердиктом и исполненным событием: ветвь "+
			"суждения не исполнялась, и молчание гейта ничего не означает (%s)", census)
	}

	matched := map[string]bool{}
	for _, f := range findings {
		if form, ok := reviewSanctionLedger[f.Record]; ok && form == f.Form {
			matched[f.Record] = true
			t.Logf("в ведомости: %s", f)
			continue
		}
		t.Error(f)
	}
	for rec, form := range reviewSanctionLedger {
		if !matched[rec] {
			t.Errorf("запись ведомости %s (%s) не встретила своего расхождения — оно снято либо "+
				"сменило форму; снимите запись ведомости тем же изменением", rec, form)
		}
	}
	t.Logf("перепись: %s · в ведомости %d", census, len(reviewSanctionLedger))
}
