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
// Почему ведомость, а не правка записей тем же изменением: записи каталога
// правит другая полоса (PRO-Robotech/kaname#1051 — весь `docs/specs/reviews/`),
// и пять из двадцати входят в её набор; приведение записи к факту события —
// утверждение о санкции, которое сверяется с событием на трекере, а не с
// деревом. Подпорка держит рост класса и истекает сама.
//
// Предикат снятия (PRO-Robotech/kaname#302, п. 1): ведомость пуста, и
// `TestReviewRecordWithPerformedEventAssertsItsSanction` печатает «расхождений
// 0» при «в ведомости 0».
var reviewSanctionLedger = map[string]string{
	"docs/specs/reviews/access-beyond-login-needs-a-verified-address/2abf9de5cb3d904e84a4237f3c1b28556c2314db77c44c82a1b5fc60713d3ae9.yaml":                check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/access-beyond-login-needs-a-verified-address/60278225702d6174ea60abad5b473c60227415c6c63bd4245f36b078f4e54ccd.yaml":                check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/anonymous-and-authenticated-are-subject-classes/198db838d0a75b7f5b5bdbd5564bacec23a79cc00550a26e8830f3c6be61aac9.yaml":             check.ReviewSanctionIssuedFalse,
	"docs/specs/reviews/anonymous-and-authenticated-are-subject-classes/36066b6a19f44f2a0f52b55b6d0d7314c0a9133dca930e13d0a4ed0ddf2f905d.yaml":             check.ReviewSanctionIssuedFalse,
	"docs/specs/reviews/anonymous-and-authenticated-are-subject-classes/ae9ba373d26c8f4cc2a3c0036d04ff9e1a20b7cc0a8e43c1fca4690560427f51.yaml":             check.ReviewSanctionIssuedFalse,
	"docs/specs/reviews/assurance-level-is-declared-by-our-session/f3cbfaf5a8d5c3051d166eac4afbac5ac078dd178094726731041e7d3fdc3101.yaml":                  check.ReviewSanctionIssuedFalse,
	"docs/specs/reviews/cluster-admins-on-the-public-surface/5a86c0fabd1083a5df8eae11bccd14f1158411e9a2cdfec91376166e2962177c.yaml":                        check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/email-change-is-confirmed-from-the-new-address/92d7c35d30218e418221a052ca76c257f5c3c649de8337495bdf9941ab248613.yaml":              check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/email-change-is-confirmed-from-the-new-address/9dc900c9afa74f352b606e665344e8c57500438540b87f31c1a6790880cca1fa.yaml":              check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/expired-invitation-keeps-the-address-until-the-inviter-acts/826d25f5161aa06a156bac421af13148d545640ad8ac1e8de60da2d7b256e2c8.yaml": check.ReviewSanctionIssuedFalse,
	"docs/specs/reviews/level-two-is-enrolled-at-level-two/711609ce71653511ab0bc0ab511095148b1edbcfc5326258d47ae1c00f2adbd6.yaml":                          check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/module-manifest-revision-only-moves-forward/6339dc63581b67fe2ba326199328faba5cd7df31f1703c33a7e781c635c9d63d.yaml":                 check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/module-manifest-revision-only-moves-forward/75225f47856c2d04ac04b1f16658c152dcb2ca0519185889b101d69ec98537a2.yaml":                 check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/own-account-and-identity-are-removed-in-order/6d5b9ef672c041d613ebbad511b1b391f18a3542dfae9c478c74c6fa4d7ce754.yaml":               check.ReviewSanctionIssuedAbsent,
	"docs/specs/reviews/own-account-and-identity-are-removed-in-order/f10f3e8693f26763b1658b351c1fa3891922ae9b987e1a62f6c125bde05a31b4.yaml":               check.ReviewSanctionIssuedAbsent,
	"docs/specs/reviews/own-sessions-are-listed-and-ended-by-their-owner/63333cc2f8a0a99588f0f7c3cc01218e12fc6a11c553be0c9f81096a093e2878.yaml":            check.ReviewSanctionIssuedAbsent,
	"docs/specs/reviews/public-read-container-of-a-module-type-is-admitted/06b3ef605bc41112a6e88b987694450d07b2c80eb4bed5fc578891f95868c621.yaml":          check.ReviewSanctionIssuedFalse,
	"docs/specs/reviews/recovery-code-one-live-per-person/02ab12cd396c0e54db673e9e9f7d9a84b11c799335259dbd6975969a40a42136.yaml":                           check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/step-up-with-any-enrolled-method/35224856e3e2aec098ac0398deaeceb22dbb8cd4702232d921af62ea8168d683.yaml":                            check.ReviewSanctionBlockAbsent,
	"docs/specs/reviews/unverified-address-passes-to-the-mailbox-owner/b52c2960ce878b1d4ed755360a9167e00880d65180ce3f4cf0679c5da87076a5.yaml":              check.ReviewSanctionIssuedFalse,
}

// TestReviewRecordWithPerformedEventAssertsItsSanction — несущее утверждение:
// ни одна запись с санкционирующим вердиктом и исполненным событием не молчит
// о выданной санкции и не отрицает её.
func TestReviewRecordWithPerformedEventAssertsItsSanction(t *testing.T) {
	t.Parallel()
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
