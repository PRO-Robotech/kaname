// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// review_record_sanction_injection_test.go — доказательство способности гейта
// записей ревью (`review_record_sanction.go`) упасть и смолчать, на
// синтетическом доме записей во временном каталоге: своей рабочей копии и
// живых записей каталога проба не трогает.
//
// Каждая инъекция меняет РОВНО ОДИН факт против законного близнеца
// (`APPROVED` · `performed` · `issued: true`): иначе неизвестно, какой из
// изменённых фактов дал красное.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// sanctionRecord — текст синтетической записи; пустой блок — блока нет.
func sanctionRecord(verdict, eventBlock, eaBlock string) string {
	var b strings.Builder
	b.WriteString("schema_version: 1\nkind: acceptance_review\n")
	b.WriteString("subject:\n  repository: PRO-Robotech/kaname\n  path: docs/engineering/acceptance/live.md\n")
	b.WriteString("verdict: " + verdict + "\n")
	b.WriteString(eventBlock)
	b.WriteString(eaBlock)
	return b.String()
}

const (
	sanctionEventPerformed    = "event:\n  type: issue_comment\n  status: performed\n"
	sanctionEventNotPerformed = "event:\n  type: none\n  status: not_performed\n"
	sanctionIssuedTrue        = "effective_approval:\n  issued: true\n"
	sanctionIssuedFalse       = "effective_approval:\n  issued: false\n"
)

// synthReviewHome — дом записей с файлами rel → текст; возвращает корень.
func synthReviewHome(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(check.ReviewRecordsDir)), 0o755); err != nil {
		t.Fatal(err)
	}
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(check.ReviewRecordsDir), filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const sanctionRecordRel = "live/aaaa.yaml"

// TestReviewRecordSanctionInjection — законный близнец молчит, каждая форма
// неутверждённой санкции краснеет и называет запись и форму.
func TestReviewRecordSanctionInjection(t *testing.T) {
	t.Parallel()

	t.Run("законный близнец: APPROVED, performed, issued true — молчание", func(t *testing.T) {
		t.Parallel()
		root := synthReviewHome(t, map[string]string{
			sanctionRecordRel:      sanctionRecord("APPROVED", sanctionEventPerformed, sanctionIssuedTrue),
			"live/initial/aaaa.md": "не запись\n",
		})
		findings, census, err := check.AuditReviewRecordSanction(root, check.ReviewRecordsDir)
		if err != nil {
			t.Fatalf("БЛИЗНЕЦ: гейт не исполнился: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("БЛИЗНЕЦ: гейт покраснел на законной записи: %v", findings)
		}
		if census.RecordsRead != 1 || census.Judged != 1 || census.Issued != 1 || census.OtherFiles != 1 {
			t.Fatalf("БЛИЗНЕЦ: перепись не та (ждали записей 1, судимых 1, issued 1, прочих 1): %s", census)
		}
	})

	injections := []struct {
		name    string
		verdict string
		ea      string
		form    string
	}{
		{"issued: false", "APPROVED", sanctionIssuedFalse, check.ReviewSanctionIssuedFalse},
		{"issued: null", "APPROVED", "effective_approval:\n  issued: null\n", check.ReviewSanctionIssuedNull},
		{"поля issued нет", "APPROVED", "effective_approval:\n  ban1_lifted: false\n", check.ReviewSanctionIssuedAbsent},
		{"блока нет", "APPROVED", "", check.ReviewSanctionBlockAbsent},
		{"блок null", "APPROVED", "effective_approval: null\n", check.ReviewSanctionBlockAbsent},
		{"issued строкой", "APPROVED", "effective_approval:\n  issued: 'true'\n", check.ReviewSanctionIssuedNotBool},
		{"вторая форма санкционирующего вердикта: ACCEPT", "ACCEPT", sanctionIssuedFalse, check.ReviewSanctionIssuedFalse},
	}
	for _, in := range injections {
		t.Run("инъекция: "+in.name+" — находка", func(t *testing.T) {
			t.Parallel()
			root := synthReviewHome(t, map[string]string{
				sanctionRecordRel: sanctionRecord(in.verdict, sanctionEventPerformed, in.ea),
			})
			findings, census, err := check.AuditReviewRecordSanction(root, check.ReviewRecordsDir)
			if err != nil {
				t.Fatalf("ИНЪЕКЦИЯ: гейт не исполнился: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("ИНЪЕКЦИЯ: ожидалась ровно одна находка, получено %d: %v (%s)", len(findings), findings, census)
			}
			f := findings[0]
			if !strings.HasPrefix(f.Form, in.form) {
				t.Fatalf("ИНЪЕКЦИЯ: форма %q, ожидалась %q", f.Form, in.form)
			}
			msg := f.String()
			for _, want := range []string{check.ReviewRecordsDir + "/" + sanctionRecordRel, in.verdict, "performed", in.form} {
				if !strings.Contains(msg, want) {
					t.Fatalf("ИНЪЕКЦИЯ: текст находки не называет %q: %s", want, msg)
				}
			}
			if census.Judged != 1 || census.Issued != 0 || census.ByForm[f.Form] != 1 {
				t.Fatalf("ИНЪЕКЦИЯ: перепись не та: %s", census)
			}
		})
	}

	silent := []struct {
		name, verdict, event string
	}{
		{"вердикт без санкции при исполненном событии", "CHANGES_REQUESTED", sanctionEventPerformed},
		{"санкционирующий вердикт без исполненного события", "APPROVED", sanctionEventNotPerformed},
		{"санкционирующий вердикт без блока события", "APPROVED", ""},
	}
	for _, s := range silent {
		t.Run("близнец: "+s.name+", issued false — молчание", func(t *testing.T) {
			t.Parallel()
			root := synthReviewHome(t, map[string]string{
				sanctionRecordRel: sanctionRecord(s.verdict, s.event, sanctionIssuedFalse),
			})
			findings, census, err := check.AuditReviewRecordSanction(root, check.ReviewRecordsDir)
			if err != nil {
				t.Fatalf("БЛИЗНЕЦ: гейт не исполнился: %v", err)
			}
			if len(findings) != 0 || census.Judged != 0 || census.RecordsRead != 1 {
				t.Fatalf("БЛИЗНЕЦ: запись вне предмета судима: %v (%s)", findings, census)
			}
		})
	}

	t.Run("справочно: issued true без исполненного события считается, но не судится", func(t *testing.T) {
		t.Parallel()
		root := synthReviewHome(t, map[string]string{
			sanctionRecordRel: sanctionRecord("APPROVED", sanctionEventNotPerformed, sanctionIssuedTrue),
		})
		findings, census, err := check.AuditReviewRecordSanction(root, check.ReviewRecordsDir)
		if err != nil {
			t.Fatalf("гейт не исполнился: %v", err)
		}
		if len(findings) != 0 || census.IssuedWithoutEvent != 1 {
			t.Fatalf("справочная величина не та: %v (%s)", findings, census)
		}
	})

	refusals := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"пустой дом", map[string]string{}, "прочитано 0 записей"},
		{"дом без записей, только прочие файлы", map[string]string{"live/initial/a.md": "x\n"}, "прочитано 0 записей"},
		{"вердикт вне словаря", map[string]string{
			sanctionRecordRel: sanctionRecord("LGTM", sanctionEventPerformed, sanctionIssuedTrue),
		}, `вердикт "LGTM" вне закрытого словаря`},
		{"исход события вне словаря", map[string]string{
			sanctionRecordRel: sanctionRecord("APPROVED", "event:\n  status: done\n", sanctionIssuedTrue),
		}, `event.status "done" вне закрытого словаря`},
		{"вид записи вне словаря", map[string]string{
			sanctionRecordRel: strings.Replace(
				sanctionRecord("APPROVED", sanctionEventPerformed, sanctionIssuedTrue),
				"kind: acceptance_review", "kind: design_review", 1),
		}, `вид записи "design_review" вне словаря`},
		{"запись не разбирается", map[string]string{sanctionRecordRel: "verdict: [APPROVED\n"}, "не разбирается"},
	}
	for _, r := range refusals {
		t.Run("не выполнилось: "+r.name, func(t *testing.T) {
			t.Parallel()
			root := synthReviewHome(t, r.files)
			findings, census, err := check.AuditReviewRecordSanction(root, check.ReviewRecordsDir)
			if err == nil {
				t.Fatalf("ожидался отказ разбора, получено находок %d (%s)", len(findings), census)
			}
			if !strings.Contains(err.Error(), r.want) {
				t.Fatalf("отказ не называет %q: %v", r.want, err)
			}
		})
	}

	t.Run("не выполнилось: дома нет", func(t *testing.T) {
		t.Parallel()
		if _, _, err := check.AuditReviewRecordSanction(t.TempDir(), check.ReviewRecordsDir); err == nil ||
			!strings.Contains(err.Error(), "не прочитан") {
			t.Fatalf("ожидался отказ «дом не прочитан», получено %v", err)
		}
	})
}
