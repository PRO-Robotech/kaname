// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_gap_detection_injection_test.go — доказательство падучести
// на СВОЕЙ стороне шва (порт-зеркало одноимённой пробы репозитория платформы,
// снят там вынесением службы доступа — `kacho#2597`).
//
// Инъекция подаёт синтетический вход через анализатор `auditSubjectChangeGapDetection`
// напрямую — настоящее дерево kaname править нельзя, а гейт, который нельзя
// уронить нарочно, не отличается от гейта, который не может упасть вовсе.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// subjectChangeFixture — синтетическое дерево из одного файла с заданным
// телом; возвращает список файлов и корень для аудитора.
func subjectChangeFixture(t *testing.T, rel, body string) ([]string, string) {
	t.Helper()
	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("подготовить каталог: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("записать %s: %v", full, err)
	}
	return []string{full}, root
}

// subjectChangeGoodSrc — форма, действительно стоящая в дереве kaname
// (`internal/repo/kaname/pg/subject_change_repo.go`): окно читается, пол
// спрашивается ПОСЛЕ страницы (страница текстуально выше пола).
const subjectChangeGoodSrc = `package pg

func (r *subjectChangeRepo) ListSince(ctx context.Context, since, settled int64) error {
	rows, err := r.pool.Query(ctx, ` + "`SELECT id FROM kaname.subject_change_outbox WHERE id > $1 AND id <= $2`" + `, since, settled)
	_ = rows
	if err != nil {
		return err
	}
	floor, ferr := r.settled.ObserveFloor(ctx, r.pool, true)
	_ = floor
	return ferr
}
`

// subjectChangeNoFloorSrc — законный по форме окна, но пол не спрашивается
// вовсе.
const subjectChangeNoFloorSrc = `package pg

func (r *subjectChangeRepo) ListSince(ctx context.Context, since, settled int64) error {
	rows, err := r.pool.Query(ctx, ` + "`SELECT id FROM kaname.subject_change_outbox WHERE id > $1 AND id <= $2`" + `, since, settled)
	_ = rows
	return err
}
`

// subjectChangeFloorBeforeWindowSrc — ИНЪЕКЦИЯ ПРОВЕРЯЕМОГО: пол берётся
// текстуально РАНЬШЕ страницы — тот самый порядок, который software
// check-then-act и который дал молчаливый пропуск на реальном прогоне.
const subjectChangeFloorBeforeWindowSrc = `package pg

func (r *subjectChangeRepo) ListSince(ctx context.Context, since, settled int64) error {
	floor, ferr := r.settled.ObserveFloor(ctx, r.pool, true)
	_ = floor
	if ferr != nil {
		return ferr
	}
	rows, err := r.pool.Query(ctx, ` + "`SELECT id FROM kaname.subject_change_outbox WHERE id > $1 AND id <= $2`" + `, since, settled)
	_ = rows
	return err
}
`

// subjectChangeProducerSrc — форма, действительно стоящая в дереве kaname
// (`internal/apps/kaname/api/internal_iam/handler.go`).
const subjectChangeProducerSrc = `package internal_iam

func (h *Handler) PollSubjectChanges(ctx context.Context, req *Req) (*Resp, error) {
	if lost.EarliestResumable != 0 {
		return nil, subjectchange.PositionLost(lost.EarliestResumable)
	}
	return &Resp{}, nil
}
`

// subjectChangeTokenDupSrc — раздублированный признак полосы: строка вместо
// ссылки на константу продукта.
const subjectChangeTokenDupSrc = `package pg

const localReason = "SUBJECT_CHANGE_POSITION_LOST"
`

// TestSubjectChangeGap_ControlSeesTheRealFormAsClean — КОНТРОЛЬ.
func TestSubjectChangeGap_ControlSeesTheRealFormAsClean(t *testing.T) {
	t.Parallel()
	files, root := subjectChangeFixture(t, "internal/repo/kaname/pg/subject_change_repo.go", subjectChangeGoodSrc)
	findings, census, err := auditSubjectChangeGapDetection(files, root)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(census.Windows) != 1 || len(census.WindowsAskFloor) != 1 {
		t.Fatalf("окно не распознано как спрашивающее пол: %+v", census)
	}
	if len(findings) != 0 {
		t.Fatalf("КОНТРОЛЬ: настоящая форма объявлена находкой: %v", findings)
	}
}

// TestSubjectChangeGap_RedWhenWindowAsksNoFloor — ИНЪЕКЦИЯ: окно есть, пол не
// спрашивается вовсе.
func TestSubjectChangeGap_RedWhenWindowAsksNoFloor(t *testing.T) {
	t.Parallel()
	files, root := subjectChangeFixture(t, "internal/repo/kaname/pg/subject_change_repo.go", subjectChangeNoFloorSrc)
	findings, census, err := auditSubjectChangeGapDetection(files, root)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(census.Windows) != 1 {
		t.Fatalf("окно не распознано: %+v", census)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка (окно без пола), получено %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].What, floorSelector) {
		t.Errorf("находка не называет недостающий вызов %s: %q", floorSelector, findings[0].What)
	}
}

// TestSubjectChangeGap_RedWhenFloorPrecedesTheWindow — ИНЪЕКЦИЯ: пол берётся
// раньше страницы (порядок, а не присутствие).
func TestSubjectChangeGap_RedWhenFloorPrecedesTheWindow(t *testing.T) {
	t.Parallel()
	files, root := subjectChangeFixture(t, "internal/repo/kaname/pg/subject_change_repo.go", subjectChangeFloorBeforeWindowSrc)
	findings, census, err := auditSubjectChangeGapDetection(files, root)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(census.Windows) != 1 {
		t.Fatalf("окно не распознано: %+v", census)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась 1 находка (порядок), получено %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].What, "РАНЬШЕ страницы") {
		t.Errorf("находка не называет нарушение порядка: %q", findings[0].What)
	}
}

// TestSubjectChangeGap_RedWhenNoProducerAtAll — ИНЪЕКЦИЯ: окно с полом есть, а
// производителя отказа в дереве нет вовсе.
func TestSubjectChangeGap_RedWhenNoProducerAtAll(t *testing.T) {
	t.Parallel()
	files, root := subjectChangeFixture(t, "internal/repo/kaname/pg/subject_change_repo.go", subjectChangeGoodSrc)
	// subjectChangeGoodSrc не производит отказ — только читает окно.
	_, census, err := auditSubjectChangeGapDetection(files, root)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(census.Producers) != 0 {
		t.Fatalf("контроль сломан: производитель найден там, где его нет: %v", census.Producers)
	}
}

// TestSubjectChangeGap_ProducerFoundInItsOwnForm — ЗАКОННЫЙ БЛИЗНЕЦ: форма
// производителя (`internal_iam/handler.go`) даёт РОВНО одного производителя.
func TestSubjectChangeGap_ProducerFoundInItsOwnForm(t *testing.T) {
	t.Parallel()
	files, root := subjectChangeFixture(t, "internal/apps/kaname/api/internal_iam/handler.go", subjectChangeProducerSrc)
	_, census, err := auditSubjectChangeGapDetection(files, root)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(census.Producers) != 1 {
		t.Fatalf("производитель формы продукта не распознан: %+v", census)
	}
}

// TestSubjectChangeGap_RedOnTokenDuplicate — ИНЪЕКЦИЯ: признак полосы
// раздублирован строковым литералом.
func TestSubjectChangeGap_RedOnTokenDuplicate(t *testing.T) {
	t.Parallel()
	files, root := subjectChangeFixture(t, "internal/repo/kaname/pg/const_leak.go", subjectChangeTokenDupSrc)
	_, census, err := auditSubjectChangeGapDetection(files, root)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(census.TokenDuplicates) != 1 {
		t.Fatalf("дублирующий литерал не распознан: %+v", census)
	}
}

// TestSubjectChangeGap_SilentOnItsOwnExplanation — ЗАКОННЫЙ БЛИЗНЕЦ: слово
// `subject_change_outbox` и порядок пола/страницы в КОММЕНТАРИИ, объясняющем
// эту же проверку, не являются ни окном, ни оператором.
func TestSubjectChangeGap_SilentOnItsOwnExplanation(t *testing.T) {
	t.Parallel()
	src := `package pg

// Читаем kaname.subject_change_outbox окном id > since AND id <= settled,
// и пол ObserveFloor обязан браться не раньше страницы.
func explain() {}
`
	files, root := subjectChangeFixture(t, "internal/repo/kaname/pg/doc.go", src)
	findings, census, err := auditSubjectChangeGapDetection(files, root)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if len(census.Windows) != 0 {
		t.Errorf("комментарий распознан как окно чтения: %+v", census)
	}
	if len(findings) != 0 {
		t.Errorf("гейт краснеет на КОММЕНТАРИИ, объясняющем проверку: %v", findings)
	}
}
