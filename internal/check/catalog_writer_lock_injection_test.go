// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_writer_lock_injection_test.go — доказательство падучести
// ScanCatalogWriteLocking в обе стороны, на синтетических файлах. Не
// повторяет 1:1 объём монорепошной инъекции — покрывает те же оси на
// сокращённом наборе фикстур, время порта было ограничено (см. вердикт
// батча kacho#2597).
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func scanOnePkg(t *testing.T, files map[string]string) ([]check.CatalogWriteFinding, check.CatalogWriteCensus) {
	t.Helper()
	var src []check.CatalogSource
	for path, body := range files {
		src = append(src, check.CatalogSource{Path: path, Src: []byte(body)})
	}
	findings, census, err := check.ScanCatalogWriteLocking(src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	return findings, census
}

// TestCatalogWriterLockInjection_NoLockAtAll — писатель без единого взятия
// замка — находка «не берёт вовсе».
func TestCatalogWriterLockInjection_NoLockAtAll(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"pkg/writer.go": `package pkg

type writer struct{ tx Tx }

func (w writer) UpsertModule(m string) error {
	_, err := w.tx.Exec(` + "`INSERT INTO kaname.catalog_module (module) VALUES ($1) ON CONFLICT (module) DO UPDATE SET module=$1`" + `, m)
	return err
}
`,
	}
	findings, census := scanOnePkg(t, files)
	if census.Executed == 0 {
		t.Fatalf("КОНТРОЛЬ разбора: не увидел исполняемую запись: %+v", census)
	}
	if len(findings) != 1 {
		t.Fatalf("ИНЪЕКЦИЯ: ожидалась ровно одна находка, получено %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Why, "не берёт вовсе") {
		t.Errorf("текст находки не называет причину «не берёт вовсе»: %+v", findings[0])
	}
	if findings[0].Unit != "writer" {
		t.Errorf("единица суждения названа неверно: %+v", findings[0])
	}
}

// TestCatalogWriterLockInjection_SessionLock — сессионный замок — находка
// «сессионный», не молчание.
func TestCatalogWriterLockInjection_SessionLock(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"pkg/writer.go": `package pkg

type writer struct{ tx Tx }

func (w writer) Lock() error {
	_, err := w.tx.Exec(` + "`SELECT pg_advisory_lock(hashtext($1))`" + `, CatalogLockKey)
	return err
}

func (w writer) UpsertModule(m string) error {
	_, err := w.tx.Exec(` + "`INSERT INTO kaname.catalog_module (module) VALUES ($1)`" + `, m)
	return err
}

const CatalogLockKey = "kaname.module_catalog"
`,
	}
	findings, census := scanOnePkg(t, files)
	if census.LockSites == 0 {
		t.Fatalf("КОНТРОЛЬ разбора: не увидел взятие замка: %+v", census)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Why, "СЕССИОННЫЙ") {
		t.Fatalf("ИНЪЕКЦИЯ: ожидалась находка «сессионный замок», получено %+v", findings)
	}
}

// TestCatalogWriterLockInjection_WrongKey — транзакционный замок на ЧУЖОМ
// ключе — находка «чужой ключ», не молчание.
func TestCatalogWriterLockInjection_WrongKey(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"pkg/writer.go": `package pkg

type writer struct{ tx Tx }

func (w writer) Lock() error {
	_, err := w.tx.Exec(` + "`SELECT pg_advisory_xact_lock(hashtext($1))`" + `, "some.other.key")
	return err
}

func (w writer) UpsertModule(m string) error {
	_, err := w.tx.Exec(` + "`INSERT INTO kaname.catalog_module (module) VALUES ($1)`" + `, m)
	return err
}
`,
	}
	findings, _ := scanOnePkg(t, files)
	if len(findings) != 1 || !strings.Contains(findings[0].Why, "ЧУЖОМ ключе") {
		t.Fatalf("ИНЪЕКЦИЯ: ожидалась находка «чужой ключ», получено %+v", findings)
	}
}

// TestCatalogWriterLockInjection_LockedAcrossMethods — законный близнец:
// замок и запись — РАЗНЫЕ методы ОДНОГО получателя (как настоящий
// `catalogWriter`/`LockCatalog` в дереве службы) — молчание.
func TestCatalogWriterLockInjection_LockedAcrossMethods(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"pkg/lock.go": `package pkg

func (w writer) LockCatalog() error {
	_, err := w.tx.Exec(` + "`SELECT pg_advisory_xact_lock(hashtext($1))`" + `, CatalogLockKey)
	return err
}

const CatalogLockKey = "kaname.module_catalog"
`,
		"pkg/writer.go": `package pkg

type writer struct{ tx Tx }

func (w writer) UpsertModule(m string) error {
	_, err := w.tx.Exec(` + "`INSERT INTO kaname.catalog_module (module) VALUES ($1)`" + `, m)
	return err
}
`,
	}
	findings, census := scanOnePkg(t, files)
	if census.WriteUnits == 0 || census.LockedUnits == 0 {
		t.Fatalf("КОНТРОЛЬ разбора: единица не сошлась через методы: %+v", census)
	}
	if len(findings) != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: замок и запись — разные методы одного получателя "+
			"в разных файлах пакета, а гейт покраснел: %+v", findings)
	}
}

// TestCatalogWriterLockInjection_ProseIsNotExecution — законный близнец:
// текст, объясняющий сам запрет (та же форма оператора в комментарии/строке
// РАЗБОРА, не исполнения), не даёт находки — гейт судит ИСПОЛНЕНИЕ, а не
// подстроку.
func TestCatalogWriterLockInjection_ProseIsNotExecution(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"pkg/parser.go": `package pkg

// parseSeedBlock разбирает блок посева, содержащий INSERT INTO kaname.catalog_module (module) VALUES.
// Строка ниже НЕ исполняется — она передаётся функции разбора, не Exec.
func parseSeedBlock(body string) []string {
	stmt := ` + "`INSERT INTO kaname.catalog_module (module) VALUES ($1)`" + `
	return splitByComma(stmt)
}
`,
	}
	findings, census := scanOnePkg(t, files)
	if census.TextMatches == 0 {
		t.Fatalf("КОНТРОЛЬ: текстовый предикат обязан увидеть литерал: %+v", census)
	}
	if census.Executed != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: литерал передан функции РАЗБОРА (splitByComma — не "+
			"исполнитель), а гейт признал его исполняемым: %+v", census)
	}
	if len(findings) != 0 {
		t.Fatalf("гейт покраснел на неисполняемом литерале: %+v", findings)
	}
}

// TestCatalogWriterLockInjection_NamedConstant — оператор, вынесенный в
// константу и переданный по ИМЕНИ, распознаётся как исполняемый — находка.
func TestCatalogWriterLockInjection_NamedConstant(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"pkg/writer.go": `package pkg

const upsertModuleSQL = ` + "`INSERT INTO kaname.catalog_module (module) VALUES ($1)`" + `

type writer struct{ tx Tx }

func (w writer) UpsertModule(m string) error {
	_, err := w.tx.Exec(upsertModuleSQL, m)
	return err
}
`,
	}
	findings, census := scanOnePkg(t, files)
	if census.Executed == 0 {
		t.Fatalf("ИНЪЕКЦИЯ: оператор по имени константы не распознан как исполняемый: %+v", census)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась находка по именованной константе: %+v", findings)
	}
	if !strings.Contains(findings[0].What, "upsertModuleSQL") {
		t.Errorf("текст находки не называет имя константы: %+v", findings[0])
	}
}

// TestCatalogWriterLockInjection_ForwardedExecutor — исполнитель, ПЕРЕДАЮЩИЙ
// СВОЙ параметр в известный исполнитель пакета (transitive closure), тоже
// признаётся исполнителем — запись через него находится.
func TestCatalogWriterLockInjection_ForwardedExecutor(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"pkg/writer.go": `package pkg

type writer struct{ tx Tx }

func (w writer) run(q string) error {
	_, err := w.tx.Exec(q)
	return err
}

func (w writer) UpsertModule(m string) error {
	return w.run(` + "`INSERT INTO kaname.catalog_module (module) VALUES ($1)`" + `)
}
`,
	}
	findings, census := scanOnePkg(t, files)
	if census.Executors == 0 {
		t.Fatalf("КОНТРОЛЬ: `run` обязан быть опознан как исполнитель (форвардит q в Exec): %+v", census)
	}
	if len(findings) != 1 {
		t.Fatalf("ожидалась находка через транзитивного исполнителя `run`: %+v", findings)
	}
}
