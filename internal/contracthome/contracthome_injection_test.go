// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// contracthome_injection_test.go — доказательство того, что три гейта дома
// контрактов СПОСОБНЫ упасть, и того, что они молчат на законном близнеце.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СИНТЕТИЧЕСКИЙ КОРЕНЬ, А НЕ ПРАВКА ДЕРЕВА
//
// Все три проверки читают дерево службы. Внести в него дефект ради
// доказательства значило бы править общее состояние, которое читают соседние
// сессии. Поэтому разбор вынесен в чистые функции над ПРОИЗВОЛЬНЫМ корнем, а
// сюда подаётся корень, собранный в каталоге прогона.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАЖДАЯ ИНЪЕКЦИЯ МЕНЯЕТ РОВНО ОДИН ФАКТ ПРОТИВ КОНТРОЛЯ
//
// Контроль («дерево цело — молчат все три») стоит первым: без него красное
// могло бы приходить от соседней оси, а новая проверка осталась бы вакуумной,
// не показав этого ничем.
package contracthome

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// ── Состав законного близнеца ───────────────────────────────────────────────

// soundOwnContract — контракт службы. Несёт ДВЕ ловушки для разбора текстом:
// путь чужого контракта в комментарии и точку с запятой ВНУТРИ строкового
// значения опции. Оператором ни то, ни другое не является, и гейт обязан
// молчать — иначе он краснел бы на собственном объяснении.
const soundOwnContract = `syntax = "proto3";

package kaname.cloud.iam.v1;

// Здесь НЕ оператор, а объяснение: import "kacho/cloud/operation/operation.proto";
import "corelib/authz/v1/authz_options.proto";
import "google/protobuf/timestamp.proto";

option go_package = "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1;iamv1";

message Account {
  string id = 1;
  // Точка с запятой внутри строки оператор не заканчивает.
  string note = 2 [(corelib.authz.v1.hint) = "id; then name"];
}
`

// soundInputContract — входной контракт: лежит в дереве потому, что его
// резолвит оператор соседа, заглушки публикует его собственный модуль.
const soundInputContract = `syntax = "proto3";

package corelib.authz.v1;

option go_package = "github.com/PRO-Robotech/corelib/api/corelib/authz/v1;authzv1";
`

// soundBufGen — объявление генерации: назван РОВНО собственный корень службы.
const soundBufGen = `version: v2
plugins:
  - local: [go, run, google.golang.org/protobuf/cmd/protoc-gen-go]
    out: ../pkg/api
    opt: paths=source_relative
inputs:
  - directory: .
    paths:
      - kaname
`

// soundStub — файл под каталогом заглушек: корень собственный.
const soundStub = "package iamv1\n"

// soundLedger — годная ведомость входов: один вход, его отпечаток и дом его
// заглушек.
func soundLedger(sha string) string {
	return fmt.Sprintf(`source:
  repo: PRO-Robotech/kacho
  revision: 96c5c6e10b995f09f4fe4bfa396fccdd414fbb4e
inputs:
  - path: corelib/authz/v1/authz_options.proto
    sha256: %s
    stubs: github.com/PRO-Robotech/corelib/api/corelib/authz/v1
`, sha)
}

// contractHomeRoot — годный корень службы. Всякая проба ниже строит СВОЙ корень
// этой функцией и меняет ровно один названный факт.
type contractHomeRoot struct {
	OwnContract   string // proto/kaname/cloud/iam/v1/account.proto
	InputContract string // proto/corelib/authz/v1/authz_options.proto; "" — файла нет
	OrphanInput   string // proto/kacho/cloud/operation/operation.proto; "" — файла нет
	BufGen        string // proto/buf.gen.yaml; "" — файла нет
	ForeignStub   string // pkg/api/corelib/authz/v1/authz_options.pb.go; "" — файла нет

	// Ledger — proto/inputs.yaml. Пусто означает НЕ «файла нет», а «собери
	// годную ведомость по фактическому содержимому входа»: отпечаток в контроле
	// обязан быть посчитан, а не выписан, иначе контроль зеленел бы на
	// совпадении двух одинаково неверных чисел.
	Ledger string
	// NoLedger — ведомости нет вовсе.
	NoLedger bool
}

func soundRoot() contractHomeRoot {
	return contractHomeRoot{
		OwnContract:   soundOwnContract,
		InputContract: soundInputContract,
		BufGen:        soundBufGen,
	}
}

func (r contractHomeRoot) build(t *testing.T) *treecorpus.Tree {
	t.Helper()
	root := t.TempDir()

	write := func(rel, body string) {
		if body == "" {
			return
		}
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o600))
	}

	write("proto/kaname/cloud/iam/v1/account.proto", r.OwnContract)
	write("proto/corelib/authz/v1/authz_options.proto", r.InputContract)
	write("proto/kacho/cloud/operation/operation.proto", r.OrphanInput)
	write("proto/buf.gen.yaml", r.BufGen)
	if !r.NoLedger {
		ledger := r.Ledger
		if ledger == "" {
			sum := sha256.Sum256([]byte(r.InputContract))
			ledger = soundLedger(hex.EncodeToString(sum[:]))
		}
		write("proto/inputs.yaml", ledger)
	}
	write("pkg/api/kaname/cloud/iam/v1/account.pb.go", soundStub)
	write("pkg/api/corelib/authz/v1/authz_options.pb.go", r.ForeignStub)

	// Индекса у синтетического корня нет BY CONSTRUCTION (это каталог прогона,
	// а не репозиторий), поэтому обход диска здесь — единственный возможный
	// авторитет, и выбран он ЯВНО: настоящее дерево берёт состав у индекса, и
	// подмена одного другим была бы невидима.
	tree, err := treecorpus.SyntheticTree(root)
	require.NoError(t, err, "состав синтетического корня не собран — инъекция беспредметна")
	return tree
}

// ── Контроль: годный корень молчит у ВСЕХ ТРЁХ ──────────────────────────────

func TestInjectionControl_SoundRootIsSilentInAllThreeGates(t *testing.T) {
	t.Parallel()
	tree := soundRoot().build(t)

	ccensus, cfindings, cerr := scanContractClosure(tree)
	require.NoError(t, cerr)
	require.Empty(t, cfindings, "годное дерево контрактов объявлено нарушением: %s", ccensus)
	require.Equal(t, 2, ccensus.ProtoFiles, "контроль беспредметен: контрактов прочитано не два")
	require.Equal(t, 1, ccensus.OwnFiles)
	require.Equal(t, 1, ccensus.InputFiles)
	require.Equal(t, 2, ccensus.Imports, "оператор в комментарии зачтён импортом — разбор идёт текстом")
	require.Equal(t, 1, ccensus.WellKnown)
	require.Equal(t, 1, ccensus.ResolvedInTree)

	gcensus, gfindings, gerr := scanGenerationRoots(tree)
	require.NoError(t, gerr)
	require.Empty(t, gfindings, "годное объявление генерации объявлено нарушением: %s", gcensus)
	require.Equal(t, []string{"kaname"}, gcensus.GenerationPaths)
	require.Equal(t, []string{"kaname"}, gcensus.StubRoots)

	lcensus, lfindings, lerr := scanInputLedger(tree)
	require.NoError(t, lerr)
	require.Empty(t, lfindings, "годная ведомость входов объявлена нарушением: %s", lcensus)
	require.Equal(t, 1, lcensus.Entries)
	require.Equal(t, 1, lcensus.Hashed, "контроль беспредметен: отпечатков не пересчитано")
	require.Equal(t, 1, lcensus.TreeFiles)
}

// ── Ось 4: ведомость входных контрактов ─────────────────────────────────────

func TestInjection_EditedInputContractIsFound(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	// РОВНО ОДИН факт: копия входа правлена здесь, ведомость осталась прежней.
	sum := sha256.Sum256([]byte(soundInputContract))
	r.Ledger = soundLedger(hex.EncodeToString(sum[:]))
	r.InputContract = soundInputContract + "\n// правка, которой в источнике нет\n"
	_, findings, err := scanInputLedger(r.build(t))
	require.NoError(t, err)
	require.Len(t, findings, 1, "правка копии входного контракта не найдена")
	require.Equal(t, ledgerGroundDrift, findings[0].Ground)
}

func TestInjection_LedgerEntryWithoutAFileIsFound(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	// РОВНО ОДИН факт: ведомость называет вход, которого в дереве нет.
	r.Ledger = soundLedger("0000000000000000000000000000000000000000000000000000000000000000") +
		`  - path: corelib/api/v1/operation.proto
    sha256: 1111111111111111111111111111111111111111111111111111111111111111
    stubs: github.com/PRO-Robotech/corelib/api/corelib/api/v1
`
	_, findings, err := scanInputLedger(r.build(t))
	require.NoError(t, err)
	grounds := map[string]int{}
	for _, f := range findings {
		grounds[f.Ground]++
	}
	require.Equal(t, 1, grounds[ledgerGroundMissingFile], "запись без предмета не найдена")
}

func TestInjection_InputContractOutsideTheLedgerIsFound(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	// РОВНО ОДИН факт: в дереве завёлся вход, которого в ведомости нет.
	r.OwnContract = soundOwnContract +
		"\n// второй оператор ниже\nimport \"kacho/cloud/operation/operation.proto\";\n"
	r.OrphanInput = "syntax = \"proto3\";\n\npackage kacho.cloud.operation;\n"
	_, findings, err := scanInputLedger(r.build(t))
	require.NoError(t, err)
	require.Len(t, findings, 1, "вход мимо ведомости не найден")
	require.Equal(t, ledgerGroundUnledgered, findings[0].Ground)
	require.Equal(t, "kacho/cloud/operation/operation.proto", findings[0].Path)
}

func TestInjection_MissingLedgerIsNotSilence(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	r.NoLedger = true // РОВНО ОДИН факт: ведомости нет
	_, _, err := scanInputLedger(r.build(t))
	require.Error(t, err, "отсутствие ведомости принято за «расхождений нет»: это ТРЕТИЙ исход")
}

// ── Ось 1: замкнутость графа контрактов ─────────────────────────────────────

func TestInjection_ImportWithoutAFileInTheTreeIsFound(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	r.InputContract = "" // РОВНО ОДИН факт: импортируемого файла в дереве нет
	_, findings, err := scanContractClosure(r.build(t))
	require.NoError(t, err)
	require.Len(t, findings, 1, "импорт без файла в дереве не найден: посторонний, "+
		"клонировавший один этот репозиторий, контракты не соберёт")
	require.Equal(t, closureGroundMissing, findings[0].Ground)
	require.Equal(t, "corelib/authz/v1/authz_options.proto", findings[0].Path)
}

func TestInjection_InputContractWithoutAConsumerIsFound(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	// РОВНО ОДИН факт: в дереве появился входной контракт, которого не
	// импортирует ни один контракт службы.
	r.OrphanInput = "syntax = \"proto3\";\n\npackage kacho.cloud.operation;\n"
	_, findings, err := scanContractClosure(r.build(t))
	require.NoError(t, err)
	require.Len(t, findings, 1, "копия чужого контракта без потребителя не найдена")
	require.Equal(t, closureGroundOrphan, findings[0].Ground)
}

func TestInjection_OperatorInACommentIsNotAnImport(t *testing.T) {
	t.Parallel()
	// Законный близнец предыдущей пробы: файл чужого контракта в дереве ЕСТЬ и
	// назван он только КОММЕНТАРИЕМ соседа. Если разбор считал бы подстроку,
	// находки не было бы — и проба выше зеленела бы, не измеряя ничего.
	r := soundRoot()
	r.OrphanInput = "syntax = \"proto3\";\n\npackage kacho.cloud.operation;\n"
	census, findings, err := scanContractClosure(r.build(t))
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, closureGroundOrphan, findings[0].Ground,
		"путь из комментария зачтён импортом: тогда находка была бы другой, а разбор — текстовым")
	require.Equal(t, 2, census.Imports, "операторов импорта по-прежнему два, третий стоит в комментарии")
}

// ── Ось 3: входы генерации ──────────────────────────────────────────────────

func TestInjection_ForeignRootNamedInGenerationIsFound(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	// РОВНО ОДИН факт: во входах назван корень фундамента.
	r.BufGen = soundBufGen + "      - corelib\n"
	_, findings, err := scanGenerationRoots(r.build(t))
	require.NoError(t, err)
	require.Len(t, findings, 1, "чужой корень во входах генерации не найден: "+
		"его заглушки будут порождены вторично, и двоичное паникует в инициализации")
	require.Equal(t, generationGroundForeignRoot, findings[0].Ground)
	require.Equal(t, "corelib", findings[0].Root)
}

func TestInjection_OwnRootAbsentFromGenerationIsFound(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	// РОВНО ОДИН факт: собственный корень во входах не назван.
	r.BufGen = `version: v2
plugins:
  - local: [go, run, google.golang.org/protobuf/cmd/protoc-gen-go]
    out: ../pkg/api
    opt: paths=source_relative
inputs:
  - directory: .
    paths:
      - corelib
`
	_, findings, err := scanGenerationRoots(r.build(t))
	require.NoError(t, err)
	require.Len(t, findings, 2, "ожидались обе находки: чужой корень назван, свой — нет")
	grounds := []string{findings[0].Ground, findings[1].Ground}
	require.Contains(t, grounds, generationGroundOwnRootAbsent)
	require.Contains(t, grounds, generationGroundForeignRoot)
}

func TestInjection_ForeignStubAlreadyInTheTreeIsFound(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	// РОВНО ОДИН факт: заглушка чужого контракта уже лежит под каталогом
	// заглушек, а объявление генерации об этом молчит.
	r.ForeignStub = "package authzv1\n"
	census, findings, err := scanGenerationRoots(r.build(t))
	require.NoError(t, err)
	require.Len(t, findings, 1, "вторично порождённая заглушка фундамента не найдена")
	require.Equal(t, generationGroundForeignStub, findings[0].Ground)
	require.Equal(t, []string{"kaname"}, census.GenerationPaths,
		"инъекция сдвинула объявление: она меняет больше одного факта")
}

func TestInjection_MissingGenerationDeclarationIsNotSilence(t *testing.T) {
	t.Parallel()
	r := soundRoot()
	r.BufGen = "" // РОВНО ОДИН факт: объявления генерации нет
	_, _, err := scanGenerationRoots(r.build(t))
	require.Error(t, err, "отсутствие объявления генерации принято за «лишнего не порождаем»: "+
		"это ТРЕТИЙ исход — проверка не исполнялась, — и он не вычитается из вердикта")
}
