// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// password_hash_format_registry_injection_test.go — способность гейта
// `TestPasswordHashRegistryMatchesItsVerifiers` упасть и смолчать.
//
// Каждая сцена отличается от законного мира ОДНИМ фактом. Законный мир сам по
// себе — положительный контроль: на нём гейт молчит, и значит красное в сцене
// принадлежит внесённому факту, а не миру.
//
// Мир СИНТЕТИЧЕСКИЙ целиком — и корпус, и записи перечня, и объявление
// предмета. Подай сюда живые записи, и «законный мир молчит» краснело бы от
// каждой правки настоящего перечня: самопроверка зависела бы от содержимого
// того, что она проверяет.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const (
	phfRegistryRel = "internal/domain/password_hash_format.go"
	phfVerifierRel = "internal/passwordverify/verifier.go"
)

// phfLawfulCorpus — минимальное законное дерево той же ФОРМЫ, что настоящее:
// файл перечня, файл проверяющего с классификатором о двух ветвях и сосед,
// который не делает ни того, ни другого.
func phfLawfulCorpus() check.TreeCorpus {
	return check.TreeCorpus{
		phfRegistryRel: `package domain

type PasswordHashFormatRecord struct{ Format string }

var passwordHashFormats = []PasswordHashFormatRecord{{Format: "2a"}, {Format: "argon2id"}}
`,
		phfVerifierRel: `package passwordverify

import "strings"

const (
	bcryptMarkerPrefix   = "$2a$"
	argon2idMarkerPrefix = "$argon2id$"
)

type Declared struct{ Format string }

func inspectAndCompare(material, presented string, compare bool) int {
	switch {
	case strings.HasPrefix(material, bcryptMarkerPrefix):
		return compareBcrypt(material, presented, compare)
	case strings.HasPrefix(material, argon2idMarkerPrefix):
		return compareArgon2id(material, presented, compare)
	default:
		return 0
	}
}

func compareBcrypt(material, presented string, compare bool) int { return 1 }

func compareArgon2id(material, presented string, compare bool) int { return 2 }

// Настройка читается ВНЕ выбора и его ветвей — это законно: ею судят, что
// писать, а не как читать.
func meetsDeclared(d Declared) bool { return d.Format != "" }
`,
		"internal/dto/toproto/user.go": `package toproto

func noop() {}
`,
	}
}

// phfLawfulSpec — объявление предмета для синтетики.
func phfLawfulSpec() check.PasswordHashRegistrySpec {
	return check.PasswordHashRegistrySpec{
		RegistryRel:  phfRegistryRel,
		VerifierRel:  phfVerifierRel,
		SelectorFunc: "inspectAndCompare",
		SettingType:  "Declared",
		RecordType:   "PasswordHashFormatRecord",
		FloorReference: map[string]map[string]uint32{
			"argon2id": {"memory": 65536, "iterations": 3, "parallelism": 4},
		},
	}
}

// phfLawfulRecords — законный перечень: наследуемый формат только читаемый,
// объявленный записываемый, у каждого потолок внутри области допустимости, у
// записываемого пол с зазором и не ниже эталона.
func phfLawfulRecords() []check.PasswordHashRecordView {
	return []check.PasswordHashRecordView{
		{
			Format:   "2a",
			Writable: false,
			Params:   []string{"cost"},
			Ceiling:  map[string]uint32{"cost": 14},
			Floor:    map[string]uint32{},
			Range:    map[string][2]uint32{"cost": {4, 31}},
		},
		{
			Format:   "argon2id",
			Writable: true,
			Params:   []string{"memory", "iterations", "parallelism"},
			Ceiling:  map[string]uint32{"memory": 131072, "iterations": 10, "parallelism": 8},
			Floor:    map[string]uint32{"memory": 65536, "iterations": 3, "parallelism": 4},
			Range:    map[string][2]uint32{"memory": {8, 4294967295}, "iterations": {1, 4294967295}, "parallelism": {1, 255}},
		},
	}
}

func TestPasswordHashRegistryGate_LawfulWorldIsSilent(t *testing.T) {
	t.Parallel()

	findings, census, err := check.AuditPasswordHashFormatRegistry(
		phfLawfulCorpus(), phfLawfulRecords(), phfLawfulSpec())
	require.NoError(t, err)
	t.Log(census)
	require.Empty(t, findings, "законный мир обязан молчать — иначе красное в сценах ниже ничего не доказывает")
	require.Equal(t, 3, census.FilesRead)
	require.Equal(t, 2, census.Records)
	require.Equal(t, 1, census.Writable)
	require.Equal(t, 2, census.Branches, "ветвей классификатора обязано быть две — по числу форматов")
	require.Equal(t, 4, census.PairsChecked, "пар «запись × параметр»: одна у формата A, три у формата B")
}

func TestPasswordHashRegistryGate_Injection(t *testing.T) {
	t.Parallel()

	scenes := []struct {
		name        string
		corpus      func(check.TreeCorpus)
		records     func([]check.PasswordHashRecordView) []check.PasswordHashRecordView
		spec        func(*check.PasswordHashRegistrySpec)
		wantFinding string
		wantPremise string
	}{
		{
			name: "запись перечня осталась без проверяющего",
			corpus: func(c check.TreeCorpus) {
				c[phfVerifierRel] = strings.Replace(c[phfVerifierRel],
					`	case strings.HasPrefix(material, argon2idMarkerPrefix):
		return compareArgon2id(material, presented, compare)
`, "", 1)
			},
			wantFinding: `формат "argon2id" объявлен перечнем, а проверяющего у него в дереве нет`,
		},
		{
			name: "проверяющий читает признак вне перечня",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				return rs[:1]
			},
			wantFinding: `проверяющий читает признак "argon2id", которого в перечне нет`,
		},
		{
			name: "записываемых форматов ноль",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[1].Writable = false
				out[1].Floor = map[string]uint32{}
				return out
			},
			wantFinding: "записываемых форматов в перечне ноль",
		},
		{
			name: "пол выше потолка",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[1].Floor = map[string]uint32{"memory": 200000, "iterations": 3, "parallelism": 4}
				return out
			},
			wantFinding: `пол "memory" = 200000 выше потолка 131072`,
		},
		{
			name: "пол равен потолку по каждому параметру",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[1].Floor = map[string]uint32{"memory": 131072, "iterations": 10, "parallelism": 8}
				return out
			},
			wantFinding: "пол равен потолку по каждому параметру",
		},
		{
			name: "пол опущен ниже эталона нормы",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[1].Floor = map[string]uint32{"memory": 32768, "iterations": 3, "parallelism": 4}
				return out
			},
			wantFinding: `пол "memory" = 32768 ниже эталона 65536`,
		},
		{
			name: "у только читаемой записи объявлен пол",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[0].Floor = map[string]uint32{"cost": 10}
				return out
			},
			wantFinding: "у только читаемого формата объявлен пол",
		},
		{
			name: "потолок по параметру не задан",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[1].Ceiling = map[string]uint32{"memory": 131072, "iterations": 10}
				return out
			},
			wantFinding: `потолок по параметру "parallelism" не задан`,
		},
		{
			name: "потолок стоит на верхней границе допустимости",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[1].Ceiling = map[string]uint32{"memory": 131072, "iterations": 10, "parallelism": 255}
				return out
			},
			wantFinding: `потолок "parallelism" = 255 не ниже верхней границы допустимости 255`,
		},
		{
			name: "потолок ниже нижней границы допустимости",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[0].Ceiling = map[string]uint32{"cost": 2}
				return out
			},
			wantFinding: `потолок "cost" = 2 ниже нижней границы допустимости 4`,
		},
		{
			name: "выбор проверяющего читает настройку",
			corpus: func(c check.TreeCorpus) {
				c[phfVerifierRel] = strings.Replace(c[phfVerifierRel],
					"func inspectAndCompare(material, presented string, compare bool) int {",
					"func inspectAndCompare(material, presented string, compare bool) int {\n\tvar _ Declared", 1)
			},
			wantFinding: "читает тип настройки",
		},
		{
			name: "ветвь классификатора читает настройку",
			corpus: func(c check.TreeCorpus) {
				c[phfVerifierRel] = strings.Replace(c[phfVerifierRel],
					"func compareBcrypt(material, presented string, compare bool) int { return 1 }",
					"func compareBcrypt(material, presented string, compare bool) int {\n\tvar _ Declared\n\treturn 1\n}", 1)
			},
			wantFinding: "функция compareBcrypt читает тип настройки",
		},
		{
			name: "перечень объявлен вторым местом",
			corpus: func(c check.TreeCorpus) {
				c["internal/dto/toproto/user.go"] = `package toproto

type PasswordHashFormatRecord struct{ Format string }

var second = []PasswordHashFormatRecord{{Format: "2a"}}
`
			},
			wantFinding: "строится вне файла перечня",
		},
		{
			name:        "перечень пуст",
			records:     func([]check.PasswordHashRecordView) []check.PasswordHashRecordView { return nil },
			wantPremise: "перечень форматов пуст",
		},
		{
			name: "функции выбора в дереве нет",
			spec: func(s *check.PasswordHashRegistrySpec) {
				s.SelectorFunc = "такойФункцииНет"
			},
			wantPremise: "функции выбора",
		},
		{
			name: "файла проверяющего в корпусе нет",
			corpus: func(c check.TreeCorpus) {
				delete(c, phfVerifierRel)
			},
			wantPremise: "файла проверяющего",
		},

		// ── ЗАКОННЫЕ БЛИЗНЕЦЫ: каждый отличается от своей отрицательной сцены
		// одним фактом и обязан молчать.
		{
			name: "законный близнец: зазор пола и потолка по ОДНОМУ параметру",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[1].Floor = map[string]uint32{"memory": 65536, "iterations": 10, "parallelism": 8}
				return out
			},
		},
		{
			name: "законный близнец: потолок ровно на нижней границе допустимости",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[0].Ceiling = map[string]uint32{"cost": 4}
				return out
			},
		},
		{
			name: "законный близнец: потолок на единицу ниже верхней границы",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[1].Ceiling = map[string]uint32{"memory": 131072, "iterations": 10, "parallelism": 254}
				return out
			},
		},
		{
			name: "законный близнец: пол ВЫШЕ эталона",
			records: func(rs []check.PasswordHashRecordView) []check.PasswordHashRecordView {
				out := append([]check.PasswordHashRecordView{}, rs...)
				out[1].Floor = map[string]uint32{"memory": 98304, "iterations": 4, "parallelism": 4}
				return out
			},
		},
		{
			name: "законный близнец: настройку читает функция вне выбора и ветвей",
			corpus: func(c check.TreeCorpus) {
				c[phfVerifierRel] = strings.Replace(c[phfVerifierRel],
					"func meetsDeclared(d Declared) bool { return d.Format != \"\" }",
					"func meetsDeclared(d Declared) bool { return d.Format != \"\" }\n\nfunc alsoReads(d Declared) bool { return d.Format == \"argon2id\" }", 1)
			},
		},
		{
			name: "законный близнец: имя типа записи упомянуто в чужом файле без литерала",
			corpus: func(c check.TreeCorpus) {
				c["internal/dto/toproto/user.go"] = `package toproto

// PasswordHashFormatRecord назван в прозе, а не построен: это не второе объявление.
func noop() {}
`
			},
		},
	}

	for _, sc := range scenes {
		t.Run(sc.name, func(t *testing.T) {
			corpus := phfLawfulCorpus()
			if sc.corpus != nil {
				sc.corpus(corpus)
			}
			records := phfLawfulRecords()
			if sc.records != nil {
				records = sc.records(records)
			}
			spec := phfLawfulSpec()
			if sc.spec != nil {
				sc.spec(&spec)
			}

			findings, census, err := check.AuditPasswordHashFormatRegistry(corpus, records, spec)
			t.Log(census)
			t.Logf("находки: %q", findings)
			switch {
			case sc.wantPremise != "":
				require.Error(t, err, "премиса обязана отказать, а не смолчать")
				require.Contains(t, err.Error(), sc.wantPremise)
			case sc.wantFinding != "":
				require.NoError(t, err)
				require.NotEmpty(t, findings, "внесённый дефект обязан быть найден")
				require.Contains(t, strings.Join(findings, "\n"), sc.wantFinding,
					"находка обязана называть предмет и координату")
			default:
				require.NoError(t, err)
				require.Empty(t, findings, "законный близнец обязан молчать")
			}
		})
	}
}

// TestPasswordHashRegistryGate_EmptyCorpusIsNotClean — пустой обход не зелёный.
func TestPasswordHashRegistryGate_EmptyCorpusIsNotClean(t *testing.T) {
	t.Parallel()

	_, _, err := check.AuditPasswordHashFormatRegistry(check.TreeCorpus{}, phfLawfulRecords(), phfLawfulSpec())
	require.ErrorIs(t, err, check.ErrEmptyTraversal)
}
