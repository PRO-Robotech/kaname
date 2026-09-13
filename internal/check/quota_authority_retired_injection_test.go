// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// quota_authority_retired_injection_test.go — доказательство способности
// TestLimitAuthorityIsGoneFromTheTree упасть и смолчать.
//
// Обе стороны гоняют ТУ ЖЕ функцию, что и гейт по дереву
// (`check.JudgeAuthorityResidue`), на синтетическом корпусе: рабочей копии
// инъекция не касается.
//
// У КАЖДОЙ оси свой законный близнец, и миры различаются ОДНИМ фактом. Без
// второй половины «находок нет» было бы неотличимо от «ось не смотрит», а
// именно это и есть главный способ, которым проверка на ОТСУТСТВИЕ умирает
// молча.
//
// Близнец оси контракта выбран не произвольно: `int32 limit = 2` — поле размера
// страницы, ровно то, из-за чего прежнее условие снятия было недостижимо
// by construction (`kacho#2457`). Ось обязана на нём молчать, иначе она
// унаследовала бы тот же дефект.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// authorityResidueAxes — перепись самой инъекции: по какой оси прогнана какая
// сторона. Печатается в конце, чтобы «утверждений N» было видно числом, а не
// на слово.
type authorityResidueAxes struct {
	defect map[string]bool
	twin   map[string]bool
}

func newAuthorityResidueAxes() *authorityResidueAxes {
	return &authorityResidueAxes{defect: map[string]bool{}, twin: map[string]bool{}}
}

// findingOnAxis — есть ли среди находок хоть одна по названной оси.
func findingOnAxis(findings []check.AuthorityResidueFinding, axis string) (check.AuthorityResidueFinding, bool) {
	for _, f := range findings {
		if f.Axis == axis {
			return f, true
		}
	}
	return check.AuthorityResidueFinding{}, false
}

// TestAuthorityResidueGateCanFail — сторона ДЕФЕКТА по каждой оси: внесённое имя
// авторитета роняет разбор И НАЗЫВАЕТ КООРДИНАТУ.
//
// Координата утверждается отдельно от самого факта находки: находка без места
// посылает читателя искать по всему дереву, и такой гейт снимают как непонятный.
func TestAuthorityResidueGateCanFail(t *testing.T) {
	t.Parallel()
	axes := newAuthorityResidueAxes()

	cases := []struct {
		name string
		axis string
		file string
		body string
		at   string
	}{
		{
			name: "прод-код называет снятую службу УЗЛОМ-ИМЕНЕМ",
			axis: check.AxisGoCode,
			file: "internal/apps/kaname/api/limit/handler.go",
			body: "package limit\n\ntype H struct{}\n\nfunc (H) f() { var c LimitService; _ = c }\n",
			at:   "internal/apps/kaname/api/limit/handler.go:5",
		},
		{
			name: "контракт объявляет службу величин",
			axis: check.AxisContract,
			file: "proto/kaname/cloud/iam/v1/limit_service.proto",
			body: "syntax = \"proto3\";\npackage kaname.cloud.iam.v1;\n\nservice LimitService {\n}\n",
			at:   "proto/kaname/cloud/iam/v1/limit_service.proto:4",
		},
		{
			name: "закрытый каталог видов объявлен заново",
			axis: check.AxisCatalogue,
			file: "internal/domain/limit.go",
			body: "package domain\n\ntype CK struct{}\n\nvar countableKinds = []CountableKind{}\n",
			at:   "internal/domain/limit.go:5",
		},
		{
			name: "модель прав объявляет отношение читателя пределов",
			axis: check.AxisModel,
			file: "internal/authzmodel/fga_model.fga",
			body: "model\n  schema 1.1\ntype cluster\n  relations\n    define quota_reader: [service_account]\n",
			at:   "internal/authzmodel/fga_model.fga:5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			census, findings := check.JudgeAuthorityResidue(map[string]string{tc.file: tc.body}, nil)
			f, ok := findingOnAxis(findings, tc.axis)
			if !ok {
				t.Fatalf("внесённый дефект оси «%s» НЕ найден — гейт не способен упасть.\n%s\nнаходки: %v",
					tc.axis, census, findings)
			}
			if f.Where != tc.at {
				t.Fatalf("находка оси «%s» называет %s, а дефект внесён в %s — находка без верной "+
					"координаты посылает читателя не туда", tc.axis, f.Where, tc.at)
			}
		})
		axes.defect[tc.axis] = true
	}

	t.Logf("сторона дефекта: осей прогнано %d", len(axes.defect))
	if len(axes.defect) != 4 {
		t.Fatalf("осей прогнано %d, а объявлено 4 — инъекция не покрывает разбор целиком", len(axes.defect))
	}
}

// TestAuthorityResidueGateStaysSilentOnTheLawfulRemainder — сторона БЛИЗНЕЦА: то,
// что ОСТАЁТСЯ в службе после ухода авторитета, разбор обязан не находить.
//
// Ни один из этих миров не является краем или редкостью: все четыре — предмет
// решений `П25`, `Д9` и разбора поверхностей, и гейт, краснеющий на них,
// потребовал бы расширения поверхности либо снятия арендаторского чтения.
func TestAuthorityResidueGateStaysSilentOnTheLawfulRemainder(t *testing.T) {
	t.Parallel()
	axes := newAuthorityResidueAxes()

	cases := []struct {
		name string
		axis string
		file string
		body string
	}{
		{
			name: "словарь посадки: LimitKind и три её вида остаются",
			axis: check.AxisGoCode,
			file: "internal/domain/limit_posture_stated.go",
			body: "package domain\n\ntype LimitKind string\n\n" +
				"var postureStatedKinds = []LimitKind{\"iam.account\"}\n\n" +
				"func PostureStatedKinds() []LimitKind { return postureStatedKinds }\n",
		},
		{
			name: "НАДГРОБИЕ: снятая служба названа комментарием и строковым литералом",
			axis: check.AxisGoCode,
			file: "internal/authzguard/caller_policy.go",
			body: "package authzguard\n\n" +
				"// Здесь стояли пять глаголов InternalLimitService — авторитет величин\n" +
				"// снят решением владельца 2026-09-06 (kacho#2117).\n" +
				"func Retired() string { return \"LimitService\" }\n",
		},
		{
			name: "контракт: арендаторское чтение своего потолка и поле размера страницы",
			axis: check.AxisContract,
			file: "proto/kaname/cloud/iam/v1/identity_quota_service.proto",
			body: "syntax = \"proto3\";\npackage kaname.cloud.iam.v1;\n\n" +
				"service IdentityQuotaService {\n  rpc List (ListIdentityQuotasRequest) returns (ListIdentityQuotasResponse);\n}\n" +
				"message Quota {\n  int32 limit = 2;\n}\n",
		},
		{
			name: "модель прав: соседнее отношение того же типа остаётся",
			axis: check.AxisModel,
			file: "internal/authzmodel/fga_model.fga",
			body: "model\n  schema 1.1\ntype cluster\n  relations\n    define fga_writer: [service_account]\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			census, findings := check.JudgeAuthorityResidue(map[string]string{tc.file: tc.body}, nil)
			if len(findings) != 0 {
				t.Fatalf("законный остаток объявлен находкой — гейт ловит форму, а не предмет.\n%s\nнаходки: %v",
					census, findings)
			}
			// Молчание обязано быть ВЕРДИКТОМ, а не следствием непрочтения.
			if census.GoFiles+census.Contracts+census.Models == 0 {
				t.Fatalf("близнец не прочитан вовсе — его молчание ничего не доказывает: %s", census)
			}
		})
		axes.twin[tc.axis] = true
	}

	t.Logf("сторона близнеца: осей прогнано %d", len(axes.twin))
	if len(axes.twin) != 3 {
		t.Fatalf("близнецов прогнано по %d осям, а объявлено 3 — ось без близнеца "+
			"доказывает только способность краснеть", len(axes.twin))
	}
}

// TestAuthorityResidueCensusSeparatesNothingFoundFromNothingRead — перепись
// отличает «находок ноль» от «прочитано ноль».
//
// Это НЕ формальность: на пустом корпусе разбор возвращает ноль находок, и он
// неотличим от чистого дерева ничем, кроме этих чисел. Предпосылки самого гейта
// стоят на них.
func TestAuthorityResidueCensusSeparatesNothingFoundFromNothingRead(t *testing.T) {
	t.Parallel()

	empty, findings := check.JudgeAuthorityResidue(map[string]string{}, nil)
	if len(findings) != 0 {
		t.Fatalf("пустой корпус дал находки: %v", findings)
	}
	if empty.GoFiles != 0 || empty.Contracts != 0 || empty.Models != 0 || empty.Kept != 0 {
		t.Fatalf("пустой корпус объявил прочитанное: %s", empty)
	}

	// Тот же ноль находок — но на прочитанном корпусе с законным остатком.
	clean, findings := check.JudgeAuthorityResidue(map[string]string{
		"internal/domain/limit_posture_stated.go": "package domain\n\ntype LimitKind string\n\n" +
			"func IsPostureStatedKind(k LimitKind) bool { return k == \"iam.account\" }\n",
		"proto/kaname/cloud/iam/v1/identity_quota_service.proto": "syntax = \"proto3\";\n" +
			"service IdentityQuotaService {\n}\n",
		"internal/authzmodel/fga_model.fga": "model\n  schema 1.1\n",
	}, nil)
	if len(findings) != 0 {
		t.Fatalf("чистый корпус дал находки: %v", findings)
	}
	if clean.GoFiles == 0 || clean.Contracts == 0 || clean.Models == 0 {
		t.Fatalf("чистый корпус объявил обход пустым: %s", clean)
	}
	if clean.Kept == 0 {
		t.Fatalf("законный остаток прочитан ноль раз при непустом обходе — "+
			"перепись не различает соседа: %s", clean)
	}
	t.Logf("пусто: %s\nчисто: %s", empty, clean)
}

// TestAuthorityResidueUnparsedIsAThirdOutcome — файл, который парсер не принял,
// НЕ засчитывается ни в находки, ни в чистоту.
//
// Без этой пробы сломанный файл выглядел бы как чистый: находок ноль, и ноль
// этот произведён отказом разбора, а не состоянием дерева.
func TestAuthorityResidueUnparsedIsAThirdOutcome(t *testing.T) {
	t.Parallel()

	census, findings := check.JudgeAuthorityResidue(map[string]string{
		"internal/broken/broken.go": "package broken\n\nfunc ( {\n",
	}, nil)
	if len(findings) != 0 {
		t.Fatalf("неразобранный файл дал находки: %v", findings)
	}
	if len(census.Unparsed) != 1 || !strings.Contains(census.Unparsed[0], "broken.go") {
		t.Fatalf("неразобранный файл не назван третьей категорией: %s", census)
	}
	t.Logf("%s", census)
}

// TestAuthorityResidueLedgerExcusesAndExpires — ведомость отношений модели,
// обе стороны.
//
// Ведомость нужна тому единственному отношению, чьё снятие принадлежит другому
// предмету: оно ВЫДАНО применённой миграцией и ТРЕБУЕТСЯ каталогом, чья копия
// принадлежит краю платформы. Разбор причины — в шапке `AuthorityResidueLedger`.
//
// Проверяются обе стороны, потому что каждая по отдельности бесполезна:
// прощающая без истекающей даёт послабление навсегда, истекающая без прощающей
// не отличается от отсутствия ведомости.
func TestAuthorityResidueLedgerExcusesAndExpires(t *testing.T) {
	t.Parallel()

	const model = "internal/authzmodel/fga_model.fga"
	withRelation := "model\n  schema 1.1\ntype cluster\n  relations\n" +
		"    define quota_reader: [service_account, group#member] or system_admin\n"
	withoutRelation := "model\n  schema 1.1\ntype cluster\n  relations\n" +
		"    define fga_writer: [service_account, group#member] or system_admin\n"
	ledger := map[string]string{"quota_reader": "причина и предикат снятия"}

	t.Run("прощает названное и говорит об этом ЧИСЛОМ", func(t *testing.T) {
		census, findings := check.JudgeAuthorityResidue(
			map[string]string{model: withRelation}, ledger)
		if len(findings) != 0 {
			t.Fatalf("объявленное ведомостью отношение стало находкой: %v", findings)
		}
		if census.Excused != 1 {
			t.Fatalf("прощено %d раз вместо одного — послабление, о котором не сказано "+
				"числом, неотличимо от его отсутствия: %s", census.Excused, census)
		}
	})

	t.Run("БЕЗ ведомости то же отношение — находка", func(t *testing.T) {
		census, findings := check.JudgeAuthorityResidue(
			map[string]string{model: withRelation}, nil)
		if _, ok := findingOnAxis(findings, check.AxisModel); !ok {
			t.Fatalf("без ведомости отношение не найдено — прощение выше ничего не "+
				"доказывает, ось молчит сама по себе.\n%s", census)
		}
	})

	t.Run("ИСТЕКАЕТ САМА: записи нечего прощать — находка", func(t *testing.T) {
		census, findings := check.JudgeAuthorityResidue(
			map[string]string{model: withoutRelation}, ledger)
		f, ok := findingOnAxis(findings, check.AxisModel)
		if !ok {
			t.Fatalf("отношение ушло из модели, а запись ведомости молчит — послабление "+
				"переживает предмет и прикроет следующую находку.\n%s", census)
		}
		if f.Where != "AuthorityResidueLedger" {
			t.Fatalf("истёкшая запись названа координатой %q вместо ведомости", f.Where)
		}
	})

	t.Run("на корпусе БЕЗ модели истечения не объявляется", func(t *testing.T) {
		// Иначе находка была бы вердиктом об обходе, а не о дереве: модель не
		// прочитана, и о судьбе отношения не известно ничего.
		census, findings := check.JudgeAuthorityResidue(
			map[string]string{"internal/x/x.go": "package x\n"}, ledger)
		if len(findings) != 0 {
			t.Fatalf("на корпусе без модели ведомость объявлена истёкшей: %v\n%s",
				findings, census)
		}
	})
}

// TestAuthorityResidueCorpusSelectorReadsWhatItMustAndNothingElse — отбор
// корпуса.
//
// Обход и отбор живут в гейте, а не в разборе, поэтому инъекция по корпусу их не
// проверяет. Ось закрыта здесь: без неё гейт, читающий пустое подмножество,
// остался бы зелёным и выглядел бы исправным.
func TestAuthorityResidueCorpusSelectorReadsWhatItMustAndNothingElse(t *testing.T) {
	t.Parallel()

	read := map[string]bool{
		"internal/domain/limit.go":                        true,
		"cmd/kaname/wiring.go":                            true,
		"pkg/api/kaname/cloud/iam/v1/limit_service.pb.go": true,
		"proto/kaname/cloud/iam/v1/limit_service.proto":   true,
		"internal/authzmodel/fga_model.fga":               true,
		"proto/kaname/cloud/iam/v1/fga_model.fga":         true,
		"internal/domain/limit_test.go":                   false,
		"proto/kacho/cloud/operation/operation.proto":     false,
		"proto/corelib/authz/v1/authz_options.proto":      false,
		"internal/migrations/0001_initial.sql":            false,
		"docs/content/api/quotas.mdx":                     false,
		"INSTALL.md":                                      false,
	}
	for rel, want := range read {
		if got := judgedByAuthorityResidue(rel); got != want {
			t.Fatalf("отбор корпуса: %s читается=%v, а обязан %v", rel, got, want)
		}
	}
	t.Logf("отбор корпуса: путей проверено %d", len(read))
}
