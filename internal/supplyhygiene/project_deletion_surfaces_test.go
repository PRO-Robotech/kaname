// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// project_deletion_surfaces_test.go — поверхности, называющие условие и радиус
// удаления проекта, описывают ДЕЙСТВУЮЩЕЕ поведение (IAM-PNE-1-15, 1-16, 1-18;
// дом Д приёмки `non-empty-project-is-not-deleted.md`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Отказ по непустоте проекта заведён; страницы, контракт, шапки и инженерная
// записка до него утверждали обратное — «у проекта проверки ссылок нет»,
// «запрос проходит независимо от того, что в проекте лежит», «peer-callback'и
// появятся позже». Арендатор, упёршийся в отказ и прочитавший такую страницу,
// заключает, что сломан продукт, — исход хуже отсутствия отказа вовсе.
// Поэтому поверхности едут ВМЕСТЕ с отказом, и держатель у них — эта проба.
//
// Держатель у страниц НАШ, а не платформенный: гейт документа решения в дереве
// платформы судит одну координату — контракт (приёмка §8).
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРИ ПОЛОСЫ, У КАЖДОЙ СВОЙ АДРЕСАТ
//
//	1-15  страница проекта — читает тот, кто зовёт глагол руками
//	1-16  контракт, две шапки кода, инженерная записка — читает исполнитель
//	1-18  страницы Terraform и таблица кодов — читает тот, кто строит порядок сноса
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ПРОВЕРЯЕТСЯ — ОБЪЯВЛЕНИЕ, А НЕ РЕНДЕР
//
// Читаются файлы дерева, как они лежат; отрицания и утверждения ищутся
// дословными фразами, формулировка §7.4 — целиком с нормализацией пробелов.
// Проза, сказанная другими словами, вне наблюдения — и это граница, а не
// умолчание: словарь закрыт и назван ниже.
//
// Способность упасть и смолчать доказана инъекцией НАСТОЯЩИМ входом:
// project_deletion_surfaces_injection_test.go правит живые файлы по одному
// факту и ждёт находку с координатой.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Координаты поверхностей относительно корня службы.
const (
	projectPagePath      = "docs/content/api/project.mdx"
	projectContractPath  = "proto/kaname/cloud/iam/v1/project_service.proto"
	projectUseCasePath   = "internal/apps/kaname/api/project/delete.go"
	projectRepoPath      = "internal/repo/kaname/pg/project_repo.go"
	projectEngNotePath   = "docs/engineering/components/02-project.md"
	tfModuleProjectPath  = "docs/content/terraform/module-iam-project.mdx"
	tfProviderPath       = "docs/content/terraform/provider.mdx"
	apiOverviewPath      = "docs/content/api/overview.mdx"
	successorIssueNumber = "1231"
)

// boundaryStatement — формулировка §7.4 приёмки, принятая владельцем ДОСЛОВНО
// как текст страницы арендатора. Обе половины; на странице обязана стоять
// целиком, с той же разметкой выделений.
const boundaryStatement = `Удаление проекта отвергается, пока служба доступа числит в нём хотя бы один ресурс.
Счёт приходит к ней от сервисов-владельцев и обновляется **не мгновенно**: ресурс,
созданный секунду назад, может ещё не числиться, а снятый — числиться ещё некоторое
время. Поэтому отказ есть **защита от штатной ошибки**, а не гарантия целостности:
гарантию даёт только владелец ресурса у себя. Порядок, при котором потерь не бывает,
прежний — снимайте ресурсы до проекта.

Перечень в отказе называет **зарегистрированные объекты**, а не выполненные вами
действия. Один созданный ресурс может числиться **несколькими** объектами разных видов:
служебные объекты, которые владелец заводит вместе с ним, регистрируются наравне с ним
самим. Поэтому снятие одного ресурса убирает из перечня и те виды, которых вы не
создавали по отдельности, — перечень отвечает на вопрос «что ещё числится», а не
«сколько раз вы нажали создать».`

// refusalTone — дословный вид текста отказа (§2.4), которым страница называет
// перечень; форма сети, не аккаунта.
const refusalTone = "is not empty ("

// projectPageDenials — утверждения страницы проекта, ставшие ложными.
var projectPageDenials = []string{
	"проверки ссылок **нет**",
	"проверки ссылок нет",
	"проходит независимо от того, что в проекте лежит",
	"Пока решение не реализовано",
	// Сторона окна «после удаления» не закрыта (§7.1): владельцы кэшируют
	// положительный ответ о существовании проекта.
	"**прекращается**",
}

// contractDenials — утверждения описания глагола в контракте, ставшие ложными.
var contractDenials = []string{
	"NOT BLOCKED BY LIVE RESOURCES",
	"performs NO reference",
	"no NEW resource can be created",
	"delete the project LAST",
	"there is no supported way left to enumerate",
	"the OPEN successor carrying the mechanism",
	"peer-callback",
}

// contractBoundaryPhrases — формулировка §7.4 ПО СОДЕРЖАНИЮ, по-английски:
// счёт приходит не мгновенно · защита от штатной ошибки, а не гарантия ·
// перечень называет зарегистрированные объекты.
var contractBoundaryPhrases = []string{
	"does not arrive instantly",
	"a defence against an ordinary mistake, not a guarantee",
	"registered objects",
}

// useCaseHeaderDenials / repoHeaderDenials — шапки кода, пережившие свой предмет.
var useCaseHeaderDenials = []string{"peer-callback", "просто DELETE FROM projects", "Future:"}
var repoHeaderDenials = []string{"без cross-service refcheck", "Простой DELETE"}

// engNoteDenials — инженерная записка проекта.
var engNoteDenials = []string{
	"через peer-API",
	"cross-service: vpc_network.project_id",
	"на стороне kaname Delete пройдет без проблем",
	"workload останется orphan-ed",
}

// tfModuleDenials — страница модуля Terraform.
var tfModuleDenials = []string{
	"только если в нём не осталось пользовательских ролей",
}

// boundaryReference — как страница называет границу либо ведёт на неё: сама
// фраза §7.4 либо ссылка на страницу проекта.
var boundaryReference = []string{"защита от штатной ошибки", "/api/project"}

// secondToneMarkers — второй тон отказа проекта, которого заводить нельзя
// (форма аккаунта «contains … and cannot be deleted» и её русский пересказ).
var secondToneMarkers = []string{
	"Project <id> contains", "содержит роли и не может быть удалён",
}

func normalizeSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// commentMarker — маркер строчного комментария в контракте и шапках кода:
// фраза, перенесённая на следующую строку комментария, обязана читаться целиком.
var lineCommentMarker = regexp.MustCompile(`(?m)^\s*//\s?`)

func flattenComments(s string) string {
	return normalizeSpace(lineCommentMarker.ReplaceAllString(s, ""))
}

func readSurface(t *testing.T, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(serviceRoot, filepath.FromSlash(rel))) // #nosec G304 -- координата дерева службы
	require.NoErrorf(t, err, "%s не прочитан — непрочитанное есть находка, а не согласие", rel)
	require.NotEmptyf(t, body, "%s пуст", rel)
	return string(body)
}

// judgeProjectPage — IAM-PNE-1-15.
func judgeProjectPage(page string) []string {
	var findings []string
	// Страницы переносят предложения по строкам: подстроки ищутся по тексту с
	// нормализованными пробелами, строки таблиц — по сырому.
	flat := normalizeSpace(page)
	for _, d := range projectPageDenials {
		if strings.Contains(flat, d) {
			findings = append(findings, projectPagePath+": страница ещё утверждает «"+d+"»")
		}
	}
	for _, want := range []string{"FAILED_PRECONDITION", refusalTone, "REFERENCE_IN_USE"} {
		if !strings.Contains(flat, want) {
			findings = append(findings, projectPagePath+": не назван «"+want+"» — код, вид текста и признак полосы обязаны стоять на странице")
		}
	}
	if !strings.Contains(flat, normalizeSpace(boundaryStatement)) {
		findings = append(findings, projectPagePath+": формулировка границы §7.4 не стоит дословно (обе половины)")
	}
	if !errorTableHasRow(page, "FAILED_PRECONDITION") {
		findings = append(findings, projectPagePath+": таблица ошибок не несёт строки FAILED_PRECONDITION")
	}
	if !strings.Contains(page, "issues/"+successorIssueNumber) {
		findings = append(findings, projectPagePath+": ссылка на #"+successorIssueNumber+" снята — остаток (сквозное наблюдение через край платформы) потерял адрес")
	}
	return findings
}

// errorTableHasRow — в HTML-таблице ошибок страницы есть строка с кодом.
func errorTableHasRow(page, code string) bool {
	return regexp.MustCompile(`<tr>.*<code>` + regexp.QuoteMeta(code) + `</code>.*</tr>`).MatchString(page)
}

// judgeContractAndHeaders — IAM-PNE-1-16.
func judgeContractAndHeaders(contract, useCase, repo, note string) []string {
	var findings []string
	contract, useCase, repo, note = flattenComments(contract), flattenComments(useCase), flattenComments(repo), normalizeSpace(note)
	for _, d := range contractDenials {
		if strings.Contains(contract, d) {
			findings = append(findings, projectContractPath+": описание глагола ещё утверждает «"+d+"»")
		}
	}
	for _, p := range contractBoundaryPhrases {
		if !strings.Contains(contract, p) {
			findings = append(findings, projectContractPath+": описание глагола не несёт границы по содержанию: «"+p+"»")
		}
	}
	if !strings.Contains(contract, "#"+successorIssueNumber) {
		findings = append(findings, projectContractPath+": ссылка на #"+successorIssueNumber+" снята — гейт платформы требует, чтобы каждая поверхность решения называла преемника")
	}
	for _, d := range useCaseHeaderDenials {
		if strings.Contains(useCase, d) {
			findings = append(findings, projectUseCasePath+": шапка ещё говорит «"+d+"»")
		}
	}
	for _, d := range repoHeaderDenials {
		if strings.Contains(repo, d) {
			findings = append(findings, projectRepoPath+": шапка метода ещё говорит «"+d+"»")
		}
	}
	for _, d := range engNoteDenials {
		if strings.Contains(note, d) {
			findings = append(findings, projectEngNotePath+": записка ещё утверждает «"+d+"»")
		}
	}
	return findings
}

// providerBlockerCell — клетка «Что удерживает» строки «Проект» в таблице
// «Что мешает удалению» страницы провайдера.
func providerBlockerCell(page string) (string, bool) {
	section := page
	if i := strings.Index(page, "## Что мешает удалению"); i >= 0 {
		section = page[i:]
	} else {
		return "", false
	}
	if j := strings.Index(section[1:], "\n## "); j >= 0 {
		section = section[:j+1]
	}
	m := regexp.MustCompile(`(?m)^\|\s*Проект\s*\|(.*)\|\s*$`).FindStringSubmatch(section)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// overviewFailedPreconditionRow — строка FAILED_PRECONDITION таблицы кодов.
func overviewFailedPreconditionRow(page string) (string, bool) {
	m := regexp.MustCompile(`<tr>.*<code>FAILED_PRECONDITION</code>.*</tr>`).FindString(page)
	return m, m != ""
}

func namesBoundary(page string) bool {
	for _, ref := range boundaryReference {
		if strings.Contains(page, ref) {
			return true
		}
	}
	return false
}

// judgeOtherSurfaces — IAM-PNE-1-18.
func judgeOtherSurfaces(tfModule, tfProvider, overview string) []string {
	var findings []string
	flatModule := normalizeSpace(tfModule)
	for _, d := range tfModuleDenials {
		if strings.Contains(flatModule, d) {
			findings = append(findings, tfModuleProjectPath+": «Порядок сноса» ещё утверждает «"+d+"»")
		}
	}
	if !strings.Contains(tfModule, "## Порядок сноса") {
		findings = append(findings, tfModuleProjectPath+": раздела «Порядок сноса» нет — судить нечего")
	}
	cell, ok := providerBlockerCell(tfProvider)
	switch {
	case !ok:
		findings = append(findings, tfProviderPath+": строки «Проект» в таблице «Что мешает удалению» нет")
	case !strings.Contains(cell, "рол") || !strings.Contains(cell, "ресурс"):
		findings = append(findings, tfProviderPath+": клетка строки «Проект» называет не оба рода удерживающего: ["+strings.TrimSpace(cell)+"]")
	}
	row, ok := overviewFailedPreconditionRow(overview)
	switch {
	case !ok:
		findings = append(findings, apiOverviewPath+": строки FAILED_PRECONDITION в таблице кодов нет")
	case !strings.Contains(row, "непуст"):
		findings = append(findings, apiOverviewPath+": строка FAILED_PRECONDITION не называет удаление непустого проекта")
	}
	for name, page := range map[string]string{tfModuleProjectPath: tfModule, tfProviderPath: tfProvider, apiOverviewPath: overview} {
		page = normalizeSpace(page)
		if !namesBoundary(page) {
			findings = append(findings, name+": граница §7.4 не названа и ссылки на неё нет")
		}
		for _, m := range secondToneMarkers {
			if strings.Contains(page, m) {
				findings = append(findings, name+": второй тон отказа проекта «"+m+"»")
			}
		}
	}
	return findings
}

func TestProjectDeletionSurfaces_PNE_1_15_ProjectPageDescribesTheLiveBehaviour(t *testing.T) {
	t.Parallel()
	page := readSurface(t, projectPagePath)
	findings := judgeProjectPage(page)
	t.Logf("перепись: страница прочитана (%d байт) · отрицаний в словаре %d · находок %d",
		len(page), len(projectPageDenials), len(findings))
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}

func TestProjectDeletionSurfaces_PNE_1_16_ContractAndHeadersMatchTheTree(t *testing.T) {
	t.Parallel()
	findings := judgeContractAndHeaders(
		readSurface(t, projectContractPath),
		readSurface(t, projectUseCasePath),
		readSurface(t, projectRepoPath),
		readSurface(t, projectEngNotePath),
	)
	t.Logf("перепись: поверхностей прочитано 4 · отрицаний в словарях %d · находок %d",
		len(contractDenials)+len(useCaseHeaderDenials)+len(repoHeaderDenials)+len(engNoteDenials), len(findings))
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}

func TestProjectDeletionSurfaces_PNE_1_18_OtherClientPagesNameTheRadius(t *testing.T) {
	t.Parallel()
	findings := judgeOtherSurfaces(
		readSurface(t, tfModuleProjectPath),
		readSurface(t, tfProviderPath),
		readSurface(t, apiOverviewPath),
	)
	t.Logf("перепись: страниц прочитано 3 · находок %d", len(findings))
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}
