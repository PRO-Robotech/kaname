// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// image_published_revision_injection_test.go — ГЕЙТ ПРОВЯЗКИ И САМОПРОВЕРКА
// СВЕРКИ СПОСОБНЫ УПАСТЬ И СПОСОБНЫ СМОЛЧАТЬ (задача PRO-Robotech/kaname#429).
//
// Инъекция идёт НАСТОЯЩИМ входом. Для гейта провязки — объявление процесса из
// дерева, и дефект вносится в его КОПИЮ по одному факту. Для сверки — её файл
// из дерева, скопированный во временный каталог и испорченный по одному факту;
// судит его ЕГО ЖЕ самопроверка. Каждой половине «краснеет» отвечает половина
// «молчит»: на нетронутом входе находок ноль, и законный близнец каждой
// инъекции, где он есть, стоит рядом с ней.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Записи объявления, в которые вносится дефект. Каждая обязана найтись в
// дереве ровно там, где её ждут (`injectOnce` отказывает на беспредметной
// замене).
const (
	publishedCheckRun    = `run: .github/scripts/image-published-revision.sh "$IMAGE_REF" "$REVISION" "$PLATFORMS"`
	publishedSelfTestRun = `run: .github/scripts/image-published-revision.sh --self-test`
	publishedCheckIf     = "        id: published\n        if: steps.gate.outputs.push == 'true'\n"
	publishedCheckRefEnv = "/${{ env.IMAGE_NAME }}:${{ steps.subject.outputs.tag }}\n" +
		"          REVISION: ${{ steps.subject.outputs.revision }}\n          PLATFORMS:"
	publishedCheckPlatformsEnv = "          PLATFORMS: ${{ github.event_name == 'pull_request' && 'linux/amd64' || 'linux/amd64,linux/arm64' }}\n" +
		"        " + publishedCheckRun
	publishedCheckHead    = "      - name: опубликованный образ несёт ревизию головы\n"
	publishedSelfTestHead = "      - name: сверка опубликованного — доказательство инъекцией в обе стороны\n"
	publishedBuildHead    = "      - name: сборка образа\n"
)

// imageProducerSource — объявление образа службы из дерева.
func imageProducerSource(t *testing.T) string {
	t.Helper()
	raw, ok := trunkCorpusSource(t)[imageInjectRel]
	require.Truef(t, ok, "инъекция беспредметна: %s не прочитан", imageInjectRel)
	return raw
}

// cutBlock — копия без шага, начинающегося записью head и кончающегося записью
// tail (включительно), и сам вырезанный шаг.
func cutBlock(t *testing.T, raw, head, tail string) (string, string) {
	t.Helper()
	start := strings.Index(raw, head)
	require.GreaterOrEqualf(t, start, 0, "инъекция беспредметна: шага %q в объявлении нет", head)
	end := strings.Index(raw[start:], tail)
	require.GreaterOrEqualf(t, end, 0, "инъекция беспредметна: конца шага %q в объявлении нет", tail)
	end += start + len(tail)
	return raw[:start] + raw[end:], raw[start:end]
}

func publishedAudit(t *testing.T, raw string) []string {
	t.Helper()
	findings, _, err := check.AuditImagePublishedRevision(raw)
	require.NoError(t, err, "инъекция доказывала бы разбор, а не гейт")
	return findings
}

// TestImagePublishedRevisionGateCanFail — ПОЛОВИНА «КРАСНЕЕТ» гейта провязки, по
// оси на подпробу, и законные близнецы рядом.
func TestImagePublishedRevisionGateCanFail(t *testing.T) {
	t.Parallel()
	raw := imageProducerSource(t)

	for _, tc := range []struct {
		what string
		edit func(t *testing.T, raw string) string
		// says — что находка обязана назвать; пусто — находок быть не должно.
		says string
	}{
		{"сверка снята — п.1 предиката снова держится вниманием", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedCheckRun, `run: echo "$IMAGE_REF" "$REVISION" "$PLATFORMS"`)
		}, "сверки опубликованного НЕТ"},
		// Гейт читает исполняемую часть, а не текст: упоминание в комментарии
		// вызовом не является.
		{"сверка осталась только комментарием в теле шага", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedCheckRun, "run: |\n          # "+
				strings.TrimPrefix(publishedCheckRun, "run: ")+"\n          echo снята")
		}, "сверки опубликованного НЕТ"},
		{"самопроверка снята", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedSelfTestRun, "run: echo самопроверка")
		}, "--self-test не зовётся"},
		{"самопроверка условна", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedSelfTestHead, publishedSelfTestHead+
				"        if: github.event_name != 'pull_request'\n")
		}, "самопроверка сверки условна"},
		{"самопроверка стоит после сверки", func(t *testing.T, r string) string {
			rest, block := cutBlock(t, r, publishedSelfTestHead, publishedSelfTestRun+"\n")
			return injectOnce(t, rest, publishedCheckRun+"\n", publishedCheckRun+"\n"+block)
		}, "самопроверка стоит ПОСЛЕ сверки"},
		{"сверка стоит до сборки", func(t *testing.T, r string) string {
			rest, block := cutBlock(t, r, publishedCheckHead, publishedCheckRun+"\n")
			return injectOnce(t, rest, publishedBuildHead, block+publishedBuildHead)
		}, "сверка стоит ДО сборки"},
		{"у сверки нет условия публикации", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedCheckIf, "        id: published\n")
		}, "сверка без условия публикации"},
		{"условие сверки разошлось с условием публикации", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedCheckIf, "        id: published\n        if: github.event_name == 'push'\n")
		}, "разошлось с условием публикации"},
		// ЗАКОННЫЙ БЛИЗНЕЦ двух проб выше: то же условие в обёртке выражения.
		{"условие публикации в обёртке выражения — не расхождение", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedCheckIf,
				"        id: published\n        if: ${{ steps.gate.outputs.push == 'true' }}\n")
		}, ""},
		{"сверка спрашивает о движущемся теге", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedCheckRefEnv, strings.Replace(publishedCheckRefEnv,
				":${{ steps.subject.outputs.tag }}", ":latest", 1))
		}, "IMAGE_REF у сверки"},
		{"сверка сужена до одной платформы", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedCheckPlatformsEnv,
				"          PLATFORMS: linux/amd64\n        "+publishedCheckRun)
		}, "PLATFORMS у сверки"},
		{"ревизия сверки — второе написание величины", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedCheckRefEnv, strings.Replace(publishedCheckRefEnv,
				"REVISION: ${{ steps.subject.outputs.revision }}", "REVISION: ${{ github.sha }}", 1))
		}, "REVISION у сверки"},
		{"доводы сверки переставлены", func(t *testing.T, r string) string {
			return injectOnce(t, r, publishedCheckRun,
				`run: .github/scripts/image-published-revision.sh "$IMAGE_REF" "$PLATFORMS" "$REVISION"`)
		}, "зовётся не с доводами"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			got := publishedAudit(t, tc.edit(t, raw))
			if tc.says == "" {
				require.Emptyf(t, got, "законный близнец назван нарушителем: %v", got)
				return
			}
			require.Lenf(t, got, 1, "инъекция одного факта дала не одну находку: %v", got)
			require.Contains(t, got[0], tc.says)
		})
	}
}

// TestImagePublishedRevisionGateRefusesAnUnfoundedVerdict — беспредметный вход
// и ложная предпосылка: вердикта нет, и молчанием это не становится.
func TestImagePublishedRevisionGateRefusesAnUnfoundedVerdict(t *testing.T) {
	t.Parallel()
	raw := imageProducerSource(t)

	for _, tc := range []struct{ what, input, says string }{
		{"объявление не разбирается", "{ обрезано", "не разобрано"},
		{"задания образа нет", injectOnce(t, raw, "\n  image:\n", "\n  imagex:\n"), "задания"},
		{"шага сборки нет", injectOnce(t, raw, "docker buildx build \\", "echo buildx \\"), "нет шага сборки"},
		{"у сборки нет величины ревизии", injectOnce(t, raw,
			"          REVISION: ${{ steps.subject.outputs.revision }}\n          VERSION:", "          VERSION:"),
			"нет величины REVISION"},
		{"публикацию решает другое условие", injectOnce(t, raw,
			"PUSH_FLAG: ${{ steps.gate.outputs.push == 'true' && '--push' || '' }}",
			"PUSH_FLAG: ${{ github.event_name == 'push' && '--push' || '' }}"), "флаг отправки"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			_, _, err := check.AuditImagePublishedRevision(tc.input)
			require.Errorf(t, err, "ложная предпосылка принята за чистую провязку")
			require.Contains(t, err.Error(), tc.says)
		})
	}
}

// TestImagePublishedRevisionSelfTestCanFail — ПОЛОВИНА «КРАСНЕЕТ» самой сверки:
// её файл из дерева испорчен по одному факту, и её ЖЕ самопроверка обязана
// назвать пробу, на которой дефект виден. Половина «молчит» — несущее
// утверждение `TestImagePublishedRevisionCheckProvesItself` на нетронутом файле.
func TestImagePublishedRevisionSelfTestCanFail(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile(filepath.Join(treeRoot(t), filepath.FromSlash(check.ImagePublishedRevisionScript))) // #nosec G304 -- координата объявлена постоянной
	require.NoError(t, err, "инъекция беспредметна: сверки в дереве нет")
	script := string(src)

	for _, tc := range []struct {
		what, old, repl string
		rc              int
		says            string
	}{
		{"ревизия не сравнивается", `elif [ "$got" != "$want" ]; then`, `elif false; then`,
			1, "ПРОВАЛ (+) у arm64 чужая ревизия"},
		{"реестр спрошен без --pull always", "create --pull always --quiet", "create --quiet",
			1, "ПРОВАЛ (−) реестр спрошен не так"},
		{"образ берётся по тегу, а не по отпечатку платформы", `"$repo@$digest" 2>`, `"$ref" 2>`,
			1, "ПРОВАЛ (−) обе платформы несут голову"},
		{"непрочитанное сильнее находки",
			"    if [ \"$findings\" -gt 0 ]; then return 1; fi\n    if [ \"$unread\" -gt 0 ]; then return 2; fi\n",
			"    if [ \"$unread\" -gt 0 ]; then return 2; fi\n    if [ \"$findings\" -gt 0 ]; then return 1; fi\n",
			1, "ПРОВАЛ (+) чужая ревизия сильнее непрочитанного"},
		{"платформа вне индекса не находка", `if [ -z "$digest" ]; then`, `if false; then`,
			1, "ПРОВАЛ (+) arm64 в индексе нет"},
		{"читается только первая платформа", "for p in \"${wanted[@]}\"; do\n        i=$((i + 1))",
			"for p in \"${wanted[0]}\"; do\n        i=$((i + 1))", 1, "ПРОВАЛ (+) у arm64 чужая ревизия"},
		// Самопроверка отказывает идти к настоящему демону: подделка, до которой
		// можно не дойти, подделкой не является.
		{"двойник не подставлен", `docker_cli() { printf '%s' "${IMAGE_REVISION_DOCKER:-docker}"; }`,
			`docker_cli() { printf '%s' docker; }`, 2, "НЕ подменён двойником"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			require.Equalf(t, 1, strings.Count(script, tc.old), "инъекция беспредметна: записи %q в сверке не одна", tc.old)
			path := filepath.Join(t.TempDir(), "image-published-revision.sh")
			require.NoError(t, os.WriteFile(path, []byte(strings.Replace(script, tc.old, tc.repl, 1)), 0o600))
			rc, out, _, _ := runPublishedSelfTest(t, path)
			require.Equalf(t, tc.rc, rc, "испорченная сверка прошла свою самопроверку:\n%s", out)
			require.Contains(t, out, tc.says)
		})
	}

	// ВЕДОМОСТЬ ПРОБ ТОЧНАЯ: проба, выпавшая из самопроверки, оставляет её
	// зелёной — и ловит это только число, а не код.
	t.Run("проба выпала из самопроверки — число исполненных разошлось с ведомостью", func(t *testing.T) {
		t.Parallel()
		const dropped = `    run 2 "(+) ссылка пуста" "ссылка на образ пуста" "" "$HEAD" "$BOTH"` + "\n"
		require.Equal(t, 1, strings.Count(script, dropped), "инъекция беспредметна: пробы в сверке нет")
		path := filepath.Join(t.TempDir(), "image-published-revision.sh")
		require.NoError(t, os.WriteFile(path, []byte(strings.Replace(script, dropped, "", 1)), 0o600))
		rc, out, ran, failed := runPublishedSelfTest(t, path)
		require.Equalf(t, 0, rc, "самопроверка без одной пробы обязана остаться зелёной кодом:\n%s", out)
		require.Equal(t, 0, failed)
		require.Equal(t, publishedSelfTestProbes-1, ran, "выпавшая проба не видна по числу исполненных")
	})
}
