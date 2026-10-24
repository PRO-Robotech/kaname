// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// edgeless_check_is_executable_test.go — ПРОВЕРКА БЕЗ КРАЯ В INSTALL ИСПОЛНИМА
// НА ОТДЕЛЬНОМ ЧАРТЕ (kaname#761).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// INSTALL предлагал «проверку без края»: взять токен у самой службы её штатной
// выдачей (`POST :9096/iam/v1/token`) и позвать им публичный вызов. Выдача
// принимает утверждение, подписанное ключом служебной учётки, а первого
// удостоверения отдельный чарт не даёт: вход человека открывает только край,
// чеканка бутстрап-удостоверения в чарте не объявлена ни одной ручкой, ключей
// посева нет. Шаг был объявлен и неисполним.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ
//
//	предпосылка  профили чарта не объявляют источника первого удостоверения
//	             (блок `bootstrapMint`). Появится — проба падает с этим
//	             именем: шаг с токеном стал бы исполним, и вердикт о нём —
//	             беспредметен;
//	отрицание    блок «Проверка без края» не велит взять токен у выдачи
//	             (путь выводится из `clienttokenhttp.TokenPath`), если тот же
//	             блок не говорит, что первого удостоверения чарт не выдаёт;
//	положительное блок существует и несёт исполнимую команду (`curl`) и её
//	             исход (`UNAUTHENTICATED`) — иначе молчание о токене было бы
//	             зелёным и на пустом блоке.
package deploy_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

// edgelessCheckHeading — начало блока проверки без края в INSTALL.md.
const edgelessCheckHeading = "**Проверка без края.**"

// edgelessCheckBlock — текст блока от заголовка до следующего пункта того же
// уровня либо до конца нумерованного перечня (строка без отступа).
func edgelessCheckBlock(install string) string {
	i := strings.Index(install, edgelessCheckHeading)
	if i < 0 {
		return ""
	}
	var out []string
	for n, line := range strings.Split(install[i:], "\n") {
		if n > 0 && (strings.HasPrefix(strings.TrimSpace(line), "- **") ||
			(line != "" && !strings.HasPrefix(line, " "))) {
			break
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// takesTokenFromIssuer — велит ли блок взять токен у штатной выдачи.
var takesTokenFromIssuer = regexp.MustCompile(`(?i)возьмите\s+токен`)

// namesNoFirstCredential — говорит ли блок, что первого удостоверения
// отдельный чарт не выдаёт.
var namesNoFirstCredential = regexp.MustCompile(`(?i)первого\s+удостоверения[^.]*не\s+(?:выдаёт|даёт)`)

func edgelessCheckFindings(block string) []string {
	var f []string
	if strings.TrimSpace(block) == "" {
		return []string{"блока «Проверка без края» нет — судить нечего"}
	}
	if (takesTokenFromIssuer.MatchString(block) || strings.Contains(block, clienttokenhttp.TokenPath)) &&
		!namesNoFirstCredential.MatchString(block) {
		f = append(f, "блок велит взять токен у выдачи "+clienttokenhttp.TokenPath+
			", а первого удостоверения отдельный чарт не выдаёт — шаг неисполним")
	}
	if !strings.Contains(block, "curl ") {
		f = append(f, "блок не несёт исполнимой команды (`curl`) — проверять оператору нечем")
	}
	if !strings.Contains(block, "UNAUTHENTICATED") {
		f = append(f, "блок не называет исход команды (`UNAUTHENTICATED`)")
	}
	return f
}

func TestEdgelessCheckInInstallIsExecutableOnTheStandaloneChart(t *testing.T) {
	root := serviceRoot(t)

	// Предпосылка: источника первого удостоверения в профилях нет.
	for _, rel := range []string{"deploy/values.yaml", "deploy/values.prod.yaml"} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("%s не прочитан: %v", rel, err)
		}
		if regexp.MustCompile(`(?m)^\s*bootstrapMint:`).Match(raw) {
			t.Fatalf("предпосылка снята: %s объявляет `bootstrapMint` — у отдельного чарта появился источник первого удостоверения, и шаг с токеном в INSTALL пересматривается", rel)
		}
	}

	// Распознаватель доказан на синтетике в обе стороны.
	if len(edgelessCheckFindings("- **Проверка без края.** Возьмите токен у самой службы (`POST :9096/iam/v1/token`)\n  curl x\n  UNAUTHENTICATED")) != 1 {
		t.Fatal("распознаватель молчит на шаге, велящем взять токен у выдачи")
	}
	if f := edgelessCheckFindings("- **Проверка без края.** Первого удостоверения отдельный чарт не выдаёт; выдача `/iam/v1/token` ждёт ключа.\n  curl x\n  UNAUTHENTICATED"); len(f) != 0 {
		t.Fatalf("распознаватель краснит законный блок: %v", f)
	}

	raw, err := os.ReadFile(filepath.Join(root, "INSTALL.md"))
	if err != nil {
		t.Fatalf("INSTALL.md не прочитан: %v", err)
	}
	block := edgelessCheckBlock(string(raw))
	t.Logf("INSTALL.md: блок проверки без края — %d строк", strings.Count(block, "\n")+1)
	for _, f := range edgelessCheckFindings(block) {
		t.Error("INSTALL.md: " + f)
	}
}
