// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package tools_regression

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// model_canon_check_test.go — у побайтовой сверки модели с манифестом есть
// ИСПОЛНИТЕЛЬ, и он различает четыре исхода (задача PRO-Robotech/kacho#1089,
// приёмка services/iam/docs/engineering/acceptance/model-generated-from-manifest.md,
// §2 п. 5 и п. 7).
//
// # Зачем проба на исполнителя, когда есть пробы пакета
//
// Пробы `services/iam/internal/modelrender` судят обход на СИНТЕТИЧЕСКИХ деревьях
// и о дереве продукта не утверждают ничего. Пакет, который никто не зовёт, —
// вестигиальный код (`architecture.md` §LEAN): перепись, которую обещает §2 п. 5,
// не печатается НИГДЕ, а «сверка побайтовая» остаётся библиотекой, а не гейтом.
//
// # Исходов ЧЕТЫРЕ, и каждый проверяется своим входом
//
//	0  сверено всё объявленное
//	1  находка
//	2  VOID — сверять нечего ни для одного модуля
//	3  проверка НЕ ИСПОЛНЯЛАСЬ — вызов разобрать не удалось
//
// Схлопывание третьего в успех объявило бы годным то, чего исполнитель не читал;
// схлопывание четвёртого в VOID объявило бы пустым деревом опечатку в вызове.

// wrapper — тонкая обёртка, которую зовёт цель Makefile. Проверяется ИМЕННО она:
// цепочка «цель → обёртка → сборка → двоичный файл → код возврата» целиком.
func wrapper(t *testing.T) string {
	t.Helper()
	p := filepath.Join(serviceRoot(t), "tools", "model-canon-check.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("исполнителя сверки в дереве нет (%v): пакет modelrender зовут только его "+
			"собственные пробы, значит дерево продукта не сверяется НИЧЕМ", err)
	}
	return p
}

// runCheck зовёт обёртку и возвращает код возврата и объединённый вывод.
func runCheck(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{wrapper(t)}, args...)...) // #nosec G204 -- путь из дерева проб
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("обёртка не запустилась: %v\n%s", err, out)
		}
		code = ee.ExitCode()
	}
	return code, string(out)
}

// syntheticTree — дерево с каноном из двух блоков модуля vpc и манифестами всех
// шести модулей набора. vpcResources называет ресурсы, которые манифест vpc
// объявляет.
func syntheticTree(t *testing.T, vpcResources ...string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "proto", "kacho", "cloud", "iam", "v1")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("каталог канона: %v", err)
	}
	const canon = `model
  schema 1.1

type vpc_network
  relations
    define project: [project]
    define super_admin: super_admin from project
    define admin: [user, service_account, group#member] or super_admin
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or super_admin

type vpc_subnet
  relations
    define project: [project]
    define super_admin: super_admin from project
    define admin: [user, service_account, group#member] or super_admin
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or super_admin
`
	if err := os.WriteFile(filepath.Join(dir, "fga_model.fga"), []byte(canon), 0o600); err != nil {
		t.Fatalf("запись канона: %v", err)
	}
	for _, m := range []string{"iam", "vpc", "compute", "loadbalancer", "registry", "storage"} {
		var sb strings.Builder
		sb.WriteString("apiVersion: iam/v1\nmodule: " + m + "\nresources:\n")
		if m == "vpc" {
			for _, r := range vpcResources {
				sb.WriteString("  - name: " + strings.TrimPrefix(r, "vpc_") + "\n")
				sb.WriteString("    objectType: " + r + "\n")
				sb.WriteString("    parents: [project]\n")
				sb.WriteString("    producer: derived\n")
				sb.WriteString("    verbs:\n      - get\n")
			}
		}
		md := filepath.Join(root, "modules", m)
		if err := os.MkdirAll(md, 0o750); err != nil {
			t.Fatalf("каталог модуля %s: %v", m, err)
		}
		if err := os.WriteFile(filepath.Join(md, "manifest.yaml"), []byte(sb.String()), 0o600); err != nil {
			t.Fatalf("манифест %s: %v", m, err)
		}
	}
	return root
}

// TestModelCanonCheckOnTheRealTreeComparesEveryOwnedBlock — дерево продукта:
// манифест несёт КАЖДЫЙ модуль закрытого набора, поэтому сверяются все блоки,
// которые закрытая таблица относит к модулям.
//
// # Здесь стояло обратное утверждение, и оно пережило свой предмет
//
// Прежняя редакция звалась …IsVoidAndSaysSo и требовала исхода 2: «манифестов в
// дереве ноль». Утверждение было верно в день записи и стало ложью в день
// приезда манифестов (#1091). Снять его молча было нельзя — оно про ДЕРЕВО
// ПРОДУКТА, и без него исполнитель остался бы без пробы на настоящем входе, — а
// оставить как есть тем более: проба требовала бы от продукта отсутствия того,
// ради чего вся работа делалась.
//
// # Числа сверяются ПАРОЙ и не выписываются
//
// Знаменатель растёт вместе с закрытой таблицей, поэтому проба не пинит 27:
// выписанное число устарело бы молча при первом же новом типе. Утверждается
// СВОЙСТВО — сверено столько же, сколько принадлежит модулям, и это не ноль:
// «сверено 0 из 0» есть «ноль прочитанного», и от успеха оно отличается ровно
// тем, что печатается рядом.
func TestModelCanonCheckOnTheRealTreeComparesEveryOwnedBlock(t *testing.T) {
	code, out := runCheck(t)

	if code != 0 {
		t.Fatalf("исход %d, ожидался 0: каждый модуль закрытого набора несёт манифест, "+
			"и его блоки обязаны сверяться\n%s", code, out)
	}
	if !strings.Contains(out, "прощено ведомостью 0") {
		t.Errorf("перепись не называет пустую ведомость: послабление, которого не видно, "+
			"не снимет никто\n%s", out)
	}
	compared, owned := comparedBlocks(t, out)
	if compared == 0 || compared != owned {
		t.Errorf("сверено %d из %d: «ноль прочитанного» неотличимо от «ноль находок», "+
			"а недосверенное — от сверенного\n%s", compared, owned, out)
	}
}

// comparedBlocks достаёт из переписи пару «сверено N из M».
//
// Пара, а не одно число: одно скрывает ровно тот случай, ради которого перепись
// печатается — обход, не дошедший до блоков, отдаёт ноль так же уверенно, как
// сверивший все.
func comparedBlocks(t *testing.T, out string) (compared, owned int) {
	t.Helper()
	m := regexp.MustCompile(`блоков сверено (\d+) из (\d+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("перепись не называет пары «сверено N из M» — без знаменателя вердикт "+
			"не читается\n%s", out)
	}
	compared, _ = strconv.Atoi(m[1])
	owned, _ = strconv.Atoi(m[2])
	return compared, owned
}

// TestModelCanonCheckIsSilentWhenEveryOwnedBlockIsRendered — положительный
// контроль: дерево, где каждый блок канона порождён манифестом, даёт исход 0 и
// НИ ОДНОЙ находки.
//
// # Половина «ведомость истекает» ушла отсюда вместе со своим предметом
//
// Прежняя редакция ждала исхода 1 и шести находок «запись ведомости пережила
// свой предмет»: ведомость исполнителя прощала все шесть модулей, а на дереве с
// манифестами каждая её запись теряла предмет. Ведомость снята задачей #1091 тем
// же изменением, которым приехали манифесты, поэтому истекать здесь больше
// нечему, и требовать истечения значило бы требовать возврата послабления.
//
// САМО свойство самоистечения при этом не потеряно и проверяется там, где у него
// есть предмет, — пробами обхода (`internal/modelrender`, N04: запись ведомости
// на модуль, чей манифест приехал, есть находка). Здесь судится исполнитель, и
// от него теперь требуется обратное: молчать, когда прощать нечего и всё сверено.
func TestModelCanonCheckIsSilentWhenEveryOwnedBlockIsRendered(t *testing.T) {
	code, out := runCheck(t, "-root="+syntheticTree(t, "vpc_network", "vpc_subnet"))

	if code != 0 {
		t.Fatalf("исход %d, ожидался 0: блоки порождены и равны, прощать нечего\n%s", code, out)
	}
	if !strings.Contains(out, "блоков сверено 2 из 2") {
		t.Errorf("перепись не называет ни сверенного, ни ожидаемого: без пары чисел "+
			"«сверено 0» неотличимо от «сверять было нечего»\n%s", out)
	}
	if strings.Contains(out, "пережила свой предмет") {
		t.Errorf("ведомость исполнителя снова кого-то прощает: послабление вернулось "+
			"вместе с предметом, о котором никто не решал\n%s", out)
	}
	if strings.Contains(out, "канон сверх порождённого") ||
		strings.Contains(out, "порождено сверх канона") {
		t.Errorf("сверка нашла расхождение там, где блоки равны — гейт краснеет на "+
			"законном входе\n%s", out)
	}
}

// TestModelCanonCheckFindsTheModuleWithoutAManifest — отрицание, ставшее
// достижимым ровно со снятием ведомости: модуль закрытого набора, чьего
// манифеста в дереве нет, есть НАХОДКА, а не тихо прощённый.
//
// До снятия ведомости этот вход был неотличим от прощённого, и проверить
// свойство было нечем: исполнитель прощал все шесть.
func TestModelCanonCheckFindsTheModuleWithoutAManifest(t *testing.T) {
	root := syntheticTree(t, "vpc_network", "vpc_subnet")
	if err := os.Remove(filepath.Join(root, "modules", "storage", "manifest.yaml")); err != nil {
		t.Fatalf("снятие манифеста модуля: %v", err)
	}

	code, out := runCheck(t, "-root="+root)

	if code != 1 {
		t.Fatalf("исход %d, ожидался 1: модуль без манифеста и без записи ведомости "+
			"обязан быть находкой\n%s", code, out)
	}
	for _, want := range []string{"storage", "без манифеста и без записи ведомости"} {
		if !strings.Contains(out, want) {
			t.Errorf("находка не называет %q\n%s", want, out)
		}
	}
}

// TestModelCanonCheckFindsTheBlockNobodyRenders — тот же вход со СНЯТЫМ ресурсом:
// исход 1, и находка называет тип и сторону.
func TestModelCanonCheckFindsTheBlockNobodyRenders(t *testing.T) {
	code, out := runCheck(t, "-root="+syntheticTree(t, "vpc_network"))

	if code != 1 {
		t.Fatalf("исход %d, ожидался 1: блок vpc_subnet канона не порождает ничто\n%s", code, out)
	}
	for _, want := range []string{"vpc_subnet", "канон сверх порождённого"} {
		if !strings.Contains(out, want) {
			t.Errorf("находка не называет %q\n%s", want, out)
		}
	}
	// Отличает эту находку от истечения ведомости, которое на том же дереве тоже
	// даёт код 1: без пары чисел исход был бы переопределён, и проба зеленела бы
	// по чужой причине.
	if !strings.Contains(out, "блоков сверено 1 из 2") {
		t.Errorf("перепись не показывает НЕПРОЧИТАННОГО: «сверено 1 из 2» и есть то, "+
			"ради чего знаменатель печатается\n%s", out)
	}
}

// TestModelCanonCheckRefusesAnUnparsableCallWithItsOwnCode — опечатка в вызове
// есть «проверка НЕ ИСПОЛНЯЛАСЬ», а не пустое дерево.
func TestModelCanonCheckRefusesAnUnparsableCallWithItsOwnCode(t *testing.T) {
	code, out := runCheck(t, "-нет-такого-флага")

	if code != 3 {
		t.Fatalf("исход %d, ожидался 3: неразобранный вызов схлопнут в другой исход\n%s", code, out)
	}
	if !strings.Contains(out, "НЕ ИСПОЛНЯЛАСЬ") {
		t.Errorf("отказ не назван словами\n%s", out)
	}
}
