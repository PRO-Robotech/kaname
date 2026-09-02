// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package tools_regression

import (
	"os"
	"os/exec"
	"path/filepath"
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
				sb.WriteString("    parent: project\n")
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

// TestModelCanonCheckOnTheRealTreeIsVoidAndSaysSo — дерево продукта: манифестов в
// нём НОЛЬ, поэтому сверять нечего ни для одного модуля.
//
// Исход 2, а не 0: «ноль находок» обязано быть отличимо от «ноль прочитанного», и
// именно код читает оболочка. Перепись печатается ВСЕГДА — иначе VOID неотличим
// от успеха по виду вывода.
func TestModelCanonCheckOnTheRealTreeIsVoidAndSaysSo(t *testing.T) {
	code, out := runCheck(t)

	if code != 2 {
		t.Fatalf("исход %d, ожидался 2 (VOID): манифестов в дереве ноль\n%s", code, out)
	}
	for _, want := range []string{"перепись:", "модулей набора 6", "прощено ведомостью 6", "сверять нечего"} {
		if !strings.Contains(out, want) {
			t.Errorf("вывод не называет %q — VOID неотличим от успеха по виду вывода\n%s", want, out)
		}
	}
}

// TestModelCanonCheckComparesEveryOwnedBlockAndTheLedgerExpires — положительный
// контроль, и он двойной: сверка ПРОШЛА и ведомость ИСТЕКЛА.
//
// Дерево несёт манифесты всех шести модулей, и манифест vpc объявляет ОБА своих
// блока. Наблюдаемое:
//
//   - «сверено 2 из 2» — сверка дошла до блоков и расхождений не нашла НИ ОДНОГО.
//     Это и есть половина «гейт умеет молчать»: находки о блоках отсутствуют;
//   - шесть находок «прощать нечего» — ведомость исполнителя описывает ДЕРЕВО
//     ПРОДУКТА, где манифестов ноль, и на дереве, где они есть, каждая её запись
//     теряет предмет. Послабление, которое не истекает, не истекло бы никогда.
//
// Исход 1, а не 0, и это не слабость пробы: код 0 у исполнителя становится
// достижим ровно тогда, когда ведомость опустеет вместе с приездом манифестов
// (#1091), и переход этот ВЫНУЖДЕН — шесть находок ниже требуют снять записи тем
// же изменением. Что сам обход отдаёт 0 на таком входе, утверждает проба пакета
// TestTheSameTreeWithTheResourceDeclaredIsSilent; здесь судится исполнитель.
func TestModelCanonCheckComparesEveryOwnedBlockAndTheLedgerExpires(t *testing.T) {
	code, out := runCheck(t, "-root="+syntheticTree(t, "vpc_network", "vpc_subnet"))

	if code != 1 {
		t.Fatalf("исход %d, ожидался 1: ведомость обязана истечь на дереве с манифестами\n%s", code, out)
	}
	if !strings.Contains(out, "блоков сверено 2 из 2") {
		t.Errorf("перепись не называет ни сверенного, ни ожидаемого: без пары чисел "+
			"«сверено 0» неотличимо от «сверять было нечего»\n%s", out)
	}
	for _, m := range []string{"iam", "vpc", "compute", "loadbalancer", "registry", "storage"} {
		if !strings.Contains(out, "модуль "+m+": запись ведомости пережила свой предмет") {
			t.Errorf("запись ведомости на модуль %s не истекла: послабление без "+
				"самоистечения не снимет никто\n%s", m, out)
		}
	}
	if strings.Contains(out, "канон сверх порождённого") ||
		strings.Contains(out, "порождено сверх канона") {
		t.Errorf("сверка нашла расхождение там, где блоки равны — гейт краснеет на "+
			"законном входе\n%s", out)
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
