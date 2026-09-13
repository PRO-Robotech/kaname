// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// standalonedelivery_test.go — дерево, не несущее манифестов соседних модулей,
// даёт «проверка НЕ ИСПОЛНЯЛАСЬ», а не находку о продукте.
//
// # ПРИЗНАК СМЕНЁН — И ПРЕЖНЯЯ РЕДАКЦИЯ ЭТОГО ФАЙЛА БЫЛА ЗЕЛЕНА НАД МЁРТВОЙ ВЕТВЬЮ
//
// Здесь стояла пара, чей различающий факт был «откуда прочитан канон»: из дерева
// контрактов либо из копии, которую модуль везёт с собой. Пара была верна ровно
// до переезда контрактов: `proto/kaname/cloud/iam/v1/fga_model.fga` лежит теперь
// В ЭТОМ дереве, первая ветвь резолва выигрывает всегда, и различитель стал ложен
// при любом входе (задача PRO-Robotech/kaname#56).
//
// Пробы этого не показали НИ ОДНОЙ: они строили дерево сами и клали канон по
// везомой координате, поэтому оставались зелёными независимо от того, что лежит в
// настоящем дереве. Это класс `testing.md` §«Гейт на класс», п. 9: инъекция
// подаёт вход сама и о производстве предмета не утверждает ничего.
//
// # ЧТО РАЗЛИЧАЕТ ПАРУ ТЕПЕРЬ — ОДИН ФАКТ, И ОН О ПРЕДМЕТЕ ПОСЛАБЛЕНИЯ
//
// Послабление прощает отсутствие МАНИФЕСТОВ СОСЕДЕЙ, значит спрашивать надо про
// их дом — каталог `services/` дерева платформы:
//
//	дома нет  + нет манифестов соседей → 3 (условие не создано);
//	дом ЕСТЬ  + нет манифестов соседей → 1 (находка);
//	дома нет  + РАСХОЖДЕНИЕ блоков     → 1 (находка).
//
// Второй случай — законный близнец первого: без него послабление зеленело бы на
// всяком дереве без манифестов, включая платформенное с удалённым манифестом
// соседа. Третий — вторая сторона той же оси: послабление не вправе накрывать
// сверку, которая ДОШЛА и нашла расхождение.
//
// # ЧИТАЕТСЯ ЛИ ПРОБА ДЕРЕВОМ РЕПОЗИТОРИЯ, А НЕ ТОЛЬКО СИНТЕТИКОЙ
//
// Отдельным утверждением внизу: исполнитель, позванный НА ЭТОМ дереве, обязан
// отвечать третьим исходом, а не находкой о продукте. Без него весь файл
// по-прежнему доказывал бы, что разбор понимает синтетику.
package modelrender_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// TestStandaloneDeliveryIsNotRunNotAFinding — ИНЪЕКЦИЯ.
func TestStandaloneDeliveryIsNotRunNotAFinding(t *testing.T) {
	root := noSiblingsHomeTree(t, twoBlockCanon)
	writeManifest(t, root, "vpc", manifestFor("vpc", "vpc_network", "vpc_subnet"))

	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepNotRun {
		t.Fatalf("исход %d, ожидался %d (проверка НЕ ИСПОЛНЯЛАСЬ): дома манифестов соседних "+
			"модулей в этом дереве нет, и красное о них есть вердикт о продукте там, где "+
			"вердикта нет.\nперепись: %s\nнаходки: %v",
			code, modelrender.SweepNotRun, census, findings)
	}
	if len(findings) != 1 {
		t.Fatalf("исход назван %d строками, ожидалась одна: %v", len(findings), findings)
	}
	got := findings[0].String()
	for _, want := range []string{"условие сверки НЕ СОЗДАНО", treeposture.SiblingsDir} {
		if !strings.Contains(got, want) {
			t.Errorf("строка исхода не называет предпосылки (%q): %s", want, got)
		}
	}
	if strings.HasPrefix(got, "модуль ") {
		t.Errorf("строка исхода приписана модулю, которого не назвали: %s — читатель "+
			"ищет виновника там, где его нет", got)
	}
}

// TestSiblingsHomePresentKeepsTheMissingManifestAFinding — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// Отличие от инъекции выше РОВНО ОДНО: в дереве заведён дом манифестов соседей.
// Значит соседи сюда поставляются, и отсутствие манифеста — находка.
func TestSiblingsHomePresentKeepsTheMissingManifestAFinding(t *testing.T) {
	root := noSiblingsHomeTree(t, twoBlockCanon)
	writeManifest(t, root, "vpc", manifestFor("vpc", "vpc_network", "vpc_subnet"))
	withSiblingsHome(t, root)

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d: дом манифестов соседей ЕСТЬ, значит отсутствие "+
			"манифеста — находка, и послабление её накрывать не вправе. Без этого "+
			"утверждения послабление зеленело бы и на платформенном дереве с удалённым "+
			"манифестом соседа", code, modelrender.SweepFinding)
	}
	if len(findings) == 0 {
		t.Fatal("находок ноль при исходе «находка» — вердикт себе противоречит")
	}
}

// TestStandaloneDeliveryStillReportsARealMismatch — ВТОРАЯ СТОРОНА оси.
//
// Отличие от инъекции РОВНО ОДНО: сверка ДОШЛА до блоков и нашла расхождение.
// Послабление накрывает только «манифестов соседей нет», и ничего сверх этого.
func TestStandaloneDeliveryStillReportsARealMismatch(t *testing.T) {
	root := noSiblingsHomeTree(t, twoBlockCanon)
	// Манифест объявляет блок, которого в каноне нет: расхождение НАСТОЯЩЕЕ.
	writeManifest(t, root, "vpc", manifestFor("vpc", "vpc_network", "vpc_nosuchblock"))

	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, nil)

	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидался %d: сверка дошла до блоков и нашла расхождение — "+
			"послабление самостоятельной поставки его накрывать не вправе.\nнаходки: %v",
			code, modelrender.SweepFinding, findings)
	}
}

// TestShippedCopyResolvesWhenContractsAreAbsent — ВТОРАЯ ВЕТВЬ РЕЗОЛВА ЖИВА.
//
// Прежде эта фикстура работала различителем посадки и потому доказывала не то,
// что нужно. Её настоящий предмет остался и назван прямо: поставка БЕЗ каталога
// контрактов (архив без `proto/`, образ с одним двоичным) канон всё равно несёт —
// копией, которую модуль везёт с собой, — и резолв обязан её отдать.
//
// Снять эту ветвь значило бы вернуть красное тем, у кого текст модели есть, а
// каталога контрактов нет.
func TestShippedCopyResolvesWhenContractsAreAbsent(t *testing.T) {
	root := t.TempDir()
	dst := filepath.Join(root, filepath.FromSlash(authzplan.ShippedModelRelPath()))
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		t.Fatalf("каталог копии канона: %v", err)
	}
	if err := os.WriteFile(dst, []byte(twoBlockCanon), 0o600); err != nil {
		t.Fatalf("запись копии канона: %v", err)
	}

	path, dsl, err := authzplan.ResolveCanonicalModelFrom(root)
	if err != nil {
		t.Fatalf("канон не резолвится там, где копия модуля ЕСТЬ: %v — тогда всякий, кто "+
			"получил поставку без каталога контрактов, читает красное о продукте", err)
	}
	if path != dst {
		t.Fatalf("резолв отдал %s, ожидалась везомая копия %s", path, dst)
	}
	if string(dsl) != twoBlockCanon {
		t.Fatalf("прочитано не то содержимое: %d байт против %d", len(dsl), len(twoBlockCanon))
	}
}

// TestThisTreeItselfIsJudgedNotRun — ПРОБА ВЕДЁТ ПО ДЕРЕВУ РЕПОЗИТОРИЯ, а не
// только по `t.TempDir()`.
//
// Утверждение узкое и потому проверяемое: в дереве, где дома манифестов соседей
// нет, исполнитель отвечает ТРЕТЬИМ исходом. Обе посадки законны и обязаны
// РАЗЛИЧАТЬСЯ: в платформенном дереве (и в конвейере, где выборка платформы
// лежит под корнем обхода) дом есть, и там ветвь послабления НЕДОСТИЖИМА.
func TestThisTreeItselfIsJudgedNotRun(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	moduleRoot, merr := treeposture.ModuleRootFrom(wd)
	if merr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", merr)
	}

	census, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, moduleRoot, nil)

	home := siblingsHomeOf(t, moduleRoot)
	if home == "" {
		if code != modelrender.SweepNotRun {
			t.Fatalf("дома манифестов соседей (%s/) в дереве %s НЕТ, а исполнитель ответил %d "+
				"вместо %d: всякий, кто склонирует службу и позовёт сверку, читает КРАСНОЕ О "+
				"ПРОДУКТЕ там, где красного нет.\nперепись: %s\nнаходки: %v",
				treeposture.SiblingsDir, moduleRoot, code, modelrender.SweepNotRun, census, findings)
		}
		t.Logf("посадка: дома манифестов соседей нет (%s) — исход 3, вердикта о совпадении "+
			"блоков НЕТ ни зелёного, ни красного. перепись: %s", moduleRoot, census)
		return
	}
	if code == modelrender.SweepNotRun {
		t.Fatalf("дом манифестов соседей НАЙДЕН (%s), а исполнитель объявил условие "+
			"несозданным — послабление достижимо там, где сверять есть с чем.\nперепись: %s",
			home, census)
	}
	t.Logf("посадка: дом манифестов соседей найден (%s) — ветвь послабления НЕДОСТИЖИМА, "+
		"исход %d. перепись: %s", home, code, census)
}

// siblingsHomeOf — есть ли в дереве дом манифестов соседей. Отдельный, САМЫЙ
// простой читатель того же факта: совпади он с ответом исполнителя по построению,
// утверждение выше было бы тождеством и не проверяло бы ничего.
func siblingsHomeOf(t *testing.T, root string) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && len(name) > 1 && name[0] == '.' {
				return filepath.SkipDir
			}
			if name == treeposture.SiblingsDir {
				found = path
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход дерева %s отказал: %v", root, err)
	}
	return found
}
