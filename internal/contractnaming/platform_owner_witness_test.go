// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_owner_witness_test.go — у ВЛАДЕЛЬЦА ПЛАТФОРМЫ есть свидетель,
// способный упасть (задача kaname#128).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Шапка пакета обещает: «его истинность проверяется не сверкой с тем
// объявлением, а сверкой с КОНТРАКТОМ». Для записи ведомости (`iam` → `kaname`)
// это держит `contractnaming_test.go` дескриптором стаба. Для `platformOwner`
// свидетеля не стало: прежний сверял имя с пакетом `kacho.cloud.operation`, а
// контракт операции переехал под имя фундамента (#98) и был снят собственным
// предикатом истечения. С тех пор `git grep '^package kacho\.cloud' -- proto`
// даёт ПУСТО: в дереве службы не осталось ни одного контракта, которым это имя
// можно подтвердить.
//
// Значение при этом решает, под каким именем служба ищет каталожную запись
// КАЖДОГО модуля платформы. Разойдись оно с действительностью — записи не
// «отвергаются», они НЕ ВИДЯТСЯ: ровно тот отказ, из-за которого пакет и
// заведён (116 записей выпали молча, задача #2168).
//
// ─────────────────────────────────────────────────────────────────────────────
// ГДЕ ВЗЯТ СВИДЕТЕЛЬ, КОГДА СВОИХ КОНТРАКТОВ ПЛАТФОРМЫ В ДЕРЕВЕ НЕТ
//
// В ПОСТАВЛЯЕМОМ каталоге прав. Он приезжает от платформы и несёт полные имена
// методов КАЖДОГО её модуля — то есть тот самый внешний факт, которого в
// контрактах службы нет и быть не может. Свидетель внешний: он меняется без
// участия этого пакета, и в этом его ценность.
//
// ─────────────────────────────────────────────────────────────────────────────
// УТВЕРЖДАЕТСЯ ОТНОШЕНИЕ, А НЕ ЛИТЕРАЛ
//
// Литерал «в каталоге есть kacho» повторял бы проверяемое и согласился бы с
// любой редакцией. Утверждается связь: ДЛЯ КАЖДОГО модуля, названного
// каталогом, владелец из записи каталога совпадает с тем, что называет
// `contractnaming.Owner`. Плюс предпосылка — модуль, владельца которому даёт
// именно `platformOwner`, в каталоге ЕСТЬ: без неё проверка молчала бы на
// каталоге, где платформы нет вовсе, и `platformOwner` снова остался бы без
// свидетеля.
package contractnaming_test

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"

	"github.com/PRO-Robotech/kaname/internal/contractnaming"
)

// catalogOwnerFindings — расхождения владельца между каталогом и ведомостью.
// Вынесено функцией: инъекция зовёт ТОТ ЖЕ предикат.
func catalogOwnerFindings(fqns []string) (findings []string, byOwner map[string]int, modules map[string]string) {
	byOwner = map[string]int{}
	modules = map[string]string{}
	for _, fqn := range fqns {
		// Форма записи: `<владелец>.cloud.<модуль>.v1.<Служба>/<Метод>`. Службы
		// фундамента (`corelib.operation.…`) модулем платформы не являются — их
		// разбор обязан отличать, а не отбрасывать.
		pkg := fqn
		if i := strings.LastIndex(fqn, "/"); i >= 0 {
			pkg = fqn[:i]
		}
		if i := strings.LastIndex(pkg, "."); i >= 0 {
			pkg = pkg[:i] // отрезали имя службы
		}
		owner, module, ok := contractnaming.Split(pkg)
		if !ok {
			continue
		}
		byOwner[owner]++
		if prev, seen := modules[module]; seen && prev != owner {
			findings = append(findings, "модуль "+module+": каталог называет двух владельцев — "+
				prev+" и "+owner)
		}
		modules[module] = owner
		if want := contractnaming.Owner(module); want != owner {
			findings = append(findings, "модуль "+module+": каталог называет владельцем "+owner+
				", ведомость — "+want)
		}
	}
	sort.Strings(findings)
	return findings, byOwner, modules
}

// TestPlatformOwnerIsTheOneTheDeliveredCatalogDeclares — сам свидетель.
func TestPlatformOwnerIsTheOneTheDeliveredCatalogDeclares(t *testing.T) {
	reg, err := seed.LoadPermissionRegistry(context.Background(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: поставляемый каталог прав не прочитан: %v", err)
	}
	entries := reg.All()
	fqns := make([]string, 0, len(entries))
	for _, e := range entries {
		fqns = append(fqns, e.FQN)
	}

	findings, byOwner, modules := catalogOwnerFindings(fqns)
	t.Logf("перепись: записей каталога прочитано %d, из них разобрано в пару "+
		"владелец/модуль %d; по владельцам: %v; модулей названо %d",
		len(fqns), sum(byOwner), byOwner, len(modules))

	if len(fqns) == 0 {
		t.Fatalf("каталог пуст — свидетеля нет, и его молчание сказано ни о чём")
	}
	if sum(byOwner) == 0 {
		t.Fatalf("ни одна запись каталога не разобралась в пару владелец/модуль на %d "+
			"записях — разбор перестал видеть предмет", len(fqns))
	}

	// ПРЕДПОСЫЛКА: платформа в каталоге ЕСТЬ. Без неё проверка ниже проходит на
	// каталоге, где `platformOwner` не участвует вовсе, — и значение снова
	// остаётся без свидетеля, при зелёном прогоне.
	own := contractnaming.PlatformOwner()
	if byOwner[own] == 0 {
		t.Fatalf("в поставляемом каталоге НЕТ НИ ОДНОЙ записи владельца %q, а модули "+
			"платформы объявлены принадлежащими ему. Либо имя разошлось с действительностью "+
			"— и тогда записи платформы служба не ВИДИТ (не отвергает, а не видит, #2168), — "+
			"либо каталог перестал нести платформу, и свидетеля больше нет.\n"+
			"По владельцам каталог называет: %v", own, byOwner)
	}

	if len(findings) > 0 {
		t.Fatalf("владелец, объявленный здесь, разошёлся с поставляемым каталогом — "+
			"%d находк(и):\n  %s\n\n"+
			"Каталог приезжает ОТ ПЛАТФОРМЫ и является внешним фактом: он меняется без "+
			"участия этого пакета, и в этом его ценность как свидетеля.",
			len(findings), strings.Join(findings, "\n  "))
	}

	var named []string
	for m, o := range modules {
		named = append(named, o+"."+m)
	}
	sort.Strings(named)
	t.Logf("каталог подтверждает владельцев: %s", strings.Join(named, ", "))
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
