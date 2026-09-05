// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// plane_agreement_has_a_subject_test.go — сверка плоскости на ДЕРЕВЕ судит
// различающийся вход, а не сравнивает `false` с `false`.
//
// ПРЕДМЕТ. Плоскость действия объявлена дважды: разделом `resources` (ключ
// `internal`) и каталогом прав (приставка `Internal` у имени службы). Два
// объявления одного предмета обязаны сверяться, и сверка (CheckActionLinkage)
// исправна — её способность падать доказана инъекцией в linkage_test.go.
//
// Но предмета у неё не было. Замер #1997: раздел `resources` НИ ОДНОГО
// манифеста дерева не объявлял ни одного внутреннего действия при 101 внутренней
// записи каталога — то есть каждая пара сравнивала `false` с `false`. Исправная
// и беспредметная разом, и отличить это от работающей проверки было НЕЧЕМ:
// `PlaneDisagrees == 0` печатается одинаково в обоих случаях.
//
// ПОЧЕМУ ЭТО ГЕЙТ ДЕРЕВА, А НЕ ПРОБА НА СИНТЕТИКЕ. Синтетический манифест с
// внутренним действием сверку удовлетворяет всегда — его пишет сама проба.
// Утверждение здесь о ДЕРЕВЕ: что поставляемые манифесты плоскость объявляют, а
// значит у сверки есть что сверять. Свойство дерева держится гейтом по дереву.
//
// ЧТО ГЕЙТ НЕ УТВЕРЖДАЕТ. Не «объявлены ВСЕ внутренние действия каталога»: часть
// из них принадлежит ресурсам, которых раздел не объявляет вовсе (`nodeOwnership`,
// `cluster`, `storageBackend`, …), и объявить их значило бы завести запись
// ресурса, порождающую в модели блок типа сверх канона. Это отдельный предмет со
// своим предикатом. Здесь утверждается, что предмет у сверки ЕСТЬ.
package roleexport_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest/roleexport"
)

// minManifestsRead — пол переписи: не про размер дерева, а про то, что обход
// вообще что-то прочитал. Пустой обход даёт ноль находок так же убедительно,
// как полное согласие сторон.
const minManifestsRead = 5

func TestPlaneAgreementJudgesADifferingInputOnTheTree(t *testing.T) {
	// `../../../..` от этого пакета — каталог `services` монорепо.
	paths, err := filepath.Glob(filepath.Join("../../../..", "*", "manifest.yaml"))
	if err != nil {
		t.Fatalf("обход дерева: %v", err)
	}
	if len(paths) < minManifestsRead {
		t.Fatalf("прочитано манифестов %d при пороге %d — обход пуст либо усечён, "+
			"вердикт беспредметен", len(paths), minManifestsRead)
	}

	reg, err := seed.LoadPermissionRegistry(context.Background(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("каталог прав не прочитан: %v", err)
	}
	entries := make([]roleexport.CatalogEntry, 0)
	for _, r := range reg.All() {
		entries = append(entries, roleexport.CatalogEntry{
			FQN:              r.FQN,
			RequiredRelation: r.RequiredRelation,
			ScopeObjectType:  r.ScopeExtractor.ObjectType,
		})
	}
	actions, _ := roleexport.Attribute(entries)
	if len(actions) == 0 {
		t.Fatal("каталог не дал ни одного действия — сверять нечем")
	}

	var (
		read            int
		verbs           int
		matched         int
		matchedInternal int
		disagreed       int
		declaring       []string
	)
	for _, p := range paths {
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			t.Fatalf("%s: %v", p, rerr)
		}
		m, lerr := manifest.Load(body)
		if lerr != nil {
			t.Fatalf("%s: манифест не разобран: %v", p, lerr)
		}
		read++
		faults, census := roleexport.CheckActionLinkage(m, actions)
		verbs += census.ManifestVerbs
		matched += census.Matched
		matchedInternal += census.MatchedInternal
		disagreed += census.PlaneDisagrees
		if census.MatchedInternal > 0 {
			declaring = append(declaring, filepath.Base(filepath.Dir(p)))
		}
		for _, f := range faults {
			t.Errorf("%s: находка соединения: %v", p, f)
		}
	}

	if read < minManifestsRead {
		t.Fatalf("разобрано манифестов %d при пороге %d", read, minManifestsRead)
	}
	if matchedInternal == 0 {
		t.Errorf("сопоставленных пар внутренней плоскости НОЛЬ при %d сопоставленных всего: "+
			"сверка плоскости сравнивает `false` с `false` на каждой паре — она исправна и "+
			"беспредметна разом, и «расхождений 0» здесь неотличимо от «сравнивать было "+
			"нечем». Объявите плоскость в разделе `resources` тех действий, которые каталог "+
			"знает внутренними (ключ `internal: true` длинной формы)", matched)
	}
	if disagreed != 0 {
		t.Errorf("расхождений плоскости %d — манифест и каталог объявляют разное об одном "+
			"действии", disagreed)
	}

	t.Logf("осмотрено: манифестов %d · действий раздела %d · сопоставлено %d · "+
		"из них внутренней плоскости %d · расхождений %d · объявляют плоскость: %v",
		read, verbs, matched, matchedInternal, disagreed, declaring)
}

// namedByMODRL19 — внутренние действия, которые называют оси MOD-RL-19 (ось Б) и
// второй положительный MOD-RL-19a. Пара «ресурс, действие» — та же, которой их
// знает каталог прав.
var namedByMODRL19 = []struct{ resource, verb string }{
	{"network", "internalGetNetwork"},
	{"networkInterface", "internalAttach"},
	{"networkInterface", "internalDetach"},
}

// TestMODRL19InternalAxesHaveAnInputInTheTree — оси MOD-RL-19, называющие
// внутренние действия, имеют вход в ПОСТАВЛЯЕМОМ манифесте, а не только в
// самодостаточном манифесте своей пробы.
//
// ПРЕДМЕТ. Шапка `namedRoleManifest` (namedverbs_test.go) объявляла расхождение
// с приёмкой: приёмка считала эти оси по черновику воркспейса, а дерево
// внутренних действий не объявляло, поэтому вход осей приходилось писать в самой
// пробе. Расхождение снято (#1997), и снятие обязано быть УТВЕРЖДЕНО, а не
// записано словами: иначе следующая правка манифеста вернёт прежнее состояние, а
// шапка продолжит сообщать, что расхождения нет.
//
// ЧЕМ ЭТО НЕ ЯВЛЯЕТСЯ. Проба не требует, чтобы фикстуры MOD-RL-19 читали дерево:
// они объявляют ещё и РОЛЬ с поимённым правом, которой поставляемый манифест не
// несёт. Утверждается ровно то, что оси не выдуманы — их действия в дереве есть.
func TestMODRL19InternalAxesHaveAnInputInTheTree(t *testing.T) {
	const rel = "../../../../vpc/manifest.yaml"
	body, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("поставляемый манифест vpc не прочитан: %v", err)
	}
	m, err := manifest.Load(body)
	if err != nil {
		t.Fatalf("поставляемый манифест vpc не разобран: %v", err)
	}
	if len(m.Resources) == 0 {
		t.Fatal("ресурсов в манифесте ноль — предмет пуст, вердикт беспредметен")
	}

	declared := map[string]bool{}
	verbs := 0
	for _, r := range m.Resources {
		for _, v := range r.Verbs {
			verbs++
			if v.Internal {
				declared[r.Name+"."+v.Name] = true
			}
		}
	}

	for _, a := range namedByMODRL19 {
		key := a.resource + "." + a.verb
		if !declared[key] {
			t.Errorf("ось MOD-RL-19 называет %q, а поставляемый %s его внутренним действием "+
				"НЕ объявляет: вход оси существует только в её собственной пробе, и шапка "+
				"`namedRoleManifest`, утверждающая обратное, стала ложью", key, rel)
		}
	}

	t.Logf("осмотрено: %s · ресурсов %d · действий %d · внутренних %d · осей проверено %d",
		rel, len(m.Resources), verbs, len(declared), len(namedByMODRL19))
}
