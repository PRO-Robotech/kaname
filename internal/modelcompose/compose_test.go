// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modelcompose_test

// IAM-MB-1-06: тип нового модуля доезжает до ВЕРДИКТА — модельная половина.
//
// Красная сегодня по существу: композиции нет, и модель процесса равна вшитому
// канону, который подопытного типа не объявляет. Это ОТСУТСТВИЕ предмета, а не
// поломка прогона: пакет собирается, канон разбирается, вопрос задаётся и
// получает ответ «тип не объявлен моделью».

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/authzplan"
	"github.com/PRO-Robotech/kacho/internal/treecorpus"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmodel"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelcompose"
)

const probeType = "probemod_alpha"

func TestIAMMB106_TypeDeclaredOnlyByAManifestReachesThePlan(t *testing.T) {
	// КОНТРОЛЬ ПРЕДПОСЫЛКИ: канон подопытного типа НЕ знает. Впиши его
	// кто-нибудь в канон — и проба зеленела бы вхолостую.
	if strings.Contains(authzmodel.DSL, "type "+probeType+"\n") {
		t.Fatalf("канон объявляет %q — предпосылка отпала, проба стала бы вакуумной", probeType)
	}
	// ЗЕРКАЛО: канон знает поставляемого соседа. Без него контроль выше зеленел
	// бы и на каноне, не знающем НИЧЕГО.
	if !strings.Contains(authzmodel.DSL, "type vpc_network\n") {
		t.Fatal("канон не знает vpc_network — контроль предпосылки беспредметен")
	}

	m := &manifest.Manifest{Module: "probemod", Resources: []manifest.Resource{{
		Name:       "alpha",
		ObjectType: probeType,
		Parents:    []manifest.Parent{{Name: "project", Type: "project"}},
		Verbs:      []manifest.Verb{{Name: "get"}},
	}}}

	composed, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	t.Logf("перепись композиции: %s", rep.Census())
	if err != nil {
		t.Fatalf("композиция не состоялась: %v", err)
	}

	// ФОРМА СКЛАДЫВАНИЯ — входное требование §11 приёмки допуска, и оно
	// утверждается ЗДЕСЬ, а не подразумевается: без побайтового префикса канона
	// несущая клауза Д7(а) допуска невыразима.
	if !strings.HasPrefix(composed, authzmodel.DSL) {
		t.Fatal("собранный текст не начинается каноном ПОБАЙТОВО — Д7(а) допуска невыразима")
	}

	// ДОПУСК: err проверяется ПЕРВЫМ (см. #2000 — нулевой отчёт отвечает «допущено»).
	adm, aerr := authzmodel.Admit(composed)
	if aerr != nil {
		t.Fatalf("допуск не состоялся: %v; перепись: %s", aerr, adm.Census())
	}
	if !adm.Admitted() {
		t.Fatalf("композиция не допущена: находок %d; перепись: %s", len(adm.Findings), adm.Census())
	}

	// ВЕРДИКТ (модельная половина): план выразим, а не «тип не объявлен».
	plans, perr := authzmodel.New(composed)
	if perr != nil {
		t.Fatalf("разбор собранной модели: %v", perr)
	}
	plan, cerr := plans.Plan(probeType, "v_get")
	if cerr != nil {
		t.Fatalf("тип, объявленный ТОЛЬКО манифестом, до плана не доехал: %v", cerr)
	}
	if len(plan.Atoms) == 0 {
		t.Fatal("план пуст — «ненулевой ответ» зеленел бы на плане, не дающем права никому")
	}
	t.Logf("тип %q → атомов плана %d", probeType, len(plan.Atoms))

	// ОТРИЦАНИЕ рядом: тип, которого не объявляет НИКТО (IAM-MB-1-08), по-прежнему
	// отвергается СИГНАЛЬНОЙ ошибкой. Без него утверждение выше зеленело бы на
	// модели, отвечающей планом на любой вопрос.
	if _, nerr := plans.Plan(probeType+"_neverdeclared", "v_get"); nerr == nil {
		t.Fatal("тип, которого не объявляет никто, получил план — модель отвечает всем")
	} else if !strings.Contains(nerr.Error(), authzplan.ErrTypeNotDeclared.Error()) {
		t.Fatalf("отказ по необъявленному типу не назвал основания: %v", nerr)
	}
}

// IAM-MB-1-21 (норма §2 п. 9): вырожденное имя типа обязано быть ОТКАЗОМ, а не
// паникой. Паника на пути СТАРТА, вызванная содержимым карты оператора, есть
// цикл падения пода, а не находка.
func TestIAMMB121_ADegenerateTypeNameIsRefusedNotPanicked(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("композиция ПАНИКУЕТ на вырожденном имени типа: %v", p)
		}
	}()
	m := &manifest.Manifest{Module: "probemod", Resources: []manifest.Resource{{
		Name:       "alpha",
		ObjectType: "   ",
		Parents:    []manifest.Parent{{Name: "project", Type: "project"}},
		Verbs:      []manifest.Verb{{Name: "get"}},
	}}}
	_, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	t.Logf("перепись: %s", rep.Census())
	if err == nil {
		t.Fatal("вырожденное имя типа принято — блок без имени уехал бы в модель процесса")
	}
	t.Logf("отказ: %v", err)

	// ЗАКОННЫЙ БЛИЗНЕЦ: годное имя того же модуля проходит. Без него отрицание
	// выше зеленело бы на композиции, отвергающей ВСЁ.
	m.Resources[0].ObjectType = probeType
	if _, _, gerr := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m}); gerr != nil {
		t.Fatalf("законный близнец отвергнут: %v", gerr)
	}
}

// deliveredManifests читает НАСТОЯЩИЕ манифесты дерева — те же, что доставка
// монтирует поду. Синтетика здесь не годится: предмет `IAM-MB-1-01` — тождество
// на СЕГОДНЯШНЕМ дереве, и подставной манифест утверждал бы о другом мире.
func deliveredManifests(t *testing.T) []*manifest.Manifest {
	t.Helper()
	root := repoRoot(t)
	// Состав берётся у ИНДЕКСА git, а не у диска: под services/ на всякой
	// машине, где поднимали стенд, лежит игнорируемое (распаковки чартов,
	// отчёты прогонов), и обход по диску сделал бы вердикт свойством рабочего
	// каталога. Отбор и семантика образца те же, что у filepath.Glob.
	paths, err := treecorpus.Glob(filepath.Join(root, "services", "*", "manifest.yaml"))
	if err != nil {
		t.Fatalf("обход манифестов: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("манифестов не найдено — обход беспредметен: «сошлось» здесь неотличимо от «не прочитано»")
	}
	out := make([]*manifest.Manifest, 0, len(paths))
	for _, p := range paths {
		data, rerr := os.ReadFile(p) // #nosec G304 -- путь выведен обходом дерева, проба
		if rerr != nil {
			t.Fatalf("чтение %s: %v", p, rerr)
		}
		m, lerr := manifest.Load(data)
		if lerr != nil {
			t.Fatalf("загрузка %s: %v", p, lerr)
		}
		out = append(out, m)
	}
	t.Logf("перепись доставки: манифестов прочитано %d", len(out))
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("корень монорепо не найден")
		}
		dir = parent
	}
}

// IAM-MB-1-01: на сегодняшнем дереве композиция — ТОЖДЕСТВО.
//
// Утверждение не косметическое: все типы модулей канон уже объявляет, поэтому
// собранный текст обязан совпасть с каноном ПОБАЙТОВО. Расхождение здесь
// означало бы, что рендер и канон разошлись, — и это находка соседа (#1089),
// а не композиции.
func TestIAMMB101_OnTodaysTreeCompositionIsIdentity(t *testing.T) {
	composed, rep, err := modelcompose.Compose(authzmodel.DSL, deliveredManifests(t))
	t.Logf("перепись композиции: %s", rep.Census())
	if err != nil {
		t.Fatalf("композиция настоящих манифестов не состоялась: %v", err)
	}
	if composed != authzmodel.DSL {
		t.Fatalf("композиция на сегодняшнем дереве НЕ тождество: канон %d Б, собрано %d Б, добавлено %v",
			len(authzmodel.DSL), len(composed), rep.Composed)
	}
	if len(rep.Composed) != 0 {
		t.Fatalf("добавлено %v — на сегодняшнем дереве добавлять нечего", rep.Composed)
	}
	if len(rep.Reaffirmed) == 0 {
		t.Fatal("подтверждено 0 типов — тождество зеленело бы и на композиции, " +
			"не осмотревшей НИ ОДНОГО ресурса")
	}
	t.Logf("тождество: подтверждено типов %d, ресурсов осмотрено %d", len(rep.Reaffirmed), rep.ResourcesSeen)
}

// IAM-MB-1-02: доставки нет — модель равна канону, отказа нет.
func TestIAMMB102_NoDeliveryLeavesTheModelEqualToTheCanon(t *testing.T) {
	composed, rep, err := modelcompose.Compose(authzmodel.DSL, nil)
	if err != nil {
		t.Fatalf("композиция без доставки отвергнута: %v", err)
	}
	if composed != authzmodel.DSL {
		t.Fatal("без доставки собранный текст не равен канону")
	}
	t.Logf("перепись: %s", rep.Census())
}

// IAM-MB-1-03: канон неприкосновенен, и расхождение НАЗЫВАЕТ тип и обе длины.
func TestIAMMB103_ADivergingCanonTypeIsRefusedByName(t *testing.T) {
	// Ресурс объявляет тип, который канон УЖЕ несёт, но с другим составом —
	// значит рендер разойдётся с каноническим блоком.
	m := &manifest.Manifest{Module: "vpc", Resources: []manifest.Resource{{
		Name:       "network",
		ObjectType: "vpc_network",
		Parents:    []manifest.Parent{{Name: "project", Type: "project"}},
		Verbs:      []manifest.Verb{{Name: "get"}},
	}}}
	_, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	t.Logf("перепись: %s", rep.Census())
	if err == nil {
		t.Fatal("расхождение с каноном принято — канон перестал быть неприкосновенным")
	}
	for _, want := range []string{"vpc_network", "канон", "рендер"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("отказ не назвал %q: %v", want, err)
		}
	}
	t.Logf("отказ: %v", err)
}
