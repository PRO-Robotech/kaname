// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// model_compose_test.go — модель процесса СОБИРАЕТСЯ из доставленного и
// СТАВИТСЯ до первого чтения (задачи продукта #1969, #2002).
//
// # Почему проба живёт здесь, а не у владельцев звеньев
//
// Замок, который она стережёт, не принадлежит ни одному звену по отдельности:
// разбор доставки был исправен, установка была исправна, неисполним был их
// ПОРЯДОК. Такой класс ловится только сквозным вызовом — обе половины по
// отдельности зелены (`multi-agent-flow.md` §14, столкновение смыслов).
//
// # Почему проба ОДНА, а не две
//
// Установка модели процесса необратима в пределах процесса: второй установки не
// существует, а первое чтение её запрещает. Значит утверждать о ней вправе ровно
// одна проба бинаря — две делили бы одно состояние и роняли бы друг друга
// порядком, который никто не объявлял. Поэтому обе половины (замок #2002 и
// провязка #1969) утверждаются ОДНОЙ последовательностью — той же, что исполняет
// старт.
//
// # Почему собственный тестовый бинарь важен
//
// Признак «модель уже прочитана» — состояние ПРОЦЕССА. В одном бинаре пробы
// делят его, поэтому проба о первом чтении обязана быть единственной, кто до
// него доходит. Пакет `main` службы к `authzmodel` не обращался ни одним
// файлом до этой работы (предикат: `git grep -l authzmodel --
// 'services/iam/cmd/kaname/*'` → пусто), значит здесь состояние чистое.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// deliveryDeclaringRelationGrant — манифест, объявляющий НЕПУСТОЙ
// `seed.accessBindings[].grantedRelation`.
//
// Вход выбран не произвольно: ровно на нём разбор доставки доходил до
// `authzmodel.Shared()`. Манифест без этого ключа проходил и ДО работы, и
// ПОСЛЕ — проба на нём была бы вакуумной (сценарий `IAM-MB-1-17`, §11.3
// приёмки #1969: таких манифестов в дереве 2 из 6).
const deliveryDeclaringRelationGrant = `apiVersion: iam/v1
module: vpc
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: kacho-system
      description: "Module SA: kacho-vpc (SEC-C least-priv)"
  accessBindings:
    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: system_viewer
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
`

// deliveryWithoutRelationGrant — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к предпосылке: манифест
// без выдачи отношением. Он не доходил до модели и до этой работы, поэтому
// доказывает, что предпосылка пробы выше измеряет именно выдачу отношением, а
// не «любой манифест».
const deliveryWithoutRelationGrant = `apiVersion: iam/v1
module: loadbalancer
`

// newObjectType — тип, которого канон образа не объявляет. Живёт константой,
// потому что о нём утверждают трижды: предпосылка (канон его не знает), исход
// (модель процесса знает) и вердикт (план по нему непуст).
const newObjectType = "vpc_widget"

// deliveryDeclaringANewType — манифест, объявляющий РЕСУРС нового типа.
const deliveryDeclaringANewType = `apiVersion: iam/v1
module: vpc
resources:
  - name: widget
    objectType: ` + newObjectType + `
    parents: [project]
    producer: derived
    verbs:
      - get
      - list
      - update
      - delete
`

// TestBootComposesJudgesAndInstallsTheModel — вся последовательность старта:
// чтение доставки → композиция → допуск → установка → вердикт.
//
// Утверждаются обе половины сразу, и это не смешение предметов, а единственная
// возможная форма: установка модели процесса необратима, поэтому вправе быть
// исполнена ровно один раз за бинарь (см. шапку файла).
func TestBootComposesJudgesAndInstallsTheModel(t *testing.T) {
	// Предпосылка: вход и вправду тот, о котором проба. Манифест обязан
	// разобраться — иначе «установка прошла» означало бы лишь то, что разбор
	// сорвался раньше, чем дошёл бы до модели.
	m, err := manifest.Load([]byte(deliveryDeclaringRelationGrant))
	if err != nil {
		t.Fatalf("предпосылка не создана: манифест с grantedRelation не разобрался: %v", err)
	}
	if len(m.Seed.AccessBindings) != 1 || strings.TrimSpace(m.Seed.AccessBindings[0].GrantedRelation) == "" {
		t.Fatalf("предпосылка не создана: вход обязан нести НЕПУСТОЙ grantedRelation, получено %+v",
			m.Seed.AccessBindings)
	}

	// Положительный контроль предпосылки: манифест БЕЗ выдачи отношением тоже
	// разбирается. Без него проба не отличала бы «разбор не читает модель» от
	// «разбор вообще ничего не делает».
	if _, err := manifest.Load([]byte(deliveryWithoutRelationGrant)); err != nil {
		t.Fatalf("контроль: манифест без grantedRelation обязан разбираться: %v", err)
	}

	// ── СУТЬ 1 (#2002): замок разомкнут ──────────────────────────────────────
	//
	// Разбор доставки прошёл выше и модель процесса НЕ прочитал, поэтому
	// композиция ещё вправе её поставить. До #2002 здесь приезжал
	// ErrModelAlreadyRead, и никакого порядка, при котором композиция встаёт, не
	// существовало.
	//
	// ── СУТЬ 2 (#1969): провязка есть, и тип доставки доезжает до вердикта ────
	//
	// Манифест несёт ресурс, чьего типа канон образа НЕ объявляет.
	//
	// ЗДЕСЬ СТОЯЛ ОБХОД: манифест читался референтом ПОРОЖДЕНИЯ
	// (`manifest.ReferentCanon`) с доводом «закрытая таблица типов — продукт
	// сборки, и судить ею новый тип значило бы спрашивать у ответа». Довод был
	// верен, а обход был ЛОЖНЫМ вердиктом о старте: доставка читается на старте
	// умолчанием (`manifest.LoadDelivered`), и вход, проходивший только под
	// чужим референтом, на старте не прошёл бы. Задача #2015 сняла предмет
	// целиком — таблица типов разомкнута, новый тип модуля принимается ТОЙ ЖЕ
	// полосой, что читает доставку, — поэтому здесь стоит `manifest.Load`, и
	// проба утверждает о пути старта, а не о его обходе.
	mNew, err := manifest.Load([]byte(deliveryDeclaringANewType))
	if err != nil {
		t.Fatalf("предпосылка не создана: манифест с новым типом не разобрался ПОЛОСОЙ "+
			"СТАРТА: %v", err)
	}

	// Предпосылка провязки: канон образа этого типа НЕ объявляет. Без неё проба
	// зеленела бы на типе, который и так был в каноне, ничего не утверждая о
	// композиции.
	canon, cerr := authzmodel.New(authzmodel.DSL)
	if cerr != nil {
		t.Fatalf("канон образа не разобран: %v", cerr)
	}
	if canon.DeclaresType(newObjectType) {
		t.Fatalf("предпосылка не создана: тип %q канон образа УЖЕ объявляет — "+
			"проба обязана брать тип, которого в каноне нет", newObjectType)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := installComposedModel(logger, []*manifest.Manifest{m, mNew}); err != nil {
		t.Fatalf("композиция → допуск → установка отвергнута на пути старта: %v", err)
	}

	// ── вердикт: синтетический вопрос по типу доставки даёт НЕНУЛЕВОЙ ответ ──
	//
	// Утверждается ИСХОД вопроса, а не факт установки: «модель поставлена» верно
	// и при модели, которая о новом типе не знает.
	plans, perr := authzmodel.Shared()
	if perr != nil {
		t.Fatalf("модель процесса не отдалась после установки: %v", perr)
	}
	if !plans.DeclaresType(newObjectType) {
		t.Fatalf("тип %q объявлен ТОЛЬКО манифестом и до модели процесса не доехал — "+
			"композиция собрала не то, что поставила", newObjectType)
	}
	plan, planErr := plans.Plan(newObjectType, "v_get")
	if planErr != nil {
		t.Fatalf("вердикт по типу доставки не строится: %v", planErr)
	}
	if len(plan.Atoms) == 0 {
		t.Fatalf("план по %q.v_get ПУСТ — вердикт по нему не дал бы ни одного права, "+
			"молча; ответ обязан быть ненулевым", newObjectType)
	}
	if !plan.Expressible() {
		t.Fatalf("план по %q.v_get невыразим целиком (%v) — вердикт по такому давать нельзя",
			newObjectType, plan.Unclassified)
	}

	// Отрицание в паре: тип, которого не объявляет НИКТО, по-прежнему отвергается.
	// Без него «доезжает до вердикта» зеленело бы на модели, объявляющей типом
	// что угодно.
	if _, err := plans.Plan("no_such_type_declared_by_nobody", "v_get"); err == nil {
		t.Fatal("тип, которого не объявляет ни канон, ни доставка, обязан отвергаться")
	}
}

// TestServeInstallsTheComposedModelBetweenDeliveryAndItsFirstReader — провязка
// ПОЗВАНА, и позвана в объявленном порядке.
//
// Своя проба у композиции ничего не говорит о том, зовёт ли её композиционный
// корень: функция, объявленная и не позванная, есть мёртвый страж — служба
// поднимается, называя себя собранной, и модель остаётся вшитым каноном.
//
// Порядок здесь — половина предмета, а не оформление. Окно у установки ровно
// одно: позже доставки, из которой модель собирается, и раньше первого её
// читателя, потому что установка после первого чтения запрещена. Проба
// утверждает ближнюю границу окна (доставка), дальнюю держит сам замок — он
// отвечает отказом, а не молчанием.
func TestServeInstallsTheComposedModelBetweenDeliveryAndItsFirstReader(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, 0)
	if err != nil {
		t.Fatalf("serve.go не разобран: %v — непрочитанное есть НАХОДКА", err)
	}

	var deliveryPos, installPos token.Pos
	var callsSeen int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callsSeen++
		fn, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		switch {
		case fn.Name == "loadDeliveredManifests" && !deliveryPos.IsValid():
			deliveryPos = call.Pos()
		case fn.Name == "installComposedModel" && !installPos.IsValid():
			installPos = call.Pos()
		}
		return true
	})

	// Объём осмотренного печатается ВСЕГДА: «ноль находок» обязано быть отличимо
	// от «ноль прочитанного».
	t.Logf("осмотрено вызовов в serve.go: %d", callsSeen)
	if callsSeen == 0 {
		t.Fatal("обход не нашёл ни одного вызова — вердикт беспредметен")
	}
	if !installPos.IsValid() {
		t.Fatal("serve.go не зовёт installComposedModel — композиция объявлена и не исполняется " +
			"на пути старта: модель процесса остаётся вшитым каноном, а доставленные типы " +
			"не доезжают до вердикта вовсе")
	}
	if !deliveryPos.IsValid() {
		t.Fatal("serve.go не зовёт loadDeliveredManifests — предпосылка проверки о порядке " +
			"исчезла, и порядок больше нечем судить")
	}
	if installPos < deliveryPos {
		t.Errorf("модель собирается РАНЬШЕ чтения доставки (%s против %s) — "+
			"собирать было бы не из чего",
			fset.Position(installPos), fset.Position(deliveryPos))
	}
}

// deliveryWithWildcardSubject — ресурс НОВОГО типа, чей состав субъектов несёт
// подстановку. Допуск обязан назвать это находкой: подстановка на новом типе
// раздаёт право всякому аутентифицированному, а сужением это не является вовсе
// (`security.md` §«Отношение, выполнимое подстановочным знаком»).
const deliveryWithWildcardSubject = `apiVersion: iam/v1
module: vpc
resources:
  - name: gadget
    objectType: vpc_gadget
    parents: [project]
    producer: derived
    subjects: ["user", "user:*"]
    verbs:
      - get
      - list
`

// TestBootRefusesAModelThatDoesNotPassAdmission — провязка FAIL-CLOSED.
//
// Проба отдельная и стоит ДО успешной по порядку файла намеренно: она до
// установки не доходит ни при каком исходе, поэтому состояние процесса не
// занимает и с успешной не спорит.
//
// Без неё «композиция зовёт допуск» доказывалось бы только счастливым путём —
// то есть провязка, штампующая что угодно, была бы неотличима от судящей.
func TestBootRefusesAModelThatDoesNotPassAdmission(t *testing.T) {
	m, err := manifest.LoadWithReferent([]byte(deliveryWithWildcardSubject), manifest.ReferentCanon)
	if err != nil {
		t.Fatalf("предпосылка не создана: манифест не разобрался: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err = installComposedModel(logger, []*manifest.Manifest{m})
	if err == nil {
		t.Fatal("собранная модель с подстановкой на НОВОМ типе пущена в старт — " +
			"провязка штампует, а не судит: мягкий проход здесь есть контроль, " +
			"который не откажет ни разу за свою жизнь")
	}
	// Отказ обязан прийти от ДОПУСКА, а не от композиции. Различие несущее:
	// композиция судит СБОРКУ (мощность, множество, неприкосновенность канона),
	// допуск — СОДЕРЖАНИЕ добавленного. Красное от композиции доказывало бы, что
	// провязка отвергает негодную сборку, и не говорило бы НИЧЕГО о том,
	// спрашивают ли допуск вообще, — а именно это здесь и утверждается.
	if !strings.Contains(err.Error(), "допуск собранной модели прав отверг её") {
		t.Fatalf("отказ вынесен не допуском — провязка могла отвергнуть и не спросив его: %v", err)
	}
	// Отказ обязан называть ПРЕДМЕТ: оператор чинит содержимое карты, и «модель
	// не собралась» не говорит ему, что править.
	if !strings.Contains(err.Error(), "vpc_gadget") {
		t.Fatalf("отказ не называет тип, из-за которого он вынесен: %v", err)
	}
	// И перепись обязана ехать вместе с отказом: без неё «находок 3» неотличимо
	// от «осмотрено 0».
	if !strings.Contains(err.Error(), "типов осмотрено") {
		t.Fatalf("отказ не несёт переписи допуска: %v", err)
	}
}
