// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// root_shutdown_context_injection_test.go — доказательство, что гейт
// `TestIAM2465_NoRootTaskRunsOnANonCancellableContext` способен упасть И способен
// смолчать.
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве: до починки гейт
// назвал `cmd/kaname/invite_mail_wiring.go:103` и
// `cmd/kaname/provider_compensation_wiring.go:98`, после — молчание при той же
// переписи вхождений. Здесь то же свойство закреплено воспроизводимо, на
// синтетике: доказательство, требующее вернуть дефект в рабочую копию, в
// конвейере не исполняется никогда.
//
// У КАЖДОГО нарушителя стоит ЗАКОННЫЙ БЛИЗНЕЦ — та же форма записи, отличающаяся
// РОВНО ОДНИМ фактом. Инъекция, роняющая заодно что-то ещё, доказательством не
// является: красное пришло бы от соседа.

import (
	"strings"
	"testing"
)

// bgRunOnBackground — дефект дня заведения: долгоживущая работа получает
// неотменяемый контекст.
const bgRunOnBackground = `package main

import "context"

func buildDrainer() func() error {
	return func() error {
		return d.Run(context.Background())
	}
}
`

// bgRunOnPassedContext — ЗАКОННЫЙ БЛИЗНЕЦ: та же форма, отличается ровно одним
// фактом — контекст пришёл параметром.
const bgRunOnPassedContext = `package main

import "context"

func buildDrainer() func(context.Context) error {
	return func(ctx context.Context) error {
		return d.Run(ctx)
	}
}
`

// bgSignalRoot — производный корень процесса: неотменяемый контекст стоит
// РОДИТЕЛЕМ, и это единственное место, где он законен без записи в ведомости.
const bgSignalRoot = `package main

import (
	"context"
	"os/signal"
)

func runServe() error {
	ctx, cancel := signal.NotifyContext(context.Background(), 15)
	defer cancel()
	return serve(ctx)
}
`

// bgWithCancelRoot — второй законный вид производного: отвязанная отмена
// поверхностей.
const bgWithCancelRoot = `package main

import "context"

func runServe() error {
	surfaceCtx, stopSurfaces := context.WithCancel(context.Background())
	defer stopSurfaces()
	return serve(surfaceCtx)
}
`

// bgAliasedRun — тот же дефект под ПСЕВДОНИМОМ импорта. Гейт, знающий одно
// написание, молчал бы на форме столь же законной.
const bgAliasedRun = `package main

import ctxpkg "context"

func buildDrainer() func() error {
	return func() error { return d.Run(ctxpkg.Background()) }
}
`

// bgAliasedSignalRoot — законный близнец предыдущего: тот же псевдоним, но
// вхождение стоит РОДИТЕЛЕМ производного.
const bgAliasedSignalRoot = `package main

import (
	ctxpkg "context"
	sig "os/signal"
)

func runServe() error {
	ctx, cancel := sig.NotifyContext(ctxpkg.Background(), 15)
	defer cancel()
	return serve(ctx)
}
`

// bgTodoRun — второй конструктор неотменяемого контекста. Распознаватель,
// знающий только `Background`, оставил бы эту форму вне наблюдения.
const bgTodoRun = `package main

import "context"

func buildDrainer() func() error {
	return func() error { return d.Run(context.TODO()) }
}
`

// bgBoundToVariable — вхождение, никому не отданное аргументом. Отменяемым его
// не делает ничто, поэтому это находка, а не производный корень.
const bgBoundToVariable = `package main

import "context"

func runDrainer() error {
	ctx := context.Background()
	return d.Run(ctx)
}
`

// bgExemptedPreflight — ПРОЩЁННОЕ вхождение: синхронная проверка предпосылки.
// Гейт обязан молчать на нём ровно потому, что оно перечислено в ведомости.
const bgExemptedPreflight = `package main

import "context"

func auditSink() error { return sink.Preflight(context.Background()) }
`

func TestIAM2465_InjectionRedsTheNonCancellableRootAndKeepsQuietOnTheDerivedOne(t *testing.T) {
	cases := []struct {
		name     string
		files    []wiringFile
		ledger   map[string]bgExemption
		finds    bool
		wantRel  string
		wantCtor string
	}{
		{
			name:  "работа на context.Background() — находка",
			files: []wiringFile{{"cmd/kaname/invite_mail_wiring.go", bgRunOnBackground}},
			finds: true, wantRel: "cmd/kaname/invite_mail_wiring.go", wantCtor: "Background",
		},
		{
			name:  "тот же вызов, контекст параметром — молчание",
			files: []wiringFile{{"cmd/kaname/invite_mail_wiring.go", bgRunOnPassedContext}},
		},
		{
			name:  "сигнальный корень процесса — молчание",
			files: []wiringFile{{"cmd/kaname/serve.go", bgSignalRoot}},
		},
		{
			name:  "отвязанная отмена поверхностей — молчание",
			files: []wiringFile{{"cmd/kaname/serve.go", bgWithCancelRoot}},
		},
		{
			name:  "дефект под псевдонимом импорта — находка",
			files: []wiringFile{{"cmd/kaname/invite_mail_wiring.go", bgAliasedRun}},
			finds: true, wantRel: "cmd/kaname/invite_mail_wiring.go", wantCtor: "Background",
		},
		{
			name:  "производный корень под ТЕМ ЖЕ псевдонимом — молчание",
			files: []wiringFile{{"cmd/kaname/serve.go", bgAliasedSignalRoot}},
		},
		{
			name:  "context.TODO() у работы — находка",
			files: []wiringFile{{"cmd/kaname/invite_mail_wiring.go", bgTodoRun}},
			finds: true, wantRel: "cmd/kaname/invite_mail_wiring.go", wantCtor: "TODO",
		},
		{
			name:  "связано переменной и отдано работе — находка",
			files: []wiringFile{{"cmd/kaname/invite_mail_wiring.go", bgBoundToVariable}},
			finds: true, wantRel: "cmd/kaname/invite_mail_wiring.go", wantCtor: "Background",
		},
		{
			name:   "прощённое ведомостью вхождение — молчание",
			files:  []wiringFile{{"cmd/kaname/audit_shipper_wiring.go", bgExemptedPreflight}},
			ledger: map[string]bgExemption{"cmd/kaname/audit_shipper_wiring.go#Preflight": {Count: 1, Reason: "синтетика"}},
		},
		{
			name:  "проба, несущая дефект, предметом не является — молчание",
			files: []wiringFile{{"cmd/kaname/invite_mail_wiring_test.go", bgRunOnBackground}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, paths := writeSyntheticRoot(t, tc.files)
			sites, census, err := scanNonCancellableContexts(root, paths)
			if err != nil {
				t.Fatalf("%v", err)
			}
			ledger := tc.ledger
			if ledger == nil {
				ledger = map[string]bgExemption{}
			}
			findings, stale := adjudicate(sites, ledger, &census)
			t.Logf("%s", census.Summary())
			if len(stale) != 0 {
				t.Fatalf("ведомость синтетики протухла на своём же случае: %v", stale)
			}

			switch {
			case tc.finds && len(findings) == 0:
				t.Fatalf("гейт СМОЛЧАЛ на внесённом дефекте — он не способен упасть (%s)",
					census.Summary())
			case !tc.finds && len(findings) > 0:
				t.Fatalf("гейт покраснел на ЗАКОННОЙ форме: %s:%d `context.%s()` — "+
					"ложная находка отключает гейт первой",
					findings[0].File, findings[0].Line, findings[0].Ctor)
			}
			if !tc.finds {
				return
			}
			f := findings[0]
			if f.File != tc.wantRel || f.Line == 0 || f.Ctor != tc.wantCtor {
				t.Fatalf("находка не назвала ни координату, ни конструктор: %+v", f)
			}
		})
	}
}

// TestIAM2465_InjectionRedsAnExemptionThatHasNothingLeftToForgive — послабление
// обязано ИСТЕКАТЬ САМО. Запись, которой нечего прощать, переживает свой предмет
// и достаётся следующему дефекту даром.
func TestIAM2465_InjectionRedsAnExemptionThatHasNothingLeftToForgive(t *testing.T) {
	root, paths := writeSyntheticRoot(t, []wiringFile{
		{"cmd/kaname/invite_mail_wiring.go", bgRunOnPassedContext},
	})
	sites, census, err := scanNonCancellableContexts(root, paths)
	if err != nil {
		t.Fatalf("%v", err)
	}
	ledger := map[string]bgExemption{
		"cmd/kaname/audit_shipper_wiring.go#Preflight": {Count: 1, Reason: "предмета уже нет"},
	}
	findings, stale := adjudicate(sites, ledger, &census)
	t.Logf("%s", census.Summary())
	if len(findings) != 0 {
		t.Fatalf("на дереве без дефекта найдено %d — инъекция роняет НЕ ТО, что проверяет", len(findings))
	}
	if len(stale) != 1 || !strings.Contains(stale[0], "audit_shipper_wiring.go#Preflight") {
		t.Fatalf("запись без предмета не названа находкой: %v", stale)
	}
}

// TestIAM2465_InjectionProvesTheEmptyWalkIsRefused — премиса гейта: обход, не
// прочитавший ничего, обязан быть отказом, а не молчаливым успехом. Живой гейт
// превращает нулевые величины переписи в отказ; здесь доказано, что на пустом
// составе они действительно нулевые.
func TestIAM2465_InjectionProvesTheEmptyWalkIsRefused(t *testing.T) {
	root := t.TempDir()
	sites, census, err := scanNonCancellableContexts(root, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(sites) != 0 {
		t.Fatalf("на пустом составе найдено %d вхождений — ядро выдумывает", len(sites))
	}
	if census.Parsed != 0 || census.Occur != 0 || census.Derived != 0 {
		t.Fatalf("перепись пустого состава непуста: %s", census.Summary())
	}
	t.Logf("пустой состав: %s — живой гейт на такой переписи ОТКАЗЫВАЕТ", census.Summary())
}
