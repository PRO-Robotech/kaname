// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// frontparity_injection_test.go — доказательство, что гейты фронта СПОСОБНЫ
// упасть и способны смолчать.
//
// Вход синтетический: проба на живом дефекте исчезает вместе с ним. Оси
// проверяются по одной, и у каждой инъекции есть ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся
// ровно одним названным фактом, — без него отрицание зеленело бы на всём
// сломанном разом.

package restfront

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// synthFront кладёт во временный каталог один файл Go с телом фронта.
//
// Производитель входа: всё, кроме подставляемого тела, побайтово одинаково у
// дефекта и у близнеца.
func synthFront(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	src := `package synth

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

var _ = iamv1.RegisterAccountServiceHandlerFromEndpoint

` + body + `
`
	if err := os.WriteFile(filepath.Join(dir, "synth.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("синтетический вход не записан: %v", err)
	}
	return dir
}

// oneFront — тело одного фронта прямыми вызовами.
func oneFront(name string, services ...string) string {
	var b strings.Builder
	b.WriteString("func " + name + `(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
`)
	for _, s := range services {
		b.WriteString("\tif err := iamv1.Register" + s + "ServiceHandlerFromEndpoint(ctx, mux, endpoint, opts); err != nil {\n\t\treturn err\n\t}\n")
	}
	b.WriteString("\treturn nil\n}\n")
	return b.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// ОСЬ 1. Распознаватель знает ОБЕ законные формы записи.
//
// Ось заведена не для полноты: первая редакция гейта знала только вызов и
// насчитала ноль служб там, где их пятнадцать, — то есть молчала, а не краснела.

func TestRecogniserKnowsBothFormsOfWritingARegistration(t *testing.T) {
	t.Run("форма записи: прямой вызов", func(t *testing.T) {
		dir := synthFront(t, oneFront("registerPublicRESTServices", "Account", "Project"))
		svcs, found, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
		if err != nil || !found {
			t.Fatalf("синтетика не разобрана (found=%v): %v", found, err)
		}
		if len(svcs) != 2 || svcs["AccountService"] != "вызовом" {
			t.Fatalf("прямой вызов не опознан: %v", svcs)
		}
	})

	t.Run("форма записи: значением в таблице", func(t *testing.T) {
		dir := synthFront(t, `func registerPublicRESTServices(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
	table := []func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error{
		iamv1.RegisterAccountServiceHandlerFromEndpoint,
		iamv1.RegisterProjectServiceHandlerFromEndpoint,
	}
	for _, bind := range table {
		if err := bind(ctx, mux, endpoint, opts); err != nil {
			return err
		}
	}
	return nil
}`)
		svcs, found, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
		if err != nil || !found {
			t.Fatalf("синтетика не разобрана (found=%v): %v", found, err)
		}
		if len(svcs) != 2 {
			t.Fatalf("табличная форма не опознана: насчитано %d служб, ожидалось 2: %v",
				len(svcs), svcs)
		}
		if svcs["AccountService"] != "значением" {
			t.Fatalf("форма записи названа неверно: %v", svcs)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// ОСЬ 2. Служебная поверхность на публичном фронте — находка.

func TestGateFindsAnInternalServiceOnThePublicFront(t *testing.T) {
	t.Run("инъекция: Internal* на публичном фронте", func(t *testing.T) {
		dir := synthFront(t, oneFront("registerPublicRESTServices", "Account", "InternalIAM"))
		svcs, _, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		leaked := 0
		for svc := range svcs {
			if strings.HasPrefix(svc, "Internal") {
				leaked++
			}
		}
		if leaked != 1 {
			t.Fatalf("служебная поверхность на публичном фронте не найдена: %v", svcs)
		}
	})

	t.Run("контроль: тот же фронт без неё — молчание", func(t *testing.T) {
		dir := synthFront(t, oneFront("registerPublicRESTServices", "Account", "Project"))
		svcs, _, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		for svc := range svcs {
			if strings.HasPrefix(svc, "Internal") {
				t.Fatalf("гейт краснеет на законном фронте: %v", svcs)
			}
		}
		if len(svcs) != 2 {
			t.Fatalf("законный близнец разобран не полностью: %v", svcs)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// ОСЬ 3. Расхождение перечней — находка В ОБЕ СТОРОНЫ.

func TestGateFindsTheServiceSetsDivergingEitherWay(t *testing.T) {
	grpcDir := synthFront(t, oneFront("registerPublicServices", "Account", "Project"))
	// Синтетика зовёт форму слушателя, а не фронта: суффикс у них разный.
	grpcSrc, err := os.ReadFile(filepath.Join(grpcDir, "synth.go"))
	if err != nil {
		t.Fatalf("синтетика не прочитана: %v", err)
	}
	listenerDir := t.TempDir()
	listener := strings.ReplaceAll(string(grpcSrc), "ServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)", "ServiceServer(srv, nil)")
	if err := os.WriteFile(filepath.Join(listenerDir, "synth.go"), []byte(listener), 0o600); err != nil {
		t.Fatalf("синтетика слушателя не записана: %v", err)
	}

	listenerSvcs, found, err := registrationsIn(listenerDir, "registerPublicServices", "ServiceServer")
	if err != nil || !found {
		t.Fatalf("перечень слушателя не разобран (found=%v): %v", found, err)
	}
	if len(listenerSvcs) != 2 {
		t.Fatalf("фикстура: у слушателя насчитано %d служб, ожидалось 2 — вход инъекции не тот",
			len(listenerSvcs))
	}

	t.Run("инъекция: служба на слушателе и НЕ на фронте", func(t *testing.T) {
		dir := synthFront(t, oneFront("registerPublicRESTServices", "Account"))
		front, _, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		missing := 0
		for svc := range listenerSvcs {
			if _, ok := front[svc]; !ok {
				missing++
			}
		}
		if missing != 1 {
			t.Fatalf("недостающая на фронте служба не найдена: слушатель %v, фронт %v",
				listenerSvcs, front)
		}
	})

	t.Run("инъекция: служба на фронте и НЕ на слушателе", func(t *testing.T) {
		dir := synthFront(t, oneFront("registerPublicRESTServices", "Account", "Project", "Group"))
		front, _, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		extra := 0
		for svc := range front {
			if _, ok := listenerSvcs[svc]; !ok {
				extra++
			}
		}
		if extra != 1 {
			t.Fatalf("лишняя на фронте служба не найдена: слушатель %v, фронт %v",
				listenerSvcs, front)
		}
	})

	t.Run("контроль: равные перечни — молчание", func(t *testing.T) {
		dir := synthFront(t, oneFront("registerPublicRESTServices", "Account", "Project"))
		front, _, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		for svc := range listenerSvcs {
			if _, ok := front[svc]; !ok {
				t.Fatalf("гейт краснеет на равных перечнях: слушатель %v, фронт %v",
					listenerSvcs, front)
			}
		}
		if len(front) != len(listenerSvcs) {
			t.Fatalf("гейт краснеет на равных перечнях: %v против %v", front, listenerSvcs)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// ОСЬ 4. Внутрипроцессная форма подключения — находка.

func TestGateFindsTheInProcessRegistrationForm(t *testing.T) {
	t.Run("инъекция: подключение внутрипроцессной формой", func(t *testing.T) {
		dir := synthFront(t, `func registerPublicRESTServices(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
	return iamv1.RegisterAccountServiceHandlerServer(ctx, mux, nil)
}`)
		inProcess, found, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerServer")
		if err != nil || !found {
			t.Fatalf("синтетика не разобрана (found=%v): %v", found, err)
		}
		if len(inProcess) != 1 {
			t.Fatalf("внутрипроцессная форма не найдена: %v", inProcess)
		}
	})

	t.Run("контроль: та же служба через собственный адрес — молчание", func(t *testing.T) {
		dir := synthFront(t, oneFront("registerPublicRESTServices", "Account"))
		inProcess, _, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerServer")
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		if len(inProcess) != 0 {
			t.Fatalf("гейт краснеет на законной форме подключения: %v", inProcess)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// ОСЬ 5. Адрес, названный не доводом функции, — находка.

func TestGateFindsAnEndpointThatIsNotItsOwn(t *testing.T) {
	t.Run("инъекция: адрес соседа литералом", func(t *testing.T) {
		dir := synthFront(t, `func registerPublicRESTServices(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
	return iamv1.RegisterAccountServiceHandlerFromEndpoint(ctx, mux, "neighbour:9090", opts)
}`)
		args, err := endpointArgsIn(dir, "registerPublicRESTServices")
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		if len(args) != 1 || args[0] != "" {
			t.Fatalf("адрес, названный не доводом, не найден: %v", args)
		}
	})

	t.Run("инъекция: адрес из объявления рядом", func(t *testing.T) {
		dir := synthFront(t, `var neighbourAddr = "neighbour:9090"

func registerPublicRESTServices(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
	return iamv1.RegisterAccountServiceHandlerFromEndpoint(ctx, mux, neighbourAddr, opts)
}`)
		args, err := endpointArgsIn(dir, "registerPublicRESTServices")
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		params, err := funcParamNames(dir, "registerPublicRESTServices")
		if err != nil {
			t.Fatalf("доводы не читаются: %v", err)
		}
		if len(args) != 1 || params[args[0]] {
			t.Fatalf("адрес из объявления рядом принят за собственный: args=%v params=%v",
				args, params)
		}
	})

	t.Run("контроль: адрес доводом функции — молчание", func(t *testing.T) {
		dir := synthFront(t, oneFront("registerPublicRESTServices", "Account"))
		args, err := endpointArgsIn(dir, "registerPublicRESTServices")
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		params, err := funcParamNames(dir, "registerPublicRESTServices")
		if err != nil {
			t.Fatalf("доводы не читаются: %v", err)
		}
		if len(args) != 1 || args[0] != "endpoint" || !params[args[0]] {
			t.Fatalf("гейт краснеет на собственном адресе: args=%v params=%v", args, params)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// ОСЬ 6. Пустой обход — отказ, а не молчаливое «чисто».

func TestGateRefusesAnEmptyWalk(t *testing.T) {
	dir := synthFront(t, "func unrelated() {}")
	svcs, found, err := registrationsIn(dir, "registerPublicRESTServices", "ServiceHandlerFromEndpoint")
	if err != nil {
		t.Fatalf("синтетика не разобрана: %v", err)
	}
	if found {
		t.Fatal("функция фронта найдена там, где её нет — фикстура не тот вход подала")
	}
	if len(svcs) != 0 {
		t.Fatalf("на пустом обходе насчитаны службы: %v", svcs)
	}
	// Сам гейт на таком входе обязан ПАДАТЬ, а не проходить: это утверждают его
	// собственные t.Fatal на нулевом обходе. Здесь доказано, что вход именно
	// пустой, — то есть что предмет их падения достижим.
}

// ─────────────────────────────────────────────────────────────────────────────
// ОСЬ 7. Мультиплексор без сужающего сопоставителя — находка.

func TestMatcherGateFindsAMuxBuiltWithTheLibraryDefault(t *testing.T) {
	t.Run("инъекция: мультиплексор с умолчанием библиотеки", func(t *testing.T) {
		dir := synthFront(t, `func build() *runtime.ServeMux {
	return runtime.NewServeMux()
}`)
		calls, narrowed, err := muxConstructions(dir)
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		if len(calls) != 1 {
			t.Fatalf("фикстура: мультиплексоров насчитано %d, ожидался 1 — вход инъекции не тот",
				len(calls))
		}
		if narrowed[0] {
			t.Fatal("мультиплексор с умолчанием библиотеки зачтён за сужающий")
		}
	})

	t.Run("контроль: тот же мультиплексор с сужающим сопоставителем — молчание", func(t *testing.T) {
		dir := synthFront(t, `func narrowingHeaderMatcherOption() runtime.ServeMuxOption {
	return runtime.WithIncomingHeaderMatcher(func(string) (string, bool) { return "", false })
}

func build() *runtime.ServeMux {
	return runtime.NewServeMux(narrowingHeaderMatcherOption())
}`)
		calls, narrowed, err := muxConstructions(dir)
		if err != nil {
			t.Fatalf("синтетика не разобрана: %v", err)
		}
		if len(calls) != 1 {
			t.Fatalf("фикстура: мультиплексоров насчитано %d, ожидался 1 — вход инъекции не тот",
				len(calls))
		}
		if !narrowed[0] {
			t.Fatal("гейт краснеет на сужающем мультиплексоре")
		}
	})
}
