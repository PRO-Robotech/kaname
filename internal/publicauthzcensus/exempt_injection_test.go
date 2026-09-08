// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicauthzcensus

// exempt_injection_test.go — доказательство, что разбор решателя СПОСОБЕН
// сказать «нет» и способен смолчать.
//
// Инъекция подаётся НАСТОЯЩИМ входом разбора — каталогом с файлами Go, — и
// между дефектной фикстурой и её законным близнецом различается РОВНО ОДИН
// факт: наличие на пути обслуживания вызова, который решает доступ. Всё
// остальное — имена типов, поля, цепочка вызовов — совпадает дословно.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// servingPackage собирает синтетический обслуживающий пакет: обработчик,
// use-case в его поле и один изменяемый вызов внутри use-case'а.
func servingPackage(t *testing.T, insideUseCase string) *pkgIndex {
	t.Helper()
	dir := t.TempDir()
	src := `package fixture

import "context"

type relationStore interface {
	Check(ctx context.Context, subject, relation, object string) (bool, error)
}

type CreateUseCase struct {
	relations relationStore
}

func (u *CreateUseCase) Execute(ctx context.Context) error {
	` + insideUseCase + `
	return nil
}

type Handler struct {
	create *CreateUseCase
}

func (h *Handler) Create(ctx context.Context) error {
	return h.create.Execute(ctx)
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("фикстура не записана: %v", err)
	}
	idx, files, err := indexPackage(dir)
	if err != nil {
		t.Fatalf("фикстура не разобрана: %v", err)
	}
	if files != 1 {
		t.Fatalf("фикстура: разобрано файлов %d, ожидался 1 — вход инъекции не тот", files)
	}
	return idx
}

// TestDeciderIsNotFoundWhenTheServingPathOnlyAuthenticates — ДЕФЕКТ.
//
// Путь обслуживания проверяет лишь то, что вызывающий вошёл. На вынесенном iam
// это и есть открытая дверь: объект отдаётся любому аутентифицированному.
func TestDeciderIsNotFoundWhenTheServingPathOnlyAuthenticates(t *testing.T) {
	idx := servingPackage(t, `_ = authzguard.RequireAuthenticated(ctx)`)
	ev, resolved := idx.findOnServingPath("Create", modelQuestionMatcher)
	if !resolved {
		t.Fatal("метод обработчика не разрешился — вердикта нет ни в одну сторону")
	}
	if ev != "" {
		t.Fatalf("аутентификация зачтена за решателя: %q — гейт стал формой без содержания", ev)
	}
}

// TestDeciderIsFoundWhenTheServingPathAsksTheModel — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// От дефектной фикстуры отличается ОДНИМ фактом: рядом стоит вопрос к модели.
func TestDeciderIsFoundWhenTheServingPathAsksTheModel(t *testing.T) {
	idx := servingPackage(t, `_ = authzguard.RequireAuthenticated(ctx)
	_, _ = u.relations.Check(ctx, "sub", "admin", "obj")`)
	ev, resolved := idx.findOnServingPath("Create", modelQuestionMatcher)
	if !resolved {
		t.Fatal("метод обработчика не разрешился — вердикта нет ни в одну сторону")
	}
	if ev == "" {
		t.Fatal("вопрос к модели на пути обслуживания не найден — разбор слеп к законной форме")
	}
}

// TestClusterAdminSupervisionAloneIsNotADecider — исключение, названное в шапке
// exempt.go, доказывается, а не объявляется.
//
// Надзор администратора кластера — РАННЕЕ РАЗРЕШЕНИЕ: путь, который задаёт
// только его, отдаёт объект постороннему.
func TestClusterAdminSupervisionAloneIsNotADecider(t *testing.T) {
	idx := servingPackage(t, `_, _ = authzguard.IsClusterAdminE(ctx, u.relations)`)
	ev, _ := idx.findOnServingPath("Create", modelQuestionMatcher)
	if ev != "" {
		t.Fatalf("надзор администратора кластера зачтён за решателя: %q", ev)
	}
}

// TestCallerBindingDoesNotSatisfyHandlerDecides — причина задаёт СВОЮ форму
// решателя, и подмена одной формы другой не проходит.
//
// Чтение личности вызывающего стоит на пути почти каждой мутации (аудит); будь
// оно зачтено за «обработчик решает», гейт объявил бы доказанным освобождение,
// при котором решения не принимает никто.
func TestCallerBindingDoesNotSatisfyHandlerDecides(t *testing.T) {
	idx := servingPackage(t, `_ = operations.PrincipalFromContext(ctx)`)

	if ev, _ := idx.findOnServingPath("Create", modelQuestionMatcher); ev != "" {
		t.Fatalf("связывание с личностью зачтено за вопрос к модели: %q", ev)
	}
	ev, resolved := idx.findOnServingPath("Create", callerBindingMatcher)
	if !resolved {
		t.Fatal("метод обработчика не разрешился — вердикта нет ни в одну сторону")
	}
	if ev == "" {
		t.Fatal("связывание с личностью вызывающего не распознано — разбор слеп к законной форме")
	}
}

// TestWalkEntersAPackageFunctionSharingTheNameOfAMethod — регрессия на СКЛЕЙКУ
// посещённого.
//
// Ключом посещённого была пара «приёмник.имя», и функция уровня пакета
// склеивалась с одноимённым методом текущего приёмника: обход входил в
// метод-переходник, метил ключ и НЕ ВХОДИЛ в функцию, где стоит вопрос к
// модели. Свидетельство терялось молча — гейт называл находкой RPC, у которого
// решатель есть. Фикстура воспроизводит ровно эту пару имён.
func TestWalkEntersAPackageFunctionSharingTheNameOfAMethod(t *testing.T) {
	dir := t.TempDir()
	src := `package fixture

import "context"

type relationStore interface {
	Check(ctx context.Context, subject, relation, object string) (bool, error)
}

func requireAuthority(ctx context.Context, relations relationStore) error {
	_, _ = relations.Check(ctx, "sub", "admin", "obj")
	return nil
}

type CreateUseCase struct {
	relations relationStore
}

// Переходник назван ТАК ЖЕ, как функция пакета, которую он зовёт.
func (u *CreateUseCase) requireAuthority(ctx context.Context) error {
	return requireAuthority(ctx, u.relations)
}

func (u *CreateUseCase) Execute(ctx context.Context) error {
	return u.requireAuthority(ctx)
}

type Handler struct {
	create *CreateUseCase
}

func (h *Handler) Create(ctx context.Context) error {
	return h.create.Execute(ctx)
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("фикстура не записана: %v", err)
	}
	idx, _, err := indexPackage(dir)
	if err != nil {
		t.Fatalf("фикстура не разобрана: %v", err)
	}
	ev, resolved := idx.findOnServingPath("Create", modelQuestionMatcher)
	if !resolved {
		t.Fatal("метод обработчика не разрешился — вердикта нет ни в одну сторону")
	}
	if ev == "" {
		t.Fatal("обход не вошёл в функцию пакета, одноимённую методу приёмника: " +
			"свидетельство теряется молча")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ФОРМА РЕШАТЕЛЯ, КОТОРУЮ РАСПОЗНАВАТЕЛЬ ДОЛГО НЕ ЗНАЛ
//
// Причина `HANDLER_DECIDES` допускает две формы, и вторая — чтение, суженное
// владельцем, — сильнее вопроса к модели: предикат владения уходит доводом в
// сам запрос, поэтому чужая строка не читается вовсе. Пока распознаватель знал
// только первую, он МОЛЧАЛ на второй, и служба операций уезжала в «без двери»
// при живом и более крепком решателе.

func TestOwnershipScopedReadCountsAsAHandlerDecider(t *testing.T) {
	idx := servingPackage(t, `owner, _ := operations.OwnerFromContext(ctx)
	_, _ = u.store.GetOwned(ctx, "iop-1", owner)`)
	ev, resolved := idx.findOnServingPath("Create", handlerDecidesMatcher)
	if !resolved {
		t.Fatal("метод обработчика не разрешился — вердикта нет ни в одну сторону")
	}
	if ev == "" {
		t.Fatal("чтение, суженное владельцем, не зачтено за решателя: предикат владения " +
			"стоит доводом запроса, то есть чужая строка не читается вовсе — это строго " +
			"сильнее вопроса после чтения")
	}
	if !strings.Contains(ev, "GetOwned") {
		t.Fatalf("находка не называет форму решателя: %q", ev)
	}
}

// TestABareOwnerReadIsNotADecider — АНТИ-ЗАЧЁТ.
//
// Чтение владельца из контекста решения не производит: оно лишь узнаёт, кто
// звонит. Зачесть его значило бы принять за решателя ту самую аутентификацию,
// которую шапка пакета отвергает прямо.
func TestABareOwnerReadIsNotADecider(t *testing.T) {
	idx := servingPackage(t, `owner, _ := operations.OwnerFromContext(ctx)
	_ = owner`)
	ev, resolved := idx.findOnServingPath("Create", handlerDecidesMatcher)
	if !resolved {
		t.Fatal("метод обработчика не разрешился — вердикта нет ни в одну сторону")
	}
	if ev != "" {
		t.Fatalf("чтение владельца зачтено за решателя: %q — гейт стал формой без содержания", ev)
	}
}

// TestOwnershipScopedReadWithoutTheOwnerArgumentIsNotADecider — ГРАНИЦА ФОРМЫ.
//
// Суффикс имени сам по себе решателем не является: предикат владения обязан
// быть ДОВОДОМ запроса. Чтение без него сужает по чему угодно, только не по
// владельцу.
func TestOwnershipScopedReadWithoutTheOwnerArgumentIsNotADecider(t *testing.T) {
	idx := servingPackage(t, `_, _ = u.store.GetOwned(ctx)`)
	ev, resolved := idx.findOnServingPath("Create", handlerDecidesMatcher)
	if !resolved {
		t.Fatal("метод обработчика не разрешился — вердикта нет ни в одну сторону")
	}
	if ev != "" {
		t.Fatalf("чтение без довода-владельца зачтено за решателя: %q", ev)
	}
}
