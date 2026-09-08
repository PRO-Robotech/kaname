// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicauthzcensus_test

// index_localvar_injection_test.go — доказательство того, что распознаватель
// ЗНАЕТ форму «метод локальной переменной» и не засчитывает её по имени.
//
// # Предмет
//
// Вопрос о доступе на полосе `scope_filtered` задаёт сам путь обслуживания, и
// перепись обходит его вызовы. Форма, о которой обход не знает, даёт НЕ красное
// и НЕ зелёное, а молчание: всё, что за ней стоит, уходит из-под наблюдения, а
// RPC объявляется находкой при живой двери. Ложная находка обесценивает
// перепись целиком — инструмент, чьи находки не подтверждаются, перестают
// читать.
//
// # Почему синтетическое дерево, а не настоящее
//
// Корень передаётся параметром, поэтому обслуживающий пакет подаётся свой, а
// карта прав остаётся НАСТОЯЩЕЙ (она выводится из дескрипторов, влинкованных в
// процесс, и подменить её нельзя by construction). Между мирами ниже меняется
// РОВНО ОДИН факт — тело метода, который зовут через локальную переменную.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/publicauthzcensus"
)

// servingPkgTree кладёт синтетический контракт, точку регистрации и
// ОБСЛУЖИВАЮЩИЙ ПАКЕТ и возвращает пути, которыми перепись их найдёт.
//
// Служба — настоящая `ProjectService`, метод — настоящий `List`: он объявлен
// контрактом как `scope_filtered`, и только на этой полосе перепись вообще
// спрашивает путь обслуживания. Выдуманная служба ушла бы в «БЕЗ двери» по
// другой причине — отсутствию записи в карте, — и тогда проба утверждала бы не
// о том.
func servingPkgTree(t *testing.T, body string) (protoDir, cmdDir, root string) {
	t.Helper()
	base := t.TempDir()
	protoDir = filepath.Join(base, "proto")
	cmdDir = filepath.Join(base, "cmd")
	root = filepath.Join(base, "root")
	pkgDir := filepath.Join(root, "services", "iam", "internal", "apps", "kaname", "api", "project")
	for _, d := range []string{protoDir, cmdDir, pkgDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("создать %s: %v", d, err)
		}
	}
	proto := "syntax = \"proto3\";\npackage kaname.cloud.iam.v1;\n\n" +
		"service ProjectService {\n  rpc List(Req) returns (Res);\n}\n"
	if err := os.WriteFile(filepath.Join(protoDir, "synth.proto"), []byte(proto), 0o644); err != nil {
		t.Fatalf("записать контракт: %v", err)
	}
	reg := "package main\n\n" +
		"import (\n\tsynthapp \"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project\"\n)\n\n" +
		"type services struct {\n\tsynthHandler *synthapp.Handler\n}\n\n" +
		"func registerPublicServices(srv grpc.ServiceRegistrar, svcs *services) {\n" +
		"\tiamv1.RegisterProjectServiceServer(srv, svcs.synthHandler)\n}\n"
	if err := os.WriteFile(filepath.Join(cmdDir, "register.go"), []byte(reg), 0o644); err != nil {
		t.Fatalf("записать регистрацию: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "serving.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("записать обслуживающий пакет: %v", err)
	}
	return protoDir, cmdDir, root
}

// servingPkg собирает обслуживающий пакет из двух подставляемых кусков:
// объявления локальной переменной и тела метода, который через неё зовут.
//
// Всё остальное побайтово одинаково во всех мирах пробы — иначе красное могло
// бы прийти от соседнего различия, и инъекция перестала бы быть одно-фактной.
func servingPkg(localDecl, verdictBody, extra string) string {
	return "package project\n\n" +
		"type Handler struct{ list *ListUseCase }\n\n" +
		"func (h *Handler) List(ctx context.Context) error { return h.list.Execute(ctx) }\n\n" +
		"type ListUseCase struct{ relations RelationStore }\n\n" +
		"func (u *ListUseCase) Execute(ctx context.Context) error {\n" +
		"\t" + localDecl + "\n" +
		"\treturn authority.verdict(ctx, \"prj_1\")\n" +
		"}\n\n" +
		"type pageAuthority struct{ relations RelationStore }\n\n" +
		"func (p *pageAuthority) verdict(ctx context.Context, row string) error {\n" +
		"\t" + verdictBody + "\n" +
		"}\n" + extra
}

const (
	asksTheModel = "_, err := p.relations.Check(ctx, \"usr_1\", \"admin\", row); return err"
	asksNothing  = "return nil"
)

func categoryOf(t *testing.T, body string) publicauthzcensus.Category {
	t.Helper()
	protoDir, cmdDir, root := servingPkgTree(t, body)
	c, err := publicauthzcensus.CollectFrom(protoDir, cmdDir, root)
	if err != nil {
		t.Fatalf("перепись не состоялась: %v", err)
	}
	if c.Inspected != 1 {
		t.Fatalf("обход не подан: осмотрено %d RPC вместо 1 — вердикт беспредметен", c.Inspected)
	}
	if c.GoFiles != 1 {
		t.Fatalf("обслуживающий пакет не разобран: файлов Go %d — вердикт беспредметен", c.GoFiles)
	}
	if len(c.Unresolved) != 0 {
		t.Fatalf("метод не разрешился: %v — это «не выполнилось», а не вердикт", c.Unresolved)
	}
	if len(c.Verdicts) != 1 {
		t.Fatalf("вердиктов %d вместо 1", len(c.Verdicts))
	}
	t.Logf("%s → %s (%s)", c.Verdicts[0].RPC, c.Verdicts[0].Category, c.Verdicts[0].Evidence)
	return c.Verdicts[0].Category
}

// ЗАКОННЫЙ БЛИЗНЕЦ: дверь стоит за методом ЛОКАЛЬНОЙ переменной — молчание.
//
// Формы объявления перечислены все, которые распознаватель обещает знать:
// обещание, не проверенное по каждой форме, — это обещание про одну из них.
func TestLocalVariableDoorIsSeenInEveryDeclarationForm(t *testing.T) {
	for _, tc := range []struct{ name, decl string }{
		{"адрес составного литерала", "authority := &pageAuthority{relations: u.relations}"},
		{"составной литерал", "authority := pageAuthority{relations: u.relations}"},
		{"new(T)", "authority := new(pageAuthority)"},
		{"var v T", "var authority pageAuthority"},
		{"var v *T", "var authority *pageAuthority"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := categoryOf(t, servingPkg(tc.decl, asksTheModel, "")); got != publicauthzcensus.CategoryDataAuthorized {
				t.Errorf("дверь за локальной переменной не увидена: категория %q вместо %q",
					got, publicauthzcensus.CategoryDataAuthorized)
			}
		})
	}
}

// ДЕФЕКТ: та же форма, а вопроса нет — находка.
//
// От мира выше отличается РОВНО ОДНИМ фактом: телом `verdict`. Без этой стороны
// «увидена» было бы неотличимо от распознавателя, засчитывающего любую
// локальную переменную за дверь.
func TestLocalVariableWithoutAQuestionIsAFinding(t *testing.T) {
	body := servingPkg("authority := &pageAuthority{relations: u.relations}", asksNothing, "")
	if got := categoryOf(t, body); got != publicauthzcensus.CategoryUngated {
		t.Errorf("путь без вопроса зачтён за дверь: категория %q вместо %q",
			got, publicauthzcensus.CategoryUngated)
	}
}

// АНТИ-МАСКА: одноимённый метод У ПРИЁМНИКА не засчитывается за вызов через
// локальную переменную.
//
// Здесь вопрос к модели стоит в `ListUseCase.verdict`, которого путь НЕ зовёт, а
// зовёт он `pageAuthority.verdict`, где вопроса нет. Разрешение по совпадению
// имени объявило бы этот путь дверью — то есть приписало бы RPC защиту, которой
// на нём нет. Ровно так вёл себя распознаватель до правки.
func TestReceiverMethodOfTheSameNameIsNotCreditedToALocalVariable(t *testing.T) {
	extra := "\nfunc (u *ListUseCase) verdict(ctx context.Context, row string) error {\n" +
		"\t" + asksTheModel + "\n}\n"
	body := servingPkg("authority := &pageAuthority{relations: u.relations}", asksNothing, extra)
	if got := categoryOf(t, body); got != publicauthzcensus.CategoryUngated {
		t.Errorf("метод приёмника засчитан за вызов локальной переменной: категория %q вместо %q",
			got, publicauthzcensus.CategoryUngated)
	}
}

// ПРИЁМНИК ПО-ПРЕЖНЕМУ РАЗРЕШАЕТСЯ: правка добавляет форму, а не подменяет.
//
// Без этой стороны «локальная переменная приоритетнее» было бы неотличимо от
// распознавателя, переставшего входить в методы самого приёмника.
func TestReceiverMethodStaysResolvable(t *testing.T) {
	body := "package project\n\n" +
		"type Handler struct{ list *ListUseCase }\n\n" +
		"func (h *Handler) List(ctx context.Context) error { return h.list.Execute(ctx) }\n\n" +
		"type ListUseCase struct{ relations RelationStore }\n\n" +
		"func (u *ListUseCase) Execute(ctx context.Context) error { return u.verdict(ctx, \"prj_1\") }\n\n" +
		"func (u *ListUseCase) verdict(ctx context.Context, row string) error {\n" +
		"\t_, err := u.relations.Check(ctx, \"usr_1\", \"admin\", row)\n\treturn err\n}\n"
	if got := categoryOf(t, body); got != publicauthzcensus.CategoryDataAuthorized {
		t.Errorf("метод приёмника перестал разрешаться: категория %q вместо %q",
			got, publicauthzcensus.CategoryDataAuthorized)
	}
}
