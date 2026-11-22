// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

const childAuthorityModule = "github.com/PRO-Robotech/kaname/"

var childAuthorityFiles = []string{
	"cmd/kaname/wiring.go", "cmd/kaname/full_startup.go", "cmd/kaname/grpc_register.go", "cmd/kaname/serve.go",
	"internal/apps/kaname/api/child_registration/handler.go",
	"internal/apps/kaname/api/internal_iam/register_user_child.go",
	"internal/repo/kaname/pg/resource_decision_runner.go",
	"internal/repo/kaname/pg/resource_child_run.go",
	"internal/repo/kaname/pg/resource_child_stage.go",
	"internal/repo/kaname/pg/resource_child_authorization.go",
	"internal/repo/kaname/pg/resource_child_body.go",
	"internal/repo/kaname/pg/resource_attempt_retry.go",
	"internal/repo/kaname/pg/writer_protocol.go",
}

// CensusChildRegistrationQuestion читает исходники от корня модуля. Пустое
// свидетельство не разрешает RPC: вызывающая перепись сохраняет свой отказ.
func CensusChildRegistrationQuestion(root string) (string, error) {
	corpus := make(map[string][]byte, len(childAuthorityFiles))
	for _, name := range childAuthorityFiles {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return "", fmt.Errorf("предмет child authority %s: %w", name, err)
		}
		corpus[name] = body
	}
	// Дополнительный writer поля не должен исчезнуть за границей fixed list.
	for _, dir := range childAuthorityOwnerDirs {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			return "", err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			name := dir + "/" + entry.Name()
			body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
			if err != nil {
				return "", err
			}
			corpus[name] = body
		}
	}
	return CensusChildRegistrationQuestionProof(corpus)
}

var childAuthorityOwnerDirs = []string{"cmd/kaname", "internal/apps/kaname/api/child_registration", "internal/apps/kaname/api/internal_iam"}

// CensusChildRegistrationQuestionProof проверяет замкнутый capability-путь.
// Имена обозначают проверяемые исходники; ни имя RPC, ни реализация interface
// сами по себе не дают свидетельства. Проверяются сохранённые аргументы
// конструкторов, конкретный FULL binding и обязательный вопрос до capture.
func CensusChildRegistrationQuestionProof(corpus map[string][]byte) (string, error) {
	files := make(map[string]*ast.File, len(childAuthorityFiles))
	for _, name := range childAuthorityFiles {
		body, ok := corpus[name]
		if !ok {
			return "", fmt.Errorf("нет исходника child authority: %s", name)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, body, parser.SkipObjectResolution)
		if err != nil {
			return "", fmt.Errorf("разбор child authority %s: %w", name, err)
		}
		files[name] = file
	}
	for name, body := range corpus {
		for _, dir := range childAuthorityOwnerDirs {
			if filepath.ToSlash(filepath.Dir(name)) != dir || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || files[name] != nil {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), name, body, parser.SkipObjectResolution)
			if err != nil {
				return "", err
			}
			files[name] = f
		}
	}
	for _, source := range files {
		if !directBooleanLiteralsUnshadowed(source) {
			return "", nil
		}
	}
	file := func(name string) *ast.File { return files[name] }
	const app = "internal/apps/kaname/api/"
	const pg = "internal/repo/kaname/pg/"
	handler := file(app + "child_registration/handler.go")
	uc := file(app + "internal_iam/register_user_child.go")
	wire := file("cmd/kaname/full_startup.go")
	mount := file("cmd/kaname/grpc_register.go")
	if !routeFieldType(file("cmd/kaname/wiring.go"), "services", "childRegistrationHandler", childAuthorityModule+app+"child_registration", "Handler") ||
		!childAuthorityConstructor(handler, "NewHandler", "Handler", "register", childAuthorityModule+app+"internal_iam", "UserChildRegistration") ||
		!childAuthorityConstructor(uc, "NewUserChildRegistration", "UserChildRegistration", "tx", childAuthorityModule+"internal/repo/kaname", "UserChildRegistrationTransactions") {
		return "", nil
	}
	public := routeFunction(mount, "registerPublicServices")
	if public == nil || !routeBindingUntouched(public, "svcs", "childRegistrationHandler") ||
		!childAuthorityStatements(public, `if svcs != nil && svcs.childRegistrationHandler != nil {
 iamv1.RegisterChildRegistrationServiceServer(srv, svcs.childRegistrationHandler)
}`) || routeImport(mount, "iamv1") != childAuthorityModule+"pkg/api/kaname/cloud/iam/v1" || !routeAliasUnshadowed(mount, "iamv1") {
		return "", nil
	}
	build := routeFunction(wire, "wireFullStartupServices")
	if build == nil || routeLocalBindings(build)["resourceDecisions"] != 1 ||
		!childAuthorityStatements(build, `resourceDecisions, err := kanamepg.NewResourceDecisionRunner(ctx, repo, profile.bundle, svcs.resourceGate)`, `if err != nil { return nil, err }`) ||
		!childAuthorityStatements(build, `svcs.childRegistrationHandler = childregistrationapp.NewHandler(internaliamapp.NewUserChildRegistration(resourceDecisions))`) ||
		!childAuthorityImports(wire, map[string]string{"kanamepg": pg[:len(pg)-1], "childregistrationapp": app + "child_registration", "internaliamapp": app + "internal_iam"}) {
		return "", nil
	}
	if !childAuthorityServingRoot(file("cmd/kaname/serve.go"), mount) {
		return "", nil
	}

	// Единственная запись поля — именно проверенная композиция, не decoy.
	writes := 0
	for _, f := range files {
		routeAny(f, func(n ast.Node) bool {
			if field, ok := n.(*ast.KeyValueExpr); ok && routeIdent(field.Key, "childRegistrationHandler") {
				writes++
			}
			if a, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range a.Lhs {
					if s, ok := lhs.(*ast.SelectorExpr); ok && s.Sel.Name == "childRegistrationHandler" {
						writes++
					}
				}
			}
			return false
		})
	}
	if writes != 1 {
		return "", nil
	}
	constructor := routeFunction(file(pg+"resource_decision_runner.go"), "NewResourceDecisionRunner")
	if constructor == nil || constructor.Type.Results == nil || len(constructor.Type.Results.List) != 2 ||
		!routeType(file(pg+"resource_decision_runner.go"), constructor.Type.Results.List[0].Type, "", "ResourceDecisionRunner") {
		return "", nil
	}
	rpc := routeMethod(handler, "Handler", "Register")
	use := routeMethod(uc, "UserChildRegistration", "Register")
	if !childAuthorityServes(rpc, "h", "register", "Register") || !childAuthorityServes(use, "uc", "tx", "RunUserChildRegistration") ||
		!routeMethodsPreserve(files, app+"child_registration", "Handler", "Register", "register", map[string]bool{}) ||
		!routeMethodsPreserve(files, app+"internal_iam", "UserChildRegistration", "Register", "tx", map[string]bool{}) ||
		!childAuthorityStatements(rpc, `version, err := h.register.Register(ctx, kaname.UserChildRegistrationInput{ResourceType: req.GetResourceType(), ResourceID: req.GetResourceId()})`, `if err != nil { return nil, shared.MapRepoErrAt(ctx, err) }`) ||
		!childAuthorityStatements(use, `version, err := uc.tx.RunUserChildRegistration(ctx, input, principal)`) ||
		!childAuthorityStatements(use, `principal, verified := operations.PrincipalFromContextOK(ctx)`, `_, named := authzguard.SubjectFromPrincipal(principal)`, `if !verified || !named || principal.Type != "user" || principal.IsAnonymous() || input.ResourceType == "" || input.ResourceID == "" { return time.Time{}, authzguard.PermissionDenied() }`) {
		return "", nil
	}
	run := routeMethod(file(pg+"resource_child_run.go"), "ResourceDecisionRunner", "RunUserChildRegistration")
	once := routeMethod(file(pg+"resource_child_run.go"), "ResourceDecisionRunner", "runUserChildRegistrationOnce")
	stage := routeMethod(file(pg+"resource_child_stage.go"), "ResourceDecisionRunner", "stageUserChildRegistration")
	authorize := routeMethod(file(pg+"resource_child_authorization.go"), "ResourceDecisionRunner", "captureUserChildAuthorization")
	retry := routeFunction(file(pg+"resource_attempt_retry.go"), "runResourceAttempts")
	body := routeMethod(file(pg+"resource_child_body.go"), "resourceChildStage", "applyChildBody")
	final := routeMethod(file(pg+"resource_child_authorization.go"), "resourceChildAuthorization", "checkFinal")
	if !childAuthorityFinalWriteGate(once, body, final) || !childAuthorityAttemptCleanup(once) {
		return "", nil
	}
	if run == nil || once == nil || stage == nil || authorize == nil || retry == nil || routeLocalBindings(run)["runResourceAttempts"] != 0 ||
		!childAuthorityStatements(run, `if r.repo.fullContract == nil || !r.repo.fullContractMatches(r.bundle) { return time.Time{}, resourceChildError(ctx, kaname.ErrSemanticIdentityUnavailable) }`) ||
		!childAuthorityStatements(run, `version, err := runResourceAttempts(ctx, func() (time.Time, error) {
 lease, err := r.repo.master.Acquire(ctx)
 if err != nil { return time.Time{}, resourceOpenError(ctx, err) }
 defer lease.Release()
 return r.runUserChildRegistrationOnce(ctx, lease.Conn(), input, principal, budget)
})`, `if err != nil { return time.Time{}, r.childRefusalAfterAttempt(ctx, principal, err) }`, `return version, nil`) ||
		!childAuthorityStatements(once, `rr, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})`, `if err != nil { return time.Time{}, resourceFailedAttempt(resourceOpenError(ctx, err), nil, false) }`, `active = rr`, `stage, err := r.stageUserChildRegistration(ctx, rr, lifetime, input, principal, budget)`, `if err != nil { return time.Time{}, err }`) ||
		!childAuthorityStatements(once, `stage, err := r.stageUserChildRegistration(ctx, rr, lifetime, input, principal, budget)`, `if err != nil { return time.Time{}, err }`) ||
		len(stage.Body.List) < 2 || !childAuthoritySame(stage.Body.List[0], `authorization, err := r.captureUserChildAuthorization(ctx, tx, lifetime, input, principal, budget)`) ||
		!childAuthoritySame(stage.Body.List[1], `if err != nil { return nil, err }`) {
		return "", nil
	}
	// Callback учитывается только через настоящий вызов once внутри retry.
	called := false
	for _, statement := range retry.Body.List {
		if loop, ok := statement.(*ast.ForStmt); ok && childAuthorityText(loop.Cond) == "attempt < authorityEntryAttempts" {
			if called || !directPositiveLoop(file(pg+"writer_protocol.go"), retry, loop) || len(loop.Body.List) < 3 {
				return "", nil
			}
			called = childAuthoritySame(loop.Body.List[0], "if err := ctx.Err(); err != nil { return zero, err }") &&
				childAuthoritySame(loop.Body.List[1], "result, err := once()") &&
				childAuthoritySame(loop.Body.List[2], "if err == nil { return result, nil }")
		}
	}
	authFile := file(pg + "resource_child_authorization.go")
	if !called || routeLocalBindings(retry)["once"] != 1 || !childAuthorityImports(authFile, map[string]string{"relverdict": pg + "relverdict", "authzcascade": "internal/authzcascade", "personmarks": pg + "personmarks"}) ||
		!childAuthorityStatements(authorize, `verified, ok := operations.PrincipalFromContextOK(ctx)`, `subject, named := authzguard.SubjectFromPrincipal(verified)`, `if !ok || !named || verified.Type != "user" || verified.IsAnonymous() || verified != principal { return nil, domain.ErrUserChildRegistrationRefused }`) ||
		!childAuthorityStatements(authorize, `policy, ok := r.bundle.ChildRegistration(input.ResourceType)`, `if !ok { return nil, childPolicyUnavailable }`, `target, err := policy.Path.Resolve(input.ResourceID)`, `if err != nil { return nil, childInvalidCoordinates }`) ||
		routeLocalBindings(authorize)["subject"] != 1 || routeLocalBindings(authorize)["target"] != 1 || routeLocalBindings(authorize)["allowed"] != 1 ||
		!childAuthorityStatements(authorize, `form := relverdict.NewAdministrativeAsker(tx, r.bundle, func() time.Time { return at }, sources.verify)`, `form.BindReadBudget(budget)`, `allowed, err := authzcascade.WrapAdmitted(form, personmarks.NewTransaction(tx)).Check(ctx, subject, target.ParentAction, target.ParentObject)`,
			`if errors.Is(err, relverdict.ErrAdministrativeSourceUnconfirmed) { return nil, kaname.ErrSourceUnconfirmed }`,
			`if errors.Is(err, relverdict.ErrAdministrativeSourceLimit) { return nil, kaname.ErrSourceReadLimit }`,
			`if err != nil { return nil, err }`, `if !allowed { return nil, childPermissionDenied }`) {
		return "", nil
	}
	for _, f := range []*ast.File{uc, authFile} {
		if routeImport(f, "operations") != "github.com/PRO-Robotech/corelib/operations" || !routeAliasUnshadowed(f, "operations") ||
			!childAuthorityImports(f, map[string]string{"authzguard": "internal/authzguard"}) {
			return "", nil
		}
	}
	if routeAny(authorize.Body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok {
			return false
		}
		for _, lhs := range a.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && routeIdent(sel.X, "target") {
				return true
			}
		}
		return false
	}) {
		return "", nil
	}
	absentParent := childAuthorityAbsentParent(stage, once)
	if absentParent == nil || !childAuthoritySingleResult(stage, "nil", absentParent) {
		return "", nil
	}

	// Результаты нулевой формы вовне дополнительно отклоняются вызывающим
	// сценарием. Положительный результат ни одна стадия не отдаёт раньше.
	if !childAuthorityStatements(use, "if version.IsZero() { return time.Time{}, authzguard.AuthzBackendUnavailable() }", "return version, nil") ||
		!childAuthorityStatements(once, "if stage == nil { return time.Time{}, kaname.ErrSourceUnconfirmed }") {
		return "", nil
	}
	for _, guard := range []struct {
		fn    *ast.FuncDecl
		empty string
	}{
		{rpc, "nil"}, {use, "time.Time{}"}, {run, "time.Time{}"}, {once, "time.Time{}"},
		{authorize, "nil"}, {body, "time.Time{}"}, {final, "false"},
	} {
		if !childAuthoritySingleResult(guard.fn, guard.empty, nil) {
			return "", nil
		}
	}
	return "решатель: публичный gRPC → FULL UserChildRegistrationTransactions → проверка права на родителе в RR и в writer перед записью", nil
}

// Сборка и регистрация должны использовать один экземпляр services. Обращение
// к полю допустимо, передача экземпляра другому владельцу снимает доказательство.
func childAuthorityServingRoot(source, registrations *ast.File) bool {
	serve := routeFunction(source, "runServe")
	internal := routeFunction(registrations, "registerInternalServices")
	if serve == nil || serve.Body == nil || !routeBindingUntouched(internal, "svcs", "childRegistrationHandler") {
		return false
	}
	bindings := routeLocalBindings(serve)
	if bindings["svcs"] != 1 || bindings["grpcSrv"] != 1 ||
		bindings["wireFullStartupServices"] != 0 || bindings["registerPublicServices"] != 0 ||
		bindings["buildServices"] != 0 || bindings["registerInternalServices"] != 0 {
		return false
	}
	services := routeDirectDefinition(serve, "svcs")
	server := routeDirectDefinition(serve, "grpcSrv")
	if services == nil || server == nil {
		return false
	}
	build, ok := services.Rhs[0].(*ast.CallExpr)
	if !ok || !routeIdent(build.Fun, "buildServices") {
		return false
	}
	newServer, ok := server.Rhs[0].(*ast.CallExpr)
	if !ok || !routeImportedCall(source, newServer, "github.com/PRO-Robotech/corelib/grpcsrv", "NewServer") {
		return false
	}
	var compose, fullBinding, mount, internalMount ast.Stmt
	for _, stmt := range serve.Body.List {
		switch syntax := stmt.(type) {
		case *ast.IfStmt:
			if syntax.Init == nil && syntax.Else == nil && len(syntax.Body.List) >= 2 &&
				childAuthorityText(syntax.Cond) == "fullStartup != nil" &&
				childAuthoritySame(syntax.Body.List[0], "participants, composeErr := wireFullStartupServices(ctx, fullStartup, kanameRepo, svcs, pool)") &&
				childAuthoritySame(syntax.Body.List[1], `if composeErr != nil { return startupFailureAt(fmt.Errorf("authority-protocol full public composition: %w", composeErr)) }`) {
				compose, fullBinding = stmt, syntax.Body.List[0]
			}
		case *ast.ExprStmt:
			if childAuthoritySame(stmt, "registerPublicServices(publicAdmission.Registrar(grpcSrv), svcs, opsRepo)") {
				mount = stmt
			}
			if childAuthoritySame(stmt, "registerInternalServices(admission.internalRegistrar(internalSrv), svcs, pool, cfg, logger)") {
				internalMount = stmt
			}
		}
	}
	if compose == nil || mount == nil || internalMount == nil ||
		services.Pos() >= compose.Pos() || compose.End() >= mount.Pos() ||
		server.Pos() >= mount.Pos() || mount.End() >= internalMount.Pos() {
		return false
	}
	// Допустимые ссылки на весь экземпляр уже разобраны выше. Остальные
	// ветви могут читать его поля, но не передавать или заменять сам экземпляр.
	valid := true
	ast.Inspect(serve.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case ast.Stmt:
			if node == services || node == mount || node == internalMount || node == fullBinding {
				return false
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND && routeSelector(node.X, "svcs", "childRegistrationHandler") {
				valid = false
			}
		case *ast.SelectorExpr:
			if routeIdent(node.X, "svcs") {
				return false
			}
		case *ast.Ident:
			if node.Name == "svcs" {
				valid = false
			}
		}
		return valid
	})
	return valid
}

// Тело регистрации и отклонение попытки используют решение о том же родителе,
// которое транзакция повторно запрашивает после перехода к writer.
func childAuthorityFinalWriteGate(once, body, final *ast.FuncDecl) bool {
	if !childAuthorityStatements(once,
		"decision := &resourceDecisionTx{Tx: rc, lifetime: lifetime, owner: writer}",
		"version, err = stage.applyChildBody(ctx, decision, proposal)",
		"if err != nil { return time.Time{}, err }",
	) || !childAuthorityStatements(final,
		"principal, ok := operations.PrincipalFromContextOK(ctx)",
		"if !ok || principal != a.principal || subject != a.subject || relation != a.target.ParentAction || object != a.target.ParentObject { return false, domain.ErrUserChildRegistrationRefused }",
	) || !childAuthorityStatements(final,
		"semantic := newSemanticAuthorityWriter(writer, a.native.lifetime.bundle)",
		"allowed, err := semantic.SemanticRelationChecker().Check(ctx, subject, relation, object)",
		"if err != nil || !allowed { return false, err }",
	) {
		return false
	}
	at := childAuthorityStatementIndex(body,
		"allowed, err := authorization.checkFinal(ctx, tx.owner, authorization.subject, target.ParentAction, target.ParentObject)",
		"if err != nil { return time.Time{}, err }",
		"if !allowed { return time.Time{}, childFinalDenied }",
		"var encoded []byte",
		"if err := tx.QueryRow(ctx, `SELECT kaname.authority_child_registration_begin_body_v1($1::jsonb)`, proposal.intent).Scan(&encoded); err != nil { return time.Time{}, err }",
	)
	if at < 0 || routeLocalBindings(body)["authorization"] != 1 || routeLocalBindings(body)["target"] != 1 {
		return false
	}
	if !childAuthorityStatements(body, "authorization := s.authorization", "target := authorization.target") {
		return false
	}
	// До FINAL исходный writer не передаётся другим функциям и не
	// вызывает SQL. Известная проверка lifetime использует только поля.
	for _, stmt := range body.Body.List[:at] {
		if routeAnyCall(stmt, func(call *ast.CallExpr) bool {
			for _, arg := range call.Args {
				if routeBareReceiver(arg, "tx") {
					return true
				}
			}
			selector, ok := routeUnparen(call.Fun).(*ast.SelectorExpr)
			return ok && (routeIdent(selector.X, "tx") || routeSelector(selector.X, "tx", "Tx"))
		}) {
			return false
		}
	}
	return true
}

// Именованные результаты принадлежат попытке. Единственная отложенная
// функция закрывает попытку и обнуляет версию при ненулевой ошибке.
func childAuthorityAttemptCleanup(once *ast.FuncDecl) bool {
	if once == nil || once.Body == nil || once.Type.Results == nil || len(once.Type.Results.List) != 2 {
		return false
	}
	for i, name := range []string{"version", "err"} {
		names := once.Type.Results.List[i].Names
		if len(names) != 1 || names[0].Name != name {
			return false
		}
	}
	var cleanup *ast.DeferStmt
	for _, stmt := range once.Body.List {
		deferred, ok := stmt.(*ast.DeferStmt)
		if !ok {
			continue
		}
		if cleanup != nil || !childAuthoritySame(deferred, `defer func() {
 lifetime.close()
 if active == nil { return }
 cleanup := rollbackResourceAttempt(ctx, active)
 if err == nil { err = cleanup } else { err = resourceFailedAttempt(err, cleanup, commitStarted) }
 if err != nil { version = time.Time{} }
}()`) {
			return false
		}
		cleanup = deferred
	}
	if cleanup == nil {
		return false
	}
	return !routeAny(once.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncLit:
			return v != cleanup.Call.Fun
		case *ast.UnaryExpr:
			return v.Op == token.AND && (routeAddressOfBinding(v.X, "version") || routeAddressOfBinding(v.X, "err"))
		case *ast.GoStmt:
			return true
		}
		return false
	})
}

// RR-стадия возвращает частичный снимок отсутствующего родителя, чтобы
// вызывающий метод выдал предметный отказ. Такой снимок нельзя отдать в writer.
func childAuthorityAbsentParent(stage, once *ast.FuncDecl) *ast.ReturnStmt {
	if !childAuthorityStatements(once,
		"if !stage.parentRegistered { return time.Time{}, childParentMissing }",
		"proposal, err := stage.proposal()",
		"if err != nil { return time.Time{}, err }",
	) {
		return nil
	}
	for i, stmt := range stage.Body.List {
		branch, ok := stmt.(*ast.IfStmt)
		if !ok || i == 0 || len(branch.Body.List) != 1 {
			continue
		}
		if childAuthoritySame(stmt, "if err != nil || !out.parentRegistered { return out, err }") &&
			childAuthoritySame(stage.Body.List[i-1], "_, out.parentRegistered, err = parents.mirror(ctx, parentType, parentID)") {
			ret, _ := branch.Body.List[0].(*ast.ReturnStmt)
			return ret
		}
	}
	return nil
}

func childAuthorityImports(file *ast.File, names map[string]string) bool {
	for alias, rel := range names {
		if routeImport(file, alias) != childAuthorityModule+rel || !routeAliasUnshadowed(file, alias) {
			return false
		}
	}
	return true
}

func childAuthorityConstructor(file *ast.File, name, typ, field, pkg, input string) bool {
	if !routeConstructor(file, name, typ, "", -1) || !routeFieldType(file, typ, field, pkg, input) {
		return false
	}
	fn := routeFunction(file, name)
	if len(fn.Type.Params.List) != 1 || !routeType(file, fn.Type.Params.List[0].Type, pkg, input) || len(fn.Type.Params.List[0].Names) != 1 {
		return false
	}
	ret := fn.Body.List[0].(*ast.ReturnStmt)
	lit := routeReturnedLiteral(ret.Results[0], typ)
	for _, element := range lit.Elts {
		kv := element.(*ast.KeyValueExpr)
		if routeIdent(kv.Key, field) && routeIdent(kv.Value, fn.Type.Params.List[0].Names[0].Name) {
			return true
		}
	}
	return false
}

func childAuthorityServes(fn *ast.FuncDecl, receiver, field, method string) bool {
	return fn != nil && routeBindingUntouched(fn, receiver, field) && routeExecutableCall(fn.Body, func(c *ast.CallExpr) bool {
		return routeNestedSelector(c.Fun, receiver, field, method)
	})
}

// Сопоставляются соседние AST statements. Вложенный блок не может служить
// свидетельством порядка у вызывающего метода.
func childAuthorityStatements(fn *ast.FuncDecl, expected ...string) bool {
	return childAuthorityStatementIndex(fn, expected...) >= 0
}

func childAuthorityStatementIndex(fn *ast.FuncDecl, expected ...string) int {
	if fn == nil || fn.Body == nil || len(expected) == 0 || len(fn.Body.List) < len(expected) {
		return -1
	}
	patterns := make([]string, len(expected))
	for i, source := range expected {
		patterns[i] = childAuthorityStatementPattern(source)
		if patterns[i] == "" {
			return -1
		}
	}
	for i := 0; i+len(patterns) <= len(fn.Body.List); i++ {
		matched := true
		for j, pattern := range patterns {
			if childAuthorityText(fn.Body.List[i+j]) != pattern {
				matched = false
				break
			}
		}
		if matched {
			return i
		}
	}
	return -1
}

func childAuthoritySame(node ast.Node, statement string) bool {
	pattern := childAuthorityStatementPattern(statement)
	return pattern != "" && childAuthorityText(node) == pattern
}

func childAuthorityStatementPattern(source string) string {
	f, err := parser.ParseFile(token.NewFileSet(), "proof.go", "package proof; func f(){"+source+"}", parser.SkipObjectResolution)
	if err != nil {
		return ""
	}
	decl, ok := f.Decls[0].(*ast.FuncDecl)
	if !ok || len(decl.Body.List) != 1 {
		return ""
	}
	return childAuthorityText(decl.Body.List[0])
}

func childAuthorityText(node ast.Node) string {
	var out bytes.Buffer
	if err := printer.Fprint(&out, token.NewFileSet(), node); err != nil {
		return ""
	}
	return strings.Join(strings.Fields(out.String()), " ")
}

func childAuthoritySingleResult(fn *ast.FuncDecl, empty string, partial *ast.ReturnStmt) bool {
	if fn == nil || fn.Body == nil || len(fn.Body.List) == 0 {
		return false
	}
	last, ok := fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(last.Results) != 2 || !routeIdent(last.Results[1], "nil") {
		return false
	}
	valid := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BranchStmt:
			// Break/continue обслуживают локальные конечные списки. Такая
			// форма сама по себе не может перепрыгнуть проверяемый return.
			if node.Label != nil || node.Tok == token.GOTO || node.Tok == token.FALLTHROUGH {
				valid = false
			}
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if node != last && node != partial && (len(node.Results) != 2 || childAuthorityText(node.Results[0]) != empty || routeIdent(node.Results[1], "nil")) {
				valid = false
			}
		}
		return valid
	})
	return valid
}
