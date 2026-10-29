// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// update.go — UpdateRoleUseCase. Только custom; account_id / is_system immutable.
// system-role update reject'ится sync ("system role is read-only").

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

type UpdateRoleInput struct {
	ID          domain.RoleID
	Name        *domain.RoleName
	Description *domain.Description
	Rules       domain.Rules
	// Labels — own-resource tenant-facing метки самого ресурса Role (НЕ путать с
	// Rule.MatchLabels, отбирающим объекты под грантом). mutable; делают Role
	// label-selectable наравне с account/project (iam-direct ARM_LABELS).
	Labels     domain.Labels
	UpdateMask []string
	// ResourceVersion — токен оптимистической блокировки (`xmin`), полученный
	// прежним `Get`/`List`; на правке правил сторожит от параллельной правки
	// (A-08).
	ResourceVersion string
}

var roleMutableFields = map[string]struct{}{
	"name":        {},
	"description": {},
	"rules":       {},
	"labels":      {},
}

var roleImmutableFields = map[string]string{
	"account_id": "accountId is immutable after Role.Create",
	"accountId":  "accountId is immutable after Role.Create",
	"is_system":  "isSystem is immutable after Role.Create",
	"isSystem":   "isSystem is immutable after Role.Create",
	"id":         "id is immutable after Role.Create",
	"created_at": "createdAt is immutable after Role.Create",
	"createdAt":  "createdAt is immutable after Role.Create",
	// `permissions` — скомпилированная производная проекция, прямой правке не подлежит.
	"permissions": "permissions is immutable after Role.Create",
}

type UpdateRoleUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// reconciler — сверка кортежей прав по привязкам при смене прав роли. Может
	// быть не провязан: тогда правка роли проходит, а кортежи активных привязок не
	// сверяются — так бывает только в отдельных пробах путей без смены прав.
	// Реализует `access_binding.RoleTupleReconciler`, провязывает корень службы.
	reconciler TupleReconciler
	// membership — модель правил: после фиксации смены правил заново
	// материализует членство по меткам каждой АКТИВНОЙ привязки роли (проход и
	// сторож предела). Может быть не провязан: пробы путей без правил его не
	// ставят, а периодический обход сводит состояние и сам.
	membership RulesMembershipFanout
	// objects — после фиксации материализует доступ к роли КАК К ОБЪЕКТУ
	// (`iam.role`). Не то же, что `membership` выше: тот заново материализует, что
	// ПРАВИЛА роли дают на других объектах, этот — кто может добраться до ЭТОЙ
	// роли после смены её СОБСТВЕННЫХ меток. Может быть не провязан; событие
	// сверки, зафиксированное вместе с правкой, и периодический обход остаются
	// страховкой.
	objects ObjectReconciler
	logger  *slog.Logger
	// cat — источник КАТАЛОЖНОГО ФАКТА (kacho#1816). Обязателен по той же
	// причине, что и у создания: проекция «роль → тип × глагол» пишется в той же
	// транзакции, и пустая проекция оставила бы вердикт определённым наполовину.
	cat catalog.Source
	// keys — какие ключи, названные правилами, зарегистрированы на приёме (kaname#963).
	keys shared.RegisteredKeys
}

// WithRegisteredKeys — чтение регистрации ключей, названных в resourceNames, на
// приёме правки (kaname#963, Р8). Провязывает корень службы.
func (u *UpdateRoleUseCase) WithRegisteredKeys(k shared.RegisteredKeys) *UpdateRoleUseCase {
	u.keys = k
	return u
}

func NewUpdateRoleUseCase(r Repo, opsRepo operations.Repo, cat catalog.Source) *UpdateRoleUseCase {
	return &UpdateRoleUseCase{repo: r, opsRepo: opsRepo, cat: cat}
}

// WithTupleReconciler провязывает сверку кортежей прав по привязкам. Может быть не провязан.
func (u *UpdateRoleUseCase) WithTupleReconciler(r TupleReconciler) *UpdateRoleUseCase {
	u.reconciler = r
	return u
}

// WithMembershipFanout провязывает проход членства по правилам роли (сторож
// предела и сверку каждой привязки после фиксации). Может быть не провязан.
func (u *UpdateRoleUseCase) WithMembershipFanout(m RulesMembershipFanout) *UpdateRoleUseCase {
	u.membership = m
	return u
}

// WithObjectReconciler провязывает материализацию доступа к роли как к объекту
// после фиксации правки СОБСТВЕННЫХ меток (паритет с повторной регистрацией
// ресурса чужой службой — см. doUpdate). Необязателен: без него остаётся одна очередь.
// Журнал нужен только для отчёта о сорванном проходе (событие и обход всё равно сведут).
func (u *UpdateRoleUseCase) WithObjectReconciler(r ObjectReconciler, logger *slog.Logger) *UpdateRoleUseCase {
	u.objects = r
	u.logger = logger
	return u
}

func (u *UpdateRoleUseCase) Execute(ctx context.Context, in UpdateRoleInput) (*operations.Operation, error) {
	if err := shared.ValidateResourceID(string(in.ID), domain.PrefixRole, "role"); err != nil {
		return nil, err
	}
	if err := shared.ValidateUpdateMask(in.UpdateMask, roleMutableFields, roleImmutableFields); err != nil {
		return nil, err
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Роль читается ВМЕСТЕ с токеном `xmin`, чтобы правка в транзакции исполнителя
	// стояла под сторожем от параллельной правки той же роли (две правки, каждая
	// со сверкой кортежей от своей проекции роли, — расхождение ведомости с моделью).
	// Токен снимается на синхронном пути и уходит в `UpdateCAS` транзакции
	// исполнителя; проигравшая получает FAILED_PRECONDITION, и вся её транзакция
	// записи (правка и сверка кортежей) откатывается целиком (запрет #10).
	current, version, err := rd.Roles().GetWithVersion(ctx, in.ID)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	if current.IsSystem {
		_ = rd.Rollback(ctx)
		// redesign-2026 F6 (IAM-1-16): системная роль (посев, кластерный ярус) не
		// правится — FAILED_PRECONDITION, паритет с `RoleService.Delete` и контрактом
		// (запрещает правку состояние ресурса, а не запрос).
		return nil, status.Error(codes.FailedPrecondition, "System role is read-only and cannot be updated")
	}
	_ = rd.Rollback(ctx)
	// Здесь — только отказ анониму. КТО вправе править свою роль, решает МОДЕЛЬ:
	// край спрашивает `v_update@iam_role:<role_id>` до обращения к службе. Прежняя
	// проверка «вызывающий — владелец аккаунта роли» была у́же этого пообъектного
	// отношения и невыполнима машинной личностью —
	// §«Авторизация живёт в
	// МОДЕЛИ, а не в самодельных проверках». (Отказ системной роли выше —
	// проверка СОСТОЯНИЯ ресурса, а не авторизация, и она остаётся.)
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}

	target := current
	var changed []string
	if in.Name != nil && shared.MaskAllows(in.UpdateMask, "name") && *in.Name != current.Name {
		target.Name = *in.Name
		changed = append(changed, "name")
	}
	if in.Description != nil && shared.MaskAllows(in.UpdateMask, "description") && *in.Description != current.Description {
		target.Description = *in.Description
		changed = append(changed, "description")
	}
	// Модель правил: правила — авторское изменяемое поле. При их смене заново
	// компилируется ВНУТРЕННЯЯ проекция прав (ветви якоря и имён; отбор по меткам
	// исключён; потолок 1024), и хранятся обе. Сами `permissions` — неизменяемый
	// вход (отвергнуты маской правки выше).
	// Набор модулей — ЖИВЫЕ строки каталога (kacho#1927), тот же снимок, которым
	// ниже строится проекция глаголов: обе стороны правила обязаны судиться
	// согласованным множеством, а не двумя моментами времени.
	facts := u.cat.Facts()
	if in.Rules != nil && shared.MaskAllows(in.UpdateMask, "rules") {
		// Сперва судятся новые правила (точные отказы мощности, подстановки, ленты),
		// затем компиляция (держит потолок скомпилированного 1024).
		if verr := in.Rules.Validate(domain.PolicyOfRole(current.IsSystem, current.OwnerModule), facts); verr != nil {
			return nil, shared.MapValidationErr(verr)
		}
		// Ворота выдаваемого токена — паритет с созданием (см. rules_catalog.go):
		// правка, заменившая годный токен опечаткой, иначе молча ПОНИЗИЛА бы
		// действующую выдачу до пустой.
		// Источник — ТОТ ЖЕ снимок живых строк, что и у сегмента модуля выше
		// (kacho#1993). Паритет с Create здесь несущий: приняв роль над заведённым
		// типом и отвергнув её ПРАВКУ, платформа сделала бы роль неисправимой.
		if verr := validateRuleCatalog(in.Rules, current.IsSystem, facts); verr != nil {
			return nil, shared.MapValidationErr(verr)
		}
		compiled, cerr := domain.CompileRules(in.Rules)
		if cerr != nil {
			return nil, shared.MapValidationErr(cerr)
		}
		target.Rules = in.Rules
		target.Permissions = compiled
		changed = append(changed, "rules")
		held, herr := heldNamesOf(ctx, u.keys, in.Rules)
		if herr != nil {
			return nil, herr
		}
		target.HeldNames = held
	}
	// labels — own-resource метки. Применяются, только если mask их разрешает
	// (или пустой mask = full-PATCH) И значение изменилось. Изменение labels
	// триггерит iam-direct re-материализацию (см. doUpdate reconcile-event).
	if newLabels, apply := shared.ResolveLabelsUpdate(in.UpdateMask, in.Labels); apply && !shared.LabelsEqual(newLabels, current.Labels) {
		target.Labels = newLabels
		changed = append(changed, "labels")
	}
	if err := target.Validate(facts); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	// Роль, выданная системному классу, пишущего глагола не получает (Р4,
	// SC-22). Здесь — синхронный ответ до заведения операции; последнее слово —
	// у записи (`GuardSystemClassReads` под замком строки роли в doUpdate):
	// выдача классу, заведённая между этим чтением и записью, не проходит мимо.
	if slices.Contains(changed, "rules") && !target.GrantsReadsOnly() {
		if err := u.refuseIfBoundToSystemClass(ctx, in.ID); err != nil {
			return nil, err
		}
	}

	// Оптимистическая блокировка: если вызывающий прислал `resource_version` И правила
	// меняются, версия обязана совпасть с прочитанной на синхронном пути; устаревший
	// токен — FAILED_PRECONDITION (роль правили параллельно). Без токена единственный
	// сторож — CAS по `xmin` в транзакции исполнителя ниже (побеждает последний).
	if in.ResourceVersion != "" && slices.Contains(changed, "rules") && in.ResourceVersion != version {
		return nil, shared.MapRepoErr(
			iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Role was modified concurrently, retry"))
	}

	// Сторож предела: смена правил запускает сверку по каждой АКТИВНОЙ привязке роли.
	// Роль, которую несёт больше привязок, чем предел контракта, отвергается
	// СИНХРОННО (до операции): одна правка роли не вправе запустить проход без границы.
	// Сверяется только при реальной смене правил и провязанном проходе. Это мягкий
	// сторож по наилучшему усилию (счёт читается здесь, проход — позже), а НЕ жёсткий
	// потолок: параллельная выдача может перевалить предел между сверкой и проходом.
	// Это приемлемо: предел защищает от грубо раздутого прохода, а сверка каждой
	// привязки идемпотентна и ограничена привязкой, так что малый перебор безвреден.
	if u.membership != nil && slices.Contains(changed, "rules") {
		n, cerr := u.membership.CountActiveBindings(ctx, in.ID)
		if cerr != nil {
			return nil, shared.MapRepoErr(cerr)
		}
		if n > MaxRoleFanoutBindings {
			return nil, status.Errorf(codes.FailedPrecondition,
				"role carried by too many bindings to update atomically; split role")
		}
	}

	actor := authzguard.PrincipalUserID(ctx)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update role %s", in.ID),
		&iamv1.UpdateRoleMetadata{RoleId: string(in.ID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	maskCopy := append([]string{}, in.UpdateMask...)
	changedCopy := append([]string{}, changed...)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doUpdate(ctx, target, maskCopy, actor, changedCopy, version)
	})
	return &op, nil
}

func (u *UpdateRoleUseCase) doUpdate(ctx context.Context, r domain.Role, mask []string, actor string, changed []string, expectedVersion string) (*anypb.Any, error) {
	// Признак превью — в ТОЙ ЖЕ транзакции и после записи проекций (kaname#76): эхо
	// описывает роль, которую эта транзакция записала, на обоих путях возврата.
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Role, error) {
			upd, werr := u.writeUpdate(ctx, w, r, mask, actor, changed, expectedVersion)
			if werr != nil {
				return domain.Role{}, werr
			}
			return shared.WithPreviewHolding(ctx, w, u.cat, upd)
		})
	if err != nil {
		return nil, err
	}
	return u.afterUpdate(ctx, updated, changed)
}

// writeUpdate — записи правки в транзакции записи: строка роли под сторожем
// версии, кортежи привязок, три проекции правил, аудит и событие сверки.
func (u *UpdateRoleUseCase) writeUpdate(ctx context.Context, w Writer, r domain.Role, mask []string,
	actor string, changed []string, expectedVersion string) (domain.Role, error) {
	// CAS по `xmin`: правка в транзакции исполнителя стоит под версией, снятой на
	// синхронном пути. Параллельная правка, зафиксированная первой, сдвинула `xmin`
	// → CAS не находит строки → ErrFailedPrecondition, и вся транзакция записи
	// (вместе со сверкой кортежей ниже) откатывается.
	if slices.Contains(changed, "rules") {
		if gerr := w.RolesW().GuardSystemClassReads(ctx, r.ID, r.GrantsReadsOnly()); gerr != nil {
			return domain.Role{}, gerr
		}
	}
	upd, uerr := w.RolesW().UpdateCAS(ctx, r, mask, expectedVersion)
	if uerr != nil {
		return domain.Role{}, uerr
	}
	if len(changed) == 0 {
		return upd, nil
	}
	// Сменились правила (а с ними скомпилированные права) — кортежи АКТИВНЫХ
	// привязок роли сверяются с новыми правами В ЭТОЙ транзакции записи, неделимо с
	// правкой роли (запрет #10). Без этого активная привязка сохранила бы кортеж
	// прежнего яруса после понижения (сирота — постоянная привилегия). Проход
	// ограничен активными привязками одной роли и идемпотентен (ярус не сменился —
	// пустая разница). Может быть не провязан в пробах путей без правил.
	if u.reconciler != nil && slices.Contains(changed, "rules") {
		if rerr := u.reconciler.ReconcileRoleTuples(ctx, w, upd.ID, upd); rerr != nil {
			return domain.Role{}, rerr
		}
	}
	// Явная модель: `role_rule_selectors` приводятся к новым ЕДИНЫМ материализующим
	// правилам (якорь, имена, метки) в ТОЙ ЖЕ транзакции записи (запрет #10), чтобы
	// проход членства после фиксации (и быстрый путь сверки, и обход) видел новые
	// селекторы. Снятое правило снимает здесь свой селектор; заново материализует
	// членство каждой привязки (с немедленным отзывом по `rule_fp`) проход после
	// фиксации.
	if slices.Contains(changed, "rules") {
		// Каталожный факт — один на обе стороны (довод — на создании).
		facts := u.cat.Facts()
		// Политика — та же, которой правила судились (kaname#1006).
		policy := domain.PolicyOfRole(r.IsSystem, r.OwnerModule)
		if serr := w.RolesW().ReplaceRuleSelectors(ctx, upd.ID,
			facts.GrantSelectors(upd.Rules.MaterializingSelectors(), policy)); serr != nil {
			return domain.Role{}, serr
		}
		// Та же пара, что на создании: снятый из правил глагол обязан
		// исчезнуть из проекции, иначе отзыв права не применяется — молча,
		// потому что добавление проходит успешно.
		if verr := w.RolesW().ReplaceRoleVerbs(ctx, upd.ID,
			facts.RoleVerbsFromSelectors(upd.Rules.MaterializingSelectors(), policy)); verr != nil {
			return domain.Role{}, verr
		}
		// Проекция ОБЪЯВЛЕННЫХ сегментов — третья сторона того же правила, и
		// пишется она в той же транзакции по той же причине. Отличие от двух
		// предыдущих в том, ЧТО кладётся: те несут только резолвящееся, эта —
		// КАЖДЫЙ объявленный сегмент. На ней стоят ключи в каталог, и именно
		// она отвергает правило, называющее ресурс или глагол, которых на
		// платформе нет либо больше нет (kacho#1030, миграция 20260901113757).
		//
		// Своей проверки каталога здесь НЕТ намеренно: между «спросить» и
		// «записать» помещается снятие ресурса, и правило пережило бы свой
		// референт (запрет #10). Судит ОПЕРАТОР ВСТАВКИ.
		if rerr := w.RolesW().ReplaceRuleRefs(ctx, upd.ID,
			domain.RuleRefsOf(upd.Rules)); rerr != nil {
			return domain.Role{}, rerr
		}
	}
	// `changed_fields` записывает, ЧТО изменилось (например `["permissions"]`); полный
	// набор прав в запись намеренно НЕ кладётся.
	if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
		EventType:       auditEventRoleUpdated,
		TenantAccountID: string(upd.AccountID),
		Payload: map[string]any{
			"actor":          actor,
			"resource_type":  "role",
			"resource_id":    string(upd.ID),
			"account_id":     string(upd.AccountID),
			"changed_fields": changed,
		},
	}); aerr != nil {
		return domain.Role{}, aerr
	}
	// Изменение own-resource labels может изменить membership iam-direct
	// селектора (правило, матчащее iam.role по меткам). Co-commit reconcile-event
	// в ЭТОЙ writer-tx (ban #10, паритет с user/SA Update) — reconciler ре-оценит
	// затронутые iam.role selector-биндинги (≤2s): label add → грант появляется,
	// label remove/change → eager fall-out. Только при изменении labels.
	if slices.Contains(changed, "labels") {
		if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.role", string(upd.ID)); rerr != nil {
			return domain.Role{}, rerr
		}
	}
	return upd, nil
}

// afterUpdate — шаги после фиксации правки и эхо операции.
func (u *UpdateRoleUseCase) afterUpdate(ctx context.Context, updated domain.Role, changed []string) (*anypb.Any, error) {
	// Смена СОБСТВЕННЫХ меток ⇒ мог смениться круг тех, кто достаёт до ЭТОЙ роли ⇒
	// этот ОДИН объект материализуется заново сейчас, а не после очереди сверки.
	// `iam.role` отбирается метками, поэтому снятие метки, с которой совпадает выдача
	// по меткам, есть ОТЗЫВ. Межслужебный близнец получает это даром: службы-владельцы
	// ресурсов повторно зовут `InternalIAMService.RegisterResource` при правке меток, а
	// тот гонит `ReconcileObjectForward` в процессе — сторож снятия устаревшего видит,
	// что у объекта уже есть члены, отдаёт его ПОЛНОМУ `ReconcileObject`, и устаревшая
	// выдача умирает там. У родного пути службы такого прохода не было: он ставил
	// событие в `resource_reconcile_outbox` и возвращался, и задержка отзыва
	// становилась ГЛУБИНОЙ ОБЩЕЙ ОЧЕРЕДИ СВЕРКИ — строго по порядку, один исполнитель
	// на ~5 событий/с, каждое — ПОЛНЫЙ пересчёт области, против набора проб края,
	// дающего 5–8 событий/с, то есть очередь на минуты. Замер на стенде по соседнему
	// пути `iam.project`: событие снятия метки поставлено в 19:59:18.97 и выбрано в
	// 20:06:49.82 (7 мин 30 с); кортеж жил, пока периодический обход (30 с) не дошёл
	// до привязки в 20:00:23, через 65 с после снятия.
	//
	// Не то же, что проход по правилам ниже: тот заново материализует, что роль ДАЁТ
	// на других объектах, этот — доступ К объекту-роли. Ставится РАНЬШЕ прохода по
	// правилам намеренно: маска с «rules» и «labels» не вправе дать сорванному проходу
	// по правилам (он выходит рано) погасить ускорение отзыва по меткам; транзакция
	// записи здесь уже зафиксирована.
	//
	// ВНЕ пути готовности (запрет #9): ставится отсоединённо, потому что
	// `Operation.done` сообщает, что строка роли записана, а не что её кортежи
	// сошлись. Событие сверки, зафиксированное вместе с правкой, и периодический обход
	// остаются страховкой «хотя бы раз», так что меняется КОГДА отзыв виден, а не
	// СЛУЧИТСЯ ЛИ он.
	if slices.Contains(changed, "labels") && u.objects != nil {
		id := string(updated.ID)
		shared.GoPostCommit(ctx, u.logger, "role label re-materialization", func(ctx context.Context) {
			if rerr := u.objects.ReconcileObjectForward(ctx, "iam.role", id); rerr != nil && u.logger != nil {
				u.logger.Error("role update: label re-materialization failed (reconcile event + sweep will retry)",
					"role_id", id, "err", rerr)
			}
		})
	}

	// Проход членства: после фиксации смены правил и приведения селекторов заново
	// материализуется членство по меткам каждой АКТИВНОЙ привязки роли (каждая — в
	// СВОЕЙ транзакции записи, идемпотентно). Пообъектные члены снятого правила
	// отзываются немедленно по `rule_fp` (без остатка); объекты, совпавшие с новыми и
	// правлеными правилами, материализуются. Ограничен синхронным сторожем счёта
	// выше; может быть не провязан.
	//
	// ВНЕ пути готовности (запрет #9), как проход меток выше, и по той же причине.
	// Прежде он шёл в теле исполнителя, и его отказ возвращался из него, так что
	// операция несла ОШИБКУ о правке, УЖЕ зафиксированной: строка роли, проекция
	// селекторов и запись аудита записаны до этой строки. Вред — в том, что
	// вызывающий делает с такой ошибкой: решает, что правила не применились, и
	// повторяет с версией ресурса, снятой до первой попытки, которую его же
	// зафиксированная правка уже сдвинула, — повтор отвергается как параллельная
	// правка, называющая соперника, которого не было. А права при этом ИЗМЕНЕНЫ.
	//
	// Повод не экзотический: проход берёт исключительный консультативный замок на
	// привязку — тот же ключ, что обход, отзыв и истечение, — и предела ожидания
	// замка нет: ожидание, дошедшее до предела оператора, — ошибка. Начиная с
	// нескольких сотен привязок потолком становится срок самой операции.
	//
	// Отсоединение меняет КОГДА сойдётся членство, а не СОЙДЁТСЯ ЛИ: событие сверки,
	// зафиксированное вместе с правкой, и периодический обход (30 с) остаются
	// страховкой «хотя бы раз».
	if u.membership != nil && slices.Contains(changed, "rules") {
		id := updated.ID
		shared.GoPostCommit(ctx, u.logger, "role rules membership fan-out", func(ctx context.Context) {
			if ferr := u.membership.ReconcileActiveBindings(ctx, id); ferr != nil && u.logger != nil {
				u.logger.Error("role update: rules membership fan-out failed (reconcile event + sweep will retry)",
					"role_id", string(id), "err", ferr)
			}
		})
	}
	// Эхо мутации проецируется тем же набором, что и чтение: иначе `Create`
	// вернул бы превью, собранное другим источником, чем последующий `Get`.
	updated.TypeVerbs = u.cat.Facts().RolePreviewLookup()
	return marshalRole(updated)
}

// refuseIfBoundToSystemClass — синхронный отказ правке, дающей пишущий глагол
// роли, выданной системному классу (SC-22).
func (u *UpdateRoleUseCase) refuseIfBoundToSystemClass(ctx context.Context, id domain.RoleID) error {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	bound, err := rd.Roles().BoundToSystemClass(ctx, id)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	if bound {
		return status.Error(codes.FailedPrecondition, domain.RoleBoundToSystemClassText(id))
	}
	return nil
}
