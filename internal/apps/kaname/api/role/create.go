// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// create.go — CreateRoleUseCase. Только custom-role (system-role нельзя
// создать через API — только seed-миграция). Permissions проверяются
// domain.Permissions.Validate + DB CHECK roles_permissions_valid.

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// ObjectReconciler — узкий порт (rbac-contract-a-fix, C-01b): СИНХРОННО
// материализует пообъектный доступ каждой привязки, чей селектор совпадает со
// свежесозданной ролью, сразу после фиксации создания. Плоская модель прав
// сняла каскад доступа `<rel> from account` у `iam_role`, поэтому пообъектный
// кортеж владельца и администратора аккаунта материализуется пообъектно;
// синхронный вызов закрывает гонку «чтение после создания», которую
// асинхронная выборка иначе проигрывала бы. Реализует `reconcile.Reconciler`.
// Может быть не провязан: событие сверки и обход — страховка «хотя бы раз».
type ObjectReconciler interface {
	// ReconcileObjectForwardNoStale — ДОБАВЛЯЮЩИЙ быстрый путь для свежесозданной
	// роли КАК ОБЪЕКТА (`iam.role`): материализует ТОЛЬКО пообъектные кортежи
	// владельца и администратора этой роли по совпавшим привязкам и не держит
	// консультативного замка ВОВСЕ (ни исключительного, ни разделяемого, без
	// пересчёта области) — устранение отставания материализации кортежа
	// владельца при всплеске параллельных созданий. Если у объекта уже есть
	// члены, прозрачно уходит на ПОЛНЫЙ `ReconcileObject` (сторож снятия
	// устаревшего).
	ReconcileObjectForwardNoStale(ctx context.Context, objectType, objectID string) error
	// ReconcileObjectForward — СТОРОЖЕВОЙ вход того же прохода: он сперва читает,
	// есть ли у объекта члены, и при непустом наборе уходит на полный проход ради
	// снятия устаревших. Пути СОЗДАНИЯ он не нужен (доказательство — выше), но
	// остаётся в порту: его зовёт правка того же пакета, где прежние факты есть
	// и снятие устаревших — как раз предмет.
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
	// ReconcileObject — ПОЛНЫЙ исключительный проход по объекту (асинхронная
	// страховка «хотя бы раз»: снятие устаревшего, аудит, обход); его гонит исполнитель
	// сверки по событию, зафиксированному вместе с созданием, а не горячий путь создания.
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

type CreateRoleUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// cat — источник КАТАЛОЖНОГО ФАКТА: какие глаголы объявлены живым типом
	// (kacho#1816). Обязателен: проекция «роль → тип × глагол» без него пуста, а
	// пустая проекция — это не «наблюдение выключено», а вердикт, определённый
	// наполовину.
	cat catalog.Source
	// Необязательный писатель кортежа иерархии: после успешной вставки своей роли
	// пишет `iam_role:<id>#account@account:<acc>`, чтобы каскады прав в области
	// `iam_role` разрешались (`admin from account`). Системные роли сеются миграцией
	// и сюда не доходят никогда.
	relations  clients.RelationStore
	reconciler ObjectReconciler // rbac-contract-a-fix — optional, nil-safe
	logger     *slog.Logger
	// keys — какие ключи, названные правилами, зарегистрированы на приёме (kaname#963).
	keys shared.RegisteredKeys
}

// WithRegisteredKeys — чтение регистрации ключей, названных в resourceNames, на
// приёме (kaname#963, Р8): роль, принятая до снятия и записанная после, снятого
// ключа не называет. Провязывает корень службы.
func (u *CreateRoleUseCase) WithRegisteredKeys(k shared.RegisteredKeys) *CreateRoleUseCase {
	u.keys = k
	return u
}

func NewCreateRoleUseCase(r Repo, opsRepo operations.Repo, cat catalog.Source) *CreateRoleUseCase {
	return &CreateRoleUseCase{repo: r, opsRepo: opsRepo, cat: cat}
}

// WithRelationStore провязывает писатель кортежа иерархии «роль → аккаунт».
func (u *CreateRoleUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *CreateRoleUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithObjectReconciler провязывает синхронную пообъектную материализацию после
// фиксации (rbac-contract-a-fix, C-01b). Может быть не провязан.
func (u *CreateRoleUseCase) WithObjectReconciler(r ObjectReconciler) *CreateRoleUseCase {
	u.reconciler = r
	return u
}

func (u *CreateRoleUseCase) Execute(ctx context.Context, r domain.Role) (*operations.Operation, error) {
	// Anti-anonymous: anonymous custom Role с iam.*.* permissions → escalation prep.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	// kacho-iam#212: своя роль принадлежит РОВНО ОДНОЙ области — аккаунту либо проекту.
	// Системные роли сеются миграцией и через этот вызов не заводятся никогда. Страховка
	// — проверка базы `roles_definition_tier_xor`; здесь — понятный синхронный отказ раньше.
	accountSet := r.AccountID != ""
	projectSet := r.ProjectID != ""
	switch {
	case accountSet && projectSet:
		return nil, shared.InvalidArg("project_id", "Illegal argument: exactly one of account_id / project_id (a custom role is account- XOR project-scoped)")
	case !accountSet && !projectSet:
		return nil, shared.InvalidArg("account_id", "Illegal argument: one of account_id / project_id required (system roles are seeded via migration, not API)")
	case accountSet:
		if err := shared.ValidateResourceID(string(r.AccountID), domain.PrefixAccount, "account"); err != nil {
			return nil, err
		}
	default: // projectSet
		if err := shared.ValidateResourceID(string(r.ProjectID), domain.PrefixProject, "project"); err != nil {
			return nil, err
		}
	}
	// Sync: enforce is_system=false (только custom).
	r.IsSystem = false
	// Модель правил 2026 (A): вход — авторские правила; они компилируются во
	// ВНУТРЕННЮЮ проекцию прав (ветви якоря и имён; отбор по меткам НЕ
	// компилируется), и хранятся ОБЕ. Компиляция же держит потолок скомпилированного
	// 1024 (A-12). Непустые `rules[]` обязательны: создание одними правами API больше
	// не принимает (A требует правил); унаследованные роли на чтении остаются годными.
	if len(r.Rules) == 0 {
		return nil, shared.InvalidArg("rules", "Illegal argument rules (must be non-empty)")
	}
	// Авторские правила судятся ПЕРВЫМИ (мощность, подстановка, «ровно одно», лента),
	// чтобы негодное правило получило свой точный отказ (A-05/A-10/A-13), а не
	// сбивающий отказ потолка компиляции. Компилируется только годный набор;
	// компилятор держит потолок 1024 (A-12).
	// Набор модулей — ЖИВЫЕ строки каталога, а не литерал: снятый модуль
	// обязан перестать приниматься без перезапуска службы, а заведённый строкой
	// — начать приниматься без релиза (kacho#1927). Снимок один и тот же, что у
	// проекции глаголов ниже, поэтому обе стороны правила судятся согласованным
	// множеством, а не двумя моментами времени.
	facts := u.cat.Facts()
	if verr := r.Rules.Validate(domain.PolicyOfRole(r.IsSystem, r.OwnerModule), facts); verr != nil {
		return nil, shared.MapValidationErr(verr)
	}
	// Ворота выдаваемого токена: сегмент ресурса обязан быть ОПУБЛИКОВАННОЙ парой
	// `(module,resource)`, а не просто грамматически годным токеном. Без этого токен
	// с опечаткой компилировался бы в роль, сверяемую в НОЛЬ кортежей (сверка,
	// закрываясь, ПРОПУСКАЕТ неизвестный ключ), и получатель вечно получал бы 403 без
	// сигнала на роли, привязке или операции. Стоит ПОСЛЕ `Rule.Validate`, чтобы отказы
	// подстановки, «ровно одного» и ленты пришли первыми (они точнее), и ДО
	// `CompileRules`, чтобы скомпилированная проекция никогда не несла невыдаваемого
	// токена.
	// Источник — ТОТ ЖЕ снимок живых строк, которым выше судился сегмент МОДУЛЯ
	// и ниже строится проекция глаголов (kacho#1993): обе стороны правила обязаны
	// судиться согласованным множеством, а не двумя моментами времени и не двумя
	// словарями. Прежде здесь спрашивалась таблица, ПОРОЖДЁННАЯ СБОРКОЙ, и тип,
	// заведённый применением манифеста в работающем процессе, отвергался ею —
	// первое звено цепи «клиент завёл тип манифестом → получил права».
	if verr := validateRuleCatalog(r.Rules, r.IsSystem, facts); verr != nil {
		return nil, shared.MapValidationErr(verr)
	}
	compiled, cerr := domain.CompileRules(r.Rules)
	if cerr != nil {
		return nil, shared.MapValidationErr(cerr)
	}
	r.Permissions = compiled
	if err := r.Validate(facts); err != nil {
		return nil, shared.MapValidationErr(err)
	}
	held, err := heldNamesOf(ctx, u.keys, r.Rules)
	if err != nil {
		return nil, err
	}
	r.HeldNames = held

	roleID := ids.NewID(domain.PrefixRole)
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Create role %s", r.Name),
		&iamv1.CreateRoleMetadata{RoleId: roleID},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	r.ID = domain.RoleID(roleID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doCreate(ctx, r, actor)
	})
	return &op, nil
}

func (u *CreateRoleUseCase) doCreate(ctx context.Context, r domain.Role, actor string) (*anypb.Any, error) {
	created, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.Role, error) {
			inserted, ierr := w.RolesW().Insert(ctx, r)
			if ierr != nil {
				return domain.Role{}, ierr
			}
			// Явная модель 2026 P4 (КФ-3): `role_rule_selectors` приводятся к ЕДИНЫМ
			// материализующим правилам роли (якорь, имена, метки) в ТОЙ ЖЕ транзакции
			// записи (запрет #10), чтобы быстрый путь сверки и обход нашли привязки,
			// несущие эту роль, по событию смены зеркала (forward-mat, D-4). Ничего не
			// делает, когда материализующих правил у роли нет (унаследованная роль прав).
			//
			// Каталожный факт берётся ОДИН на обе стороны: глаголы правил в
			// селекторах и проекция роли — объединение тех же наборов (kaname#878),
			// и два снимка каталога развели бы их.
			facts := u.cat.Facts()
			// Политика — та же, которой правила судились выше: от владельца роли
			// зависит, влечёт ли правка удаление (kaname#1006).
			policy := domain.PolicyOfRole(r.IsSystem, r.OwnerModule)
			if serr := w.RolesW().ReplaceRuleSelectors(ctx, inserted.ID,
				facts.GrantSelectors(inserted.Rules.MaterializingSelectors(), policy)); serr != nil {
				return domain.Role{}, serr
			}
			// Проекция глаголов — ВТОРАЯ сторона того же правила, и пишется она в
			// той же транзакции: селекторы отвечают «подходит ли объект», проекция
			// — «разрешено ли действие». Записать одну без другой значит оставить
			// вердикт наполовину определённым, а расхождение проявится не отказом,
			// а неверным ответом.
			if verr := w.RolesW().ReplaceRoleVerbs(ctx, inserted.ID,
				facts.RoleVerbsFromSelectors(inserted.Rules.MaterializingSelectors(), policy)); verr != nil {
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
			if rerr := w.RolesW().ReplaceRuleRefs(ctx, inserted.ID,
				domain.RuleRefsOf(inserted.Rules)); rerr != nil {
				return domain.Role{}, rerr
			}
			// Тело аудита роли несёт идентификатор, имя и актора — НЕ полную матрицу прав
			// (раздувание тела; 5.2-17).
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventRoleCreated,
				TenantAccountID: string(inserted.AccountID),
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "role",
					"resource_id":   string(inserted.ID),
					"account_id":    string(inserted.AccountID),
					"name":          string(inserted.Name),
				},
			}); aerr != nil {
				return domain.Role{}, aerr
			}
			// Намерение кортежа иерархии «роль → аккаунт» (указатель на родителя)
			// фиксируется в ТОЙ ЖЕ транзакции записи (запрет #10). В ПЛОСКОЙ модели прав
			// (Contract-A) указатель `account:<acc>#account@iam_role:<id>` сам доступа
			// больше не даёт — каскад доступа `<rel> from account` у `iam_role` снят. Он
			// оставлен ребром иерархии и родословной владения; ФАКТИЧЕСКИЙ доступ
			// владельца (и создателя) к этой роли МАТЕРИАЛИЗУЕТ пообъектно сверка (см.
			// событие сверки ниже), а не этот указатель.
			//
			// kacho-iam#212: указатель получают ТОЛЬКО роли уровня аккаунта (у типа
			// `iam_role` одно отношение иерархии `account`, предка `project` нет).
			if inserted.AccountID != "" {
				if ferr := w.EmitFGARelationWrite(ctx, []service.RelationTuple{
					{User: "account:" + string(inserted.AccountID), Relation: "account", Object: "iam_role:" + string(inserted.ID)},
				}); ferr != nil {
					return domain.Role{}, ferr
				}
			}
			// rbac-contract-a-fix (forward-mat, C-01b): событие сверки фиксируется в ТОЙ
			// ЖЕ транзакции записи (запрет #10), чтобы сверка заново оценила привязку
			// владельца `*.*` (и всякую другую по якорю либо именам) против новой роли и
			// материализовала пообъектный кортеж администратора и `v_*` на
			// `iam_role:<id>` — доступ, которого снятый каскад `from account` плоской
			// модели больше не выводит. Событие берёт литерал `mirror.upsert`
			// (исполнитель выбирает по типу и идентификатору объекта, а не по виду
			// события). Безопасно и без провязки: `EmitReconcileEvent` — обычная
			// вставка в очередь. Исполнитель выбирает событие →
			// `ReconcileObject("iam.role", id)` → `IAMDirectSelectorBindingsMatchingObject`
			// находит привязку владельца (`arm='anchor'`) → полный пересчёт её материализует.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.role", string(inserted.ID)); rerr != nil {
				return domain.Role{}, rerr
			}
			// Признак превью — в ЭТОЙ транзакции и после записи проекций (kaname#76):
			// эхо описывает роль, которую она записала, а писатель несёт читателя.
			return shared.WithPreviewHolding(ctx, w, u.cat, inserted)
		})
	if err != nil {
		return nil, err
	}

	// rbac-contract-a-fix (forward-mat, C-01b): пообъектный доступ к только что
	// зафиксированной роли материализуется СИНХРОННО, чтобы пообъектный кортеж
	// владельца и администратора аккаунта был виден, когда операция сообщает
	// готовность, — это закрывает гонку «чтение после создания», которую
	// асинхронная выборка событий в плоской модели иначе проигрывала бы. По
	// наилучшему усилию и не роняя создания: роль уже записана, а событие сверки,
	// зафиксированное вместе с ней, и периодический обход — страховка «хотя бы раз».
	//
	// IAM-FMB, пропускная способность: синхронная материализация после фиксации
	// идёт ДОБАВЛЯЮЩИМ путём (`ReconcileObjectForward`, без консультативного замка
	// вовсе, по одному объекту — роль новая, и снимать устаревшее НЕЧЕГО), а не
	// ПОЛНЫМ исключительным `ReconcileObject`, чей замок на привязку и пересчёт
	// области сериализовали всё на ОДНОЙ привязке владельца аккаунта, общей для
	// всех ролей аккаунта, → материализация кортежа владельца отставала дольше,
	// чем клиент готов ждать «чтения своей записи» при всплеске параллельных
	// созданий. Добавляющий путь уходит на ПОЛНЫЙ при повторной материализации
	// объекта с членами (сторож снятия устаревшего); ПОЛНЫЙ `ReconcileObject`
	// ОСТАЁТСЯ асинхронной страховкой, которую гонит событие сверки.
	u.reconcileObject(ctx, "iam.role", string(created.ID))

	// Эхо мутации проецируется тем же набором, что и чтение: иначе `Create`
	// вернул бы превью, собранное другим источником, чем последующий `Get`.
	created.TypeVerbs = u.cat.Facts().RolePreviewLookup()
	return marshalRole(created)
}

// reconcileObject гонит синхронную пообъектную материализацию после фиксации
// добавляющим быстрым путём (может быть не провязан, создания не роняет — пишет в
// журнал и идёт дальше; событие сверки и периодический обход — страховка).
func (u *CreateRoleUseCase) reconcileObject(ctx context.Context, objectType, objectID string) {
	if u.reconciler == nil {
		return
	}
	if rerr := u.reconciler.ReconcileObjectForwardNoStale(ctx, objectType, objectID); rerr != nil && u.logger != nil {
		u.logger.Error("role create: object forward reconcile failed (event/sweep will retry)",
			"object_type", objectType, "object_id", objectID, "err", rerr)
	}
}
