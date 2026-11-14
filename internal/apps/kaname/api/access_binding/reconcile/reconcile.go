// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Пакет reconcile — сведение селекторов и включения в область.
//
// Членство по селектору ДИНАМИЧЕСКОЕ: метки меняются в сервисе-владельце и поступают
// по ребру compute→iam RegisterResource в kaname.resource_mirror.
// Сведение МАТЕРИАЛИЗУЕТ желаемый набор объектов выдачи из
// зеркала (та же БД, без вызова iam→владелец — граф остаётся ацикличным), СРАВНИВАЕТ
// его с сохранённым access_binding_target_members и ВЫПУСКАЕТ/НЕМЕДЛЕННО ОТЗЫВАЕТ
// пообъектные кортежи FGA через fga_outbox — в ОДНОЙ транзакции записи (ban #10).
//
// Чистая архитектура: этот сценарий зависит ТОЛЬКО от домена и
// портов ReconcileStore / BindingSource (определены здесь). Реализация pgx —
// адаптер в repo/kaname/pg. Здесь нет pgx/grpc.
//
// Поводы запуска:
//
// (a) Create / Role.Update (смена правил) — ReconcileBinding(bindingID).
// (b) смена resource_mirror (RegisterResource) — ReconcileObject(type,id) через
//
//	событие resource_reconcile_outbox.
//
// (c) периодический обход — ReconcileBinding для каждой выдачи с селектором меток,
//
//	дополнительная защита от потери события / перезапуска обработчика.
package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// BindingScope — минимальные факты выдачи, нужные сведению для материализации
// членства: якорь области и входы выпуска FGA (субъект + селекторы
// ARM_LABELS роли). BindingSource загружает их по идентификатору выдачи.
// В модели RBAC на правилах у выдачи нет собственной ветви цели —
// выдача тонкая; единственный динамический источник членства — правила ARM_LABELS
// роли (LabelSelectors).
type BindingScope struct {
	BindingID domain.AccessBindingID
	Scope     domain.ScopeAnchor
	// Subjects — ВЕСЬ перечень субъектов выдачи (`access_binding_subjects`), в
	// порядке запроса. Разворачивание судит каждого (subjects.go, kaname#880):
	// одиночной пары «вид, идентификатор» здесь нет намеренно — она была
	// проекцией первого субъекта, и выдача разворачивалась ему одному.
	Subjects []domain.Subject
	RoleID   string
	// Policy — политика роли выдачи ([domain.PolicyOfRole] её строки). От неё
	// зависит набор глаголов правила: правка влечёт удаление у ролей платформы и
	// арендатора и не влечёт у роли модуля (kaname#1006). Нулевая — самая строгая
	// ветвь: удаление не приписывается.
	Policy domain.RulePolicy
	// Selectors — ЕДИНЫЕ материализующие селекторы роли (плоская явная
	// модель RBAC): ARM_ANCHOR(all) + ARM_NAMES + ARM_LABELS. Непустой набор даёт
	// выдаче динамическое членство по правилам: каждый селектор (rule_fp) сопоставляется
	// с источником по своей ветви (все в области / по id / по меткам) и
	// материализуется; кортежи объекта выводятся из ГЛАГОЛОВ селектора.
	// Пустой набор ⇒ тонкая выдача без материализованных членов (например, прежняя
	// роль только с разрешениями — её кортежами яруса ведает Create выдачи,
	// а не этот код). Выпуск scope_grant при создании выдачи снят; сведение —
	// ЕДИНСТВЕННЫЙ путь материализации.
	Selectors []domain.RuleSelector
	// ScopeSelfVerbs — глаголы роли, применимые к типу ресурса СОБСТВЕННОЙ области
	// выдачи: правило суперпользователя `*.*` ИЛИ
	// правило `iam.<scopeResource>`. Непустой набор заставляет сведение материализовать
	// кортеж яруса (+ глагольный v_*) НА САМОМ ОБЪЕКТЕ ОБЛАСТИ (якорь проверки записи /
	// сохранения доступа). Пустой ⇒ роль содержимого ничего не даёт на
	// якоре области (доступ живёт на совпавших объектах содержимого). Адаптер выводит
	// набор через role.Rules.ScopeSelfVerbs(scope.resource).
	ScopeSelfVerbs []string
	// Target — пообъектный отбор выдачи с минимальными привилегиями (redesign-2026 F8,
	// IAM-1-21). Непустой Target.Resources ограничивает выдачу РОВНО
	// перечисленными объектами: ветвь ARM_ANCHOR role.rules разрешается по id целей
	// (никогда не MatchAllInScope), совпадения всех ветвей ПЕРЕСЕКАЮТСЯ с набором целей,
	// а выдача на якоре собственной области ПОДАВЛЯЕТСЯ (пообъектная цель никогда не даёт
	// ярус на всём объекте области). AllInScope / пусто ⇒ выдача на всём якоре
	// (прежнее поведение — селекторы role.rules определяют членство в области).
	// Загружается адаптером из сохранённого столбца access_bindings.target.
	Target domain.AccessTarget
	// Active сообщает, остаётся ли выдача ACTIVE (REVOKED/истёкшая
	// выдача повторно не материализуется).
	Active bool
}

// DesiredMember — объект, который сведение включило в членство
// выдачи, с решением о включении в область и кортежами FGA для выпуска при
// ACTIVE. ObjectType — точечный ключ закрытой таблицы.
//
// RuleFP связывает желаемого члена с породившим правилом ARM_LABELS из role.rules
// через хеш его содержимого. Tuples — пообъектный набор кортежей FGA для выпуска
// при переходе в ACTIVE, заранее вычисленный из глаголов правила (передаётся здесь,
// чтобы applyDiff не выводил его заново). В модели RBAC на правилах
// нет прежней ветви selector/byName — каждый член выведен из правила.
type DesiredMember struct {
	RuleFP     string
	ObjectType string
	ObjectID   string
	Status     domain.VerificationStatus
	Tuples     []domain.MembershipTuple
}

// MemberCoord — координата члена выдачи, выпустившего строку реестра: точечное имя
// типа и идентификатор объекта (`access_binding_target_members.object_type`,
// `.object_id`). Строка реестра отвечает ровно за свою координату, и снятие члена
// выбирает строки по ней, а не разбором объекта кортежа: суффикс `:<id>` у объектов
// разных типов одной выдачи совпадает, а имя типа модели из снимка каталога процесса
// у реплики бывает не тем, что было при выдаче (kaname#933). Нулевая координата —
// строка уровня выдачи (`source='binding'`), у неё члена нет.
type MemberCoord struct {
	ObjectType string
	ObjectID   string
}

// coordOf — координата материализованного члена.
func coordOf(m domain.TargetMember) MemberCoord {
	return MemberCoord{ObjectType: m.ObjectType, ObjectID: m.ObjectID}
}

// desiredCoord — координата желаемого члена.
func desiredCoord(d DesiredMember) MemberCoord {
	return MemberCoord{ObjectType: d.ObjectType, ObjectID: d.ObjectID}
}

// LedgerRow — строка реестра выпущенного: координата члена и кортеж. Ключ реестра —
// (выдача, координата, кортеж): один кортеж от двух координат одной выдачи — две
// строки, и уход одной координаты не забирает строку другой.
type LedgerRow struct {
	Member MemberCoord
	Tuple  domain.MembershipTuple
}

// EmittedTupleRef — одна запись реестра выданных кортежей вместе с выдачей и членом,
// которые её породили. Нужна затем, чтобы весь веер прохода записывался ОДНИМ
// обращением: реестр ключуется по (выдача, координата члена, субъект, отношение,
// объект), поэтому выдача и координата обязаны ехать вместе с кортежем, а не быть
// общими параметрами вызова.
type EmittedTupleRef struct {
	BindingID domain.AccessBindingID
	Member    MemberCoord
	Tuple     domain.MembershipTuple
}

// ReconcileStore — порт транзакции, которым управляет сведение. Каждый метод работает
// внутри единой транзакции записи, открываемой реализацией для одного прохода,
// поэтому запись членства + выпуск кортежей FGA + аудит включения в область фиксируются
// вместе либо вместе откатываются (ban #10). Реализация — адаптер
// pg. ВНИМАНИЕ: сведение фиксирует СВОЮ транзакцию; событие resource_reconcile_outbox
// обработчик помечает отправленным в ОТДЕЛЬНОЙ короткой транзакции после этой фиксации
// (доставка хотя бы один раз, безопасный повтор — разница сведения идемпотентна), НЕ в
// этой транзакции.
type ReconcileStore interface {
	// AcquireBindingLock берёт pg_advisory_xact_lock(hashtext(binding_id)) в
	// транзакции записи сведения. Это ПЕРВЫЙ оператор
	// прохода по выдаче: параллельные проходы ОДНОЙ выдачи сериализуются
	// транзакционным замком (автоматически снимается при фиксации/откате — никогда
	// не замком пула). Это делает параллельную интеграционную проверку
	// детерминированной и вместе с замком строки LoadBinding `SELECT … FOR NO KEY UPDATE`
	// и страховкой partial-UNIQUE реестра гарантирует однократную
	// материализацию при N репликах.
	//
	// SHARE-режима у этого порта НЕТ и он не нужен: аддитивный форвард не берёт
	// advisory вовсе (reconcile/forward.go, «LOCK CHOICE»). Прежний
	// AcquireBindingLockShared существовал ради одного — развести дочерние вставки
	// форварда с `FOR UPDATE` полного прохода; режим строки ослаблен до
	// `FOR NO KEY UPDATE`, конфликта нет, и метод снят, чтобы ожидание не завелось
	// обратно «по аналогии».
	AcquireBindingLock(ctx context.Context, bindingID domain.AccessBindingID) error

	// AcquireBindingLocks берёт advisory-замки СРАЗУ ВСЕГО набора, в переданном
	// порядке и ДО первой записи прохода. Набор приходит уже отсортированным по
	// возрастанию (dedupSortBindingIDs), поэтому порядок глобально согласован между
	// параллельными проходами.
	//
	// ЗАЧЕМ ОТДЕЛЬНЫЙ ПОРТ, А НЕ ЦИКЛ ИЗ AcquireBindingLock. Предмет здесь не в числе
	// обращений, а в ПОРЯДКЕ РОДОВ ресурсов внутри транзакции. Проход веера трогает
	// строки ПРЯМОГО ФАКТА, а они общие: ключуются субъектом, объектом и отношением,
	// а не выдачей, — поэтому две выдачи одного субъекта на одном объекте спорят за
	// ОДНУ строку. Пока замок брался перед работой КАЖДОЙ выдачи, проход вставал в
	// очередь за advisory очередной выдачи, УЖЕ удерживая строки прямого факта
	// предыдущей. Снятие выдачи берёт свой advisory первым стейтментом и трогает
	// прямой факт после него — то есть порядок родов у двух сторон обратный, и
	// Postgres выходит из него, снимая одну сторону (40P01).
	//
	// Свойство, которое даёт этот порт: пока проход ждёт чужой advisory, он НЕ
	// удерживает ни одной строки прямого факта. Тогда сторона, держащая этот
	// advisory, доводит свою работу до конца, и цикла ожидания не существует
	// по построению, а не «редко случается».
	//
	// Идемпотентен внутри транзакции: повторный захват уже удерживаемого ключа
	// возвращается немедленно.
	AcquireBindingLocks(ctx context.Context, bindingIDs []domain.AccessBindingID) error

	// LockBindingsAndRoles берёт строки выдач набора `FOR NO KEY UPDATE` (тот же
	// режим, что LoadBinding), а затем строки их ролей `FOR KEY SHARE` (тот же
	// режим, что чтение роли прохода), каждый род — одним оператором в порядке id и
	// ДО первой записи прохода (kaname#974).
	//
	// ЗАЧЕМ. Снятие регистрации объекта запирает выдачи, чья цель называет ключ, и
	// роли, чьи правила называют его, и только потом пишет (UnregisteredKeyWithdrawal).
	// Проход по объекту прежде брал строку выдачи и её роль ПЕРЕД работой каждой
	// выдачи веера — то есть приходил к роли следующей выдачи, уже записав прямой
	// факт предыдущей, а к выдаче следующей — уже держа роль предыдущей. Общий факт
	// двух выдач одного субъекта на одном объекте и роль с именем ключа замыкали
	// кольцо со снятием: Postgres снимал одну сторону (40P01). Порядок родов у обеих
	// сторон теперь один — выдачи, роли, затем записи, — и кольца нет по
	// построению. Идемпотентен внутри транзакции: последующие чтения прохода берут
	// уже удерживаемые замки.
	LockBindingsAndRoles(ctx context.Context, bindingIDs []domain.AccessBindingID) error

	// LoadBinding — минимальные факты выдачи: область, селекторы, роль. ok=false —
	// выдачи больше нет (удалена: проходу делать нечего, каскад уже снял её членов).
	//
	// Реализация берёт строку выдачи `SELECT … FOR NO KEY UPDATE`: два ПОЛНЫХ прохода
	// одной выдачи идут друг за другом, и снятие устаревшего не гонится само с собой.
	// Аддитивный форвард этим чтением не пользуется — см. LoadBindingForForward.
	LoadBinding(ctx context.Context, bindingID domain.AccessBindingID) (BindingScope, bool, error)

	// LoadBindingForForward — те же факты, что LoadBinding, но под замком строки
	// `FOR KEY SHARE` (и без advisory-замка выдачи). Это чтение АДДИТИВНОГО форварда
	// (ReconcileBindingForward): форвард только ДОБАВЛЯЕТ кортежи и устаревшего не
	// снимает, поэтому взаимного исключения с полным проходом той же выдачи ему не
	// нужно — `FOR KEY SHARE` совместим с `FOR NO KEY UPDATE` полного прохода, и
	// регистрации под одной выдачей редактора или владельца в очередь за ним не встают.
	// Держит замок другое: решение форварда «выдача жива» верно до его коммита. Снятие
	// выдачи (LockBindingForDeactivation, `FOR UPDATE`) с ним конфликтует и не прочитает
	// набор членов и реестр, пока форвард, увидевший выдачу ACTIVE, ещё пишет
	// (kaname#919, kaname#923). Тот же `FOR UPDATE` берёт отзыв по снятию регистрации
	// объекта (kaname#963, F1). ok=false — выдачи больше нет.
	LoadBindingForForward(ctx context.Context, bindingID domain.AccessBindingID) (BindingScope, bool, error)

	// LoadBindingsForForward — то же чтение, что LoadBindingForForward, но для ЦЕЛОГО НАБОРА
	// выдач за фиксированное число обращений к базе (не по два на выдачу).
	//
	// Веер материализации адресуется числом ВЫДАЧ, покрывающих область объекта, а не
	// числом объектов: меняется один объект, а кандидатов у него столько, сколько выдач
	// его области. Перепись по дереву выдач (8267 объектов зеркала) дала p50 = 9
	// кандидатов, p95 = 19, p99 = 226, максимум 227, поэтому поштучное чтение делало
	// хвост в 454 последовательных обращения внутри одной транзакции.
	//
	// Контракт: выдача, которой в базе нет (удалена), в карте ОТСУТСТВУЕТ — ровно как
	// ok=false у одиночного чтения; роль, удалённая из-под выдачи, даёт «нет покрытия»
	// (пустые селекторы), а не ошибку. Строки берутся тем же `FOR KEY SHARE`, что у
	// одиночного чтения, одним оператором в порядке `id` (kaname#919).
	LoadBindingsForForward(ctx context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID]BindingScope, error)

	// MatchSelector возвращает объекты ЗЕРКАЛА, совпавшие с
	// types+matchLabels селектора (labels @> matchLabels), — источник сервиса-потребителя
	// (compute/vpc/nlb, FeedMirror). Нужен для вычисления желаемого набора при
	// проходе ReconcileBinding.
	MatchSelector(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error)

	// MatchAllInScope возвращает объекты зеркала заданных типов (ARM_ANCHOR /
	// `all` — без фильтра меток), СУЖЕННЫЕ до области включения `scope` выдачи. Область
	// передаётся в SQL как ДОКАЗАННОЕ НАДМНОЖЕСТВО повторной проверки IsContainedIn
	// сведения (она ВСЁ РАВНО выполняется — SQL лишь предварительно фильтрует), поэтому приходят
	// строки O(scope) вместо O(зеркало кластера). Источник сервиса-потребителя (FeedMirror).
	// `types` содержит ТОЛЬКО питаемые зеркалом типы (сведение разделяет их по источнику
	// перед вызовом).
	MatchAllInScope(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error)

	// MatchByIDs возвращает объекты зеркала заданных типов с object_id из
	// `ids` (ARM_NAMES — селектор точных id). Идентификатор, которого
	// пока нет в зеркале, просто отсутствует (PENDING до прихода его RegisterResource,
	// после чего его подхватывает прямой путь). Источник сервиса-потребителя (FeedMirror).
	MatchByIDs(ctx context.Context, types []string, ids []string) ([]domain.MirrorObject, error)

	// MatchAllInScopeIAMDirect / MatchByIDsIAMDirect — аналоги для прямого чтения
	// СОБСТВЕННЫХ объектов IAM (iam.project / iam.account + содержимое) из родных таблиц
	// ТОЙ ЖЕ БД. `types` содержит ТОЛЬКО такие типы. MatchAllInScopeIAMDirect
	// передаёт область включения `scope` выдачи в SQL как ДОКАЗАННОЕ НАДМНОЖЕСТВО
	// повторной проверки IsContainedIn (как MatchAllInScope); MatchByIDsIAMDirect (ветвь имён)
	// областью не ограничен — совпавший чужой id нужен для аудита REJECTED по включению.
	MatchAllInScopeIAMDirect(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error)
	MatchByIDsIAMDirect(ctx context.Context, types []string, ids []string) ([]domain.MirrorObject, error)

	// MatchCreatedByIAMDirect — собственные объекты iam типов `types` в области
	// `scope`, создатель которых — учётка из `creators` (kaname#1003, селектор
	// создателя). Отбор — по индексу «аккаунт, создатель», а не перебором объектов
	// области: число строк пропорционально числу учёток создателя. Тип, факт
	// создателя которого не хранится, не даёт ни одного объекта. Сужение по
	// области — то же доказанное надмножество IsContainedIn, что у ветви якоря.
	MatchCreatedByIAMDirect(ctx context.Context, types []string, scope domain.ScopeAnchor, creators []string) ([]domain.MirrorObject, error)

	// MatchIAMDirect возвращает СОБСТВЕННЫЕ объекты IAM, совпавшие с
	// types+matchLabels селектора, из родных таблиц ТОЙ ЖЕ БД (FeedIAMDirect —
	// iam.project/iam.account). Возвращённый MirrorObject несёт родителя иерархии iam
	// (project→его account_id; account→свой id), чтобы ТОТ ЖЕ
	// предикат IsContainedIn решал включение в область. Объекты iam-direct всегда
	// находятся в исходной таблице и никогда не PENDING. `types` содержит ТОЛЬКО
	// типы iam-direct (сведение разделяет их по источнику до вызова).
	MatchIAMDirect(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error)

	// GetMirrorObject возвращает строку зеркала одного объекта (проверка включения
	// конкретного члена при событии смены зеркала / ссылке byName). ok=false ⇒ нет в
	// зеркале ⇒ PENDING_VERIFICATION.
	GetMirrorObject(ctx context.Context, objectType, objectID string) (domain.MirrorObject, bool, error)
	// LockMirrorObjects запирает строки зеркала объектов `objs` под `FOR KEY SHARE`
	// одним оператором в порядке (тип, id) и возвращает те, что есть (kaname#975).
	// В `objs` — только объекты зеркала (не iam-direct).
	//
	// ЗАЧЕМ. Ветви отбора членов по зеркалу — область, метки, вложенное правило —
	// выбирают объект по его строке зеркала, а не по выдаче или роли, которые
	// запирает снятие регистрации. Снятие удаляет строку зеркала, а удаление
	// конфликтует с `FOR KEY SHARE`: проход, запирающий строку объекта перед записью
	// члена по нему, либо видит её и держит до коммита (снятие ждёт его, и
	// пост-фиксационный проход снятия снимает записанное), либо, придя после снятия,
	// её не находит и члена не пишет. Правка меток (`FOR NO KEY UPDATE`) с этим
	// режимом не конфликтует. Строку, которую снятие удаляет прямо сейчас, замок не
	// ждёт, а пропускает как отсутствующую (`SKIP LOCKED`): проход никогда не стоит
	// на строке зеркала и потому не замыкает кольца со снятием (URG-24).
	LockMirrorObjects(ctx context.Context, objs []MemberCoord) (map[MemberCoord]struct{}, error)
	// AncestorObjects — предки объекта из его зарегистрированной цепи, которые
	// есть в зеркале, с метками (kaname#874). По ним путь по объекту решает,
	// охватывает ли объект вложенное правило. Строки предков чтение запирает
	// `FOR KEY SHARE` (kaname#975): охват потомка держится на строке контейнера, и
	// снятие регистрации контейнера не проходит мимо прохода, который по ней решил.
	AncestorObjects(ctx context.Context, objectType, objectID string) ([]domain.MirrorObject, error)
	// MatchDescendants — объекты типов `types`, у которых среди предков есть
	// контейнер типа `containerType` с идентификатором из `containerIDs`, на любой
	// глубине (kaname#874): кандидаты вложенного правила на полном проходе.
	MatchDescendants(ctx context.Context, types []string, containerType string, containerIDs []string) ([]domain.MirrorObject, error)

	// GetIAMDirectObject возвращает проекцию СОБСТВЕННОЙ таблицы той же БД (родители
	// включения + метки) ОДНОГО родного объекта iam (iam.project / iam.account + типы
	// содержимого user/serviceAccount/group/role/accessBinding). Это
	// аналог GetMirrorObject для iam-direct, нужный АДДИТИВНОМУ прямому пути
	// нового объекта iam-direct, который живёт в СВОЕЙ таблице, никогда не в
	// зеркале. Проекция задаёт ТЕХ ЖЕ родителей включения (parentAccount /
	// parentProject) и метки, что и запросы отбора iam-direct, поэтому общее
	// пообъектное решение (IsContainedIn / selectorMatchesObject / desiredMemberForObject)
	// совпадает с ПОЛНЫМ путём. ok=false, если тип не iam-direct
	// либо строки нет. Никогда не PENDING (объект iam находится в своей таблице с
	// момента появления) — чтение той же БД, без вызова соседа (граф ацикличен).
	GetIAMDirectObject(ctx context.Context, objectType, objectID string) (domain.MirrorObject, bool, error)

	// CurrentMembers возвращает материализованных членов выдачи (базу сравнения) —
	// чтение ВСЕЙ выдачи, нужное лишь проходам по выдаче (ReconcileBinding
	// / ExpireBinding / обход), чей желаемый набор действительно охватывает всю область.
	CurrentMembers(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.TargetMember, error)

	// CurrentMembersForObject возвращает материализованных членов ОДНОЙ выдачи на ОДНОМ
	// объекте — УЗКУЮ базу сравнения прохода по объекту (ReconcileObject).
	// Вставка/удаление зеркала меняет ровно один объект, поэтому могут измениться лишь его
	// члены; чтение ВСЕГО набора членов выдачи ради него — пересчёт O(зеркало)
	// (две самые горячие измеренные выдачи несут по 10 140 членов). Используется индекс
	// членов по ключу (binding_id, object_type, object_id).
	CurrentMembersForObject(ctx context.Context, bindingID domain.AccessBindingID, objectType, objectID string) ([]domain.TargetMember, error)

	// BindingsForObject возвращает id выдач с членом, ссылающимся на
	// объект (для разворачивания события смены зеркала на затронутые выдачи).
	BindingsForObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error)

	// SelectorBindingsMatchingObject возвращает id ACTIVE-выдач, чей
	// селектор СЕЙЧАС совпадает с данным объектом зеркала (objectType ∈ selector.types
	// AND mirror.labels @> selector.match_labels), ВКЛЮЧАЯ выдачи, у которых
	// ещё НЕТ строки члена для него. Это быстрый путь, позволяющий
	// подхватить новый совпавший объект при событии смены зеркала (≤2с) вместо
	// ожидания периодического обхода. Чтение той же БД:
	// спецификация селектора + метки зеркала (без вызова соседа — граф ацикличен).
	SelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error)

	// IAMDirectSelectorBindingsMatchingObject — аналог для iam-direct метода
	// SelectorBindingsMatchingObject: id ACTIVE-выдач, чей селектор
	// СЕЙЧАС совпадает с данным СОБСТВЕННЫМ объектом IAM (objectType ∈ selector.types AND
	// метки СОБСТВЕННОЙ ТАБЛИЦЫ @> selector.match_labels), ВКЛЮЧАЯ выдачи без
	// строки члена. Нужен поводу Q2 (смена меток Project/Account.Update), чтобы
	// подхватить только что совпавший объект iam-direct по событию смены меток. Чтение той
	// же БД (своя таблица), без зеркала и вызова соседа.
	IAMDirectSelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error)

	// UpsertMember / DeleteMember материализуют/удаляют строку членства. Ключ члена —
	// ПОЛНАЯ координата правила (выдача, роль через выдачу, rule_fp,
	// объект), поэтому ОДИН объект под двумя правилами — две строки, а
	// снятое правило удаляет ТОЛЬКО свою строку.
	UpsertMember(ctx context.Context, m domain.TargetMember) error
	DeleteMember(ctx context.Context, bindingID domain.AccessBindingID, ruleFP, objectType, objectID string) error

	// LedgerTuplesForMember — строки реестра, выпущенные ОДНИМ членом выдачи
	// (access_binding_emitted_tuples WHERE binding_id=… AND координата=…), по префиксу
	// первичного ключа. Источник снятия члена: глаголы снятого правила ушли, и кортежи
	// не вывести заново — снимается СОХРАНЁННЫЙ набор. Каталог процесса не читается:
	// координата — та же, что у строки члена (kaname#933).
	LedgerTuplesForMember(ctx context.Context, bindingID domain.AccessBindingID, member MemberCoord) ([]domain.MembershipTuple, error)

	// LedgerTuples — весь реестр выпущенного одной выдачей с координатами строк
	// (access_binding_emitted_tuples WHERE binding_id=…), одним обращением. Читает его
	// полный проход, чтобы довести неизменного члена выдачи нескольким субъектам до
	// полного набора кортежей (emitted_completion.go, kaname#880), и истечение выдачи,
	// снимающее весь учтённый набор.
	LedgerTuples(ctx context.Context, bindingID domain.AccessBindingID) ([]LedgerRow, error)

	// EmitTupleWrite / EmitTupleDelete ставят пообъектные кортежи FGA в очередь
	// fga_outbox транзакции (+ указатель родителя иерархии области — предмет жизненного цикла
	// выдачи в Create/Delete, а НЕ отдельного члена).
	EmitTupleWrite(ctx context.Context, tuples []domain.MembershipTuple) error
	EmitTupleDelete(ctx context.Context, tuples []domain.MembershipTuple) error

	// RecordEmittedTuples / ForgetEmittedTuples фиксируют кортежи FGA каждого члена
	// в постоянном реестре выпущенных кортежей (access_binding_emitted_tuples)
	// В ТОЙ ЖЕ транзакции записи сведения, что и соответствующий EmitTupleWrite /
	// EmitTupleDelete (ban #10). Реестр — достоверный набор «что выпущено»,
	// который воспроизводит симметричный отзыв (delete.go) и с которым сравнивает
	// веер сведения Role.Update, ОБЪЕДИНЯЯ кортежи членов ветви селектора с
	// кортежами ветвей all_in_scope / resources[], уже внесёнными в реестр. Без этого
	// кортежи членов селектора выпускались в fga_outbox без учёта, поэтому
	// отзыв оставлял их без владельца, а смена яруса роли их не сводила.
	// RecordEmittedTuples пишет строки ОДНОГО члена — с его координатой, INSERT … ON
	// CONFLICT DO NOTHING по полному ключу (повтор идемпотентен); ForgetEmittedTuples
	// снимает ровно названные строки по полному ключу (eager-revoke / fell-out /
	// истечение). Строки удалённой привязки снимает FK ON DELETE CASCADE.
	RecordEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, member MemberCoord, tuples []domain.MembershipTuple) error

	// UpsertMembers / RecordEmittedTuplesBatch — те же записи, что UpsertMember и
	// RecordEmittedTuples, но НАБОРОМ и за фиксированное число обращений к базе, каким
	// бы ни был размер веера. Аддитивный форвард материализует по строке члена и по
	// записи реестра на КАЖДУЮ совпавшую выдачу, поэтому поштучная запись делала
	// стоимость прохода линейной по числу выдач области (p50 = 9 кандидатов, хвост 227
	// по дереву выдач) — при том что изменился ровно один объект.
	//
	// Семантика сохраняется дословно: тот же ON CONFLICT, та же идемпотентность повтора,
	// тот же порядок строк (а на порядке id очереди держится поголовный FIFO партиции —
	// выдача и отзыв одного ключа НЕ коммутативны). Пустой набор — no-op.
	UpsertMembers(ctx context.Context, members []domain.TargetMember) error
	RecordEmittedTuplesBatch(ctx context.Context, refs []EmittedTupleRef) error
	ForgetEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, rows []LedgerRow) error

	// EmitContainmentAudit пишет в транзакции событие аудита «отказ: нет включения в область»
	// (отказ не остаётся молчаливым).
	EmitContainmentAudit(ctx context.Context, bindingID domain.AccessBindingID, objectType, objectID string, scope domain.ScopeAnchor) error

	// RevokeExpiredBinding атомарно переводит ACTIVE-выдачу в REVOKED через CAS
	// (`UPDATE … WHERE status='ACTIVE' AND id=$id`, ban #10 — без TOCTOU). ok=false,
	// если обновлено 0 строк (уже отозвана / параллельный Delete победил). Нужен проходу
	// немедленного отзыва по истечению; пообъектные отзывы кортежей выпускает
	// вызывающая сторона отдельно по загруженным ACTIVE-членам.
	RevokeExpiredBinding(ctx context.Context, bindingID domain.AccessBindingID) (ok bool, err error)

	// LockBindingForDeactivation берёт строку выдачи `FOR UPDATE` — единственный режим
	// строки, конфликтующий с `FOR KEY SHARE` форварда (LoadBinding(s)ForForward).
	// Снятие (истечение срока) берёт его ДО чтения набора членов: снимаемый набор
	// включает всех членов, которых зафиксировал одновременный форвард, а форвард,
	// пришедший позже, читает выдачу REVOKED (kaname#919). Строки нет — не ошибка:
	// следующее LoadBinding вернёт ok=false.
	LockBindingForDeactivation(ctx context.Context, bindingID domain.AccessBindingID) error

	// EmitSubjectChangeEvent пишет строку журнала смены субъекта в транзакции прохода.
	// Вид события и `op` выбирает вызывающий use-case, порт только пишет: так
	// производитель журнала остаётся в слое, который обходит перепись производителей
	// (internal/check, TestSelfFlushCoversEveryProducerOfTheSubjectChangeQueue).
	EmitSubjectChangeEvent(ctx context.Context, evt abrepo.SubjectChangeEvent) error

	// EmitAuditEvent пишет строку журнала аудита в транзакции прохода — тем же
	// писателем, что отзыв и удаление. Содержимое строки выбирает use-case.
	EmitAuditEvent(ctx context.Context, ev abrepo.AuditEvent) error
}

// ExpiredBindingSource перечисляет выдачи с истёкшим TTL (поиск истечения,
// индекс (status, expires_at)). Чтение через пул (вне транзакции отзыва
// выдачи); затем каждый id отзывается в своей транзакции записи через ExpireBinding.
type ExpiredBindingSource interface {
	ListExpiredBindingIDs(ctx context.Context) ([]domain.AccessBindingID, error)
}

// TxRunner выполняет fn в одной транзакции записи, фиксируя успех и откатывая
// ошибку/панику. Весь проход сведения — единая атомарная операция.
type TxRunner interface {
	WithTx(ctx context.Context, fn func(ctx context.Context, s ReconcileStore) error) error
}

// Reconciler — сценарий сведения селекторов и включения в область.
type Reconciler struct {
	stagedBindings   StagedBindingReconciler
	groupObjects     *Reconciler
	objectObjects    *Reconciler
	objectConfigured bool
	tx               TxRunner
	logger           *slog.Logger
	// cat — источник КАТАЛОЖНОГО ФАКТА: какие глаголы объявлены живым типом.
	//
	// Обязателен, а не опционален, как `size` ниже: без него проход не может
	// вычислить ни одного кортежа, и незаполненное поле дало бы не «наблюдение
	// выключено», а «выдача не материализуется» — тихо и целиком.
	cat catalog.Source
	// size — НЕОБЯЗАТЕЛЬНЫЙ регистратор размера материализации выдачи. nil ⇒
	// наблюдение ничего не делает; сам проход от него не зависит.
	size SizeRecorder
}

// SizeRecorder получает РАЗМЕР желаемого набора выдачи: сколько объектов
// совпало с селекторами и сколько кортежей эти объекты порождают.
//
// Выдача ниже трёх каскадных уровней разворачивается ПО ОБЪЕКТАМ, её цена — «совпавшие
// объекты × глаголы правила». Такое разворачивание никто не считал, поэтому «эта
// выдача выросла» нельзя было отличить от «эта выдача обычная», а
// различие проявляется не при выдаче, а позже, на чужом
// запросе, на пути, который выдачу вообще не называет. Предел здесь не навязывается:
// достижимый размер не измерен, а выбранное до замера ограничение
// либо отвергает законные выдачи, либо ничего не отвергает, лишь изображая контроль.
type SizeRecorder interface {
	ObserveBindingMaterialization(objects, tuples int)
}

// SyncFGATuple — одна тройка набора, собираемого проходом реконсайлера.
//
// Имя историческое и оставлено намеренно: тип пересекает границу пакета, а
// переименование ради красоты стоило бы правки вызывающих без единого изменения
// свойства. Адресат у набора теперь один — вычитание переживших выдач в базе.
type SyncFGATuple struct {
	User     string
	Relation string
	Object   string
}

// ПРЯМОГО ПИСАТЕЛЯ В ЧУЖОЕ ХРАНИЛИЩЕ У РЕКОНСАЙЛЕРА БОЛЬШЕ НЕТ.
//
// Он применял вычисленный набор ПОСЛЕ коммита, чтобы закрыть окно между коммитом
// и дренажом очереди. Окна нет: прямой факт складывается из строки журнала
// триггером, в той же транзакции, — то есть материализация стала тождеством
// коммита, и догонять её нечем.
//
// Сбор набора (`syncFGACollector`) ОСТАЛСЯ и остался не по инерции: вычитание
// переживших выдач при снятии («кортеж, который держит другая действующая
// выдача, не снимается») делается его же данными и делается в базе.

// New создаёт сведение.
//
// `cat` — источник каталожного факта; параметр ОБЯЗАТЕЛЬНЫЙ (см. поле `cat`).
func New(tx TxRunner, logger *slog.Logger, cat catalog.Source) *Reconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{tx: tx, logger: logger, cat: cat}
}

// WithSizeRecorder подключает НЕОБЯЗАТЕЛЬНЫЙ регистратор размера материализации. nil безопасен:
// без регистратора проход побайтово тот же, только больше не измеряется.
func (r *Reconciler) WithSizeRecorder(rec SizeRecorder) *Reconciler {
	r.size = rec
	return r
}

// observeSize сообщает размер желаемого набора выдачи. Объекты считаются как
// РАЗЛИЧНЫЕ (тип, id): один объект под двумя правилами роли — два члена,
// но ОДИН объект; счёт членов завысил бы число объектов в
// число правил, уже отражённое числом кортежей.
//
// Проход без совпадений сообщает ноль, а не пропускается — иначе переставший
// совпадать селектор выглядел бы точно как выдача, которую никто не сводит.
func (r *Reconciler) observeSize(desired []DesiredMember) {
	if r.size == nil {
		return
	}
	objects := make(map[string]struct{}, len(desired))
	tuples := 0
	for _, d := range desired {
		objects[d.ObjectType+":"+d.ObjectID] = struct{}{}
		tuples += len(d.Tuples)
	}
	r.size.ObserveBindingMaterialization(len(objects), tuples)
}

// syncFGACollector собирает в одном проходе сведения пообъектные кортежи,
// выпущенные reconcileBinding в fga_outbox для ACTIVE-членов. НИЧЕГО никуда не применяется
// после фиксации прохода — см. примечание выше SyncFGATuple: прямой факт сворачивает
// из строки журнала триггер внутри той же транзакции. Коллектор всё ещё
// НУЖЕН для вычитания в конце прохода: flushDeletes не должен снимать
// кортеж, заново записанный этим же проходом. nil-коллектор ничего не устраняет, а вызовы
// collect становятся дешёвой передачей насквозь. Между горутинами не разделяется: один коллектор
// на проход WithTx, проход идёт одной горутиной под advisory-замком выдачи.
type syncFGACollector struct {
	// seen — что ЭТОТ проход уже записал. Единственный носитель, ради которого
	// сбор и существует: вычитание в конце прохода.
	//
	// Рядом лежали два накопителя — записанное и снятое, — и оба уезжали
	// пост-коммитным применителем в чужое хранилище. Применителя нет (стадия S6,
	// эпик kacho#747), и накопители сняты вместе с ним: срез, который заполняют и
	// никогда не читают, снаружи неотличим от работающего механизма.
	seen map[SyncFGATuple]struct{}
	// pendingDeletes — строки снятия выдач прохода, ОТЛОЖЕННЫЕ до его конца
	// (flushDeletes): вычитание записанного проходом идёт по ВСЕМУ проходу, от
	// порядка сверки выдач не завися. Факт, который держит ведомость другой действующей выдачи,
	// оставляет свёртка строки снятия под замком строки факта (kaname#919); снимок
	// соседей здесь не читается.
	pendingDeletes []pendingDelete
}

// pendingDelete — отложенные строки снятия одной выдачи (строки её реестра
// жадный отзыв уже забыл на месте; отложена лишь строка журнала).
type pendingDelete struct {
	binding domain.AccessBindingID
	tuples  []domain.MembershipTuple
}

// deferDelete сохраняет предполагаемые удаления кортежей выдачи до сброса в конце прохода.
func (c *syncFGACollector) deferDelete(binding domain.AccessBindingID, tuples []domain.MembershipTuple) {
	if c == nil || len(tuples) == 0 {
		return
	}
	c.pendingDeletes = append(c.pendingDeletes, pendingDelete{binding: binding, tuples: tuples})
}

// collectNew учитывает кортежи выпуска ACTIVE-члена БЕЗ ПОВТОРОВ во всём проходе
// и возвращает ровно подмножество, ЕЩЁ НЕ выпущенное этим проходом, — набор, который
// вызывающая сторона должна поставить в fga_outbox.
//
// Один проход сведения (веер ReconcileObject по многим выдачам либо член собственной
// области и член содержимого `*.*`, оба на account:<X>, либо два правила одной
// выдачи с пересекающимися глаголами) выводит ОДИН кортеж несколько раз. Устранение повторов
// прежде было обязательно ещё потому, что пакетная запись внешнего движка отвергала
// запрос целиком при повторе, но вместе с движком эта причина исчезла.
//
// Осталась цена производителя, и её самой достаточно: вторая строка fga_outbox для
// кортежа, уже поставленного этой транзакцией, ничего не даёт, ведь обе строки сворачиваются
// в один прямой факт. На измеренном стенде один проход давал 27 строк outbox
// для 21 различного кортежа — 2,2 строки на различный кортеж по всей таблице.
// Устранение повторов строго ВНУТРИ ПРОХОДА (транзакции записи), по ключу кортежа, поэтому не может
// схлопнуть последовательность выдача → отзыв → выдача: это три отдельных прохода,
// каждый со своим коллектором; промежуточный отзыв очищает строку члена и реестр.
//
// Запись РЕЕСТРА каждой выдачи намеренно НЕ устраняет повторы этим набором: реестр
// PK — (binding_id, координата члена, fga_user, relation, object), поэтому две привязки (и
// две координаты одной выдачи), претендующие на один кортеж, должны каждая сохранять СВОЮ
// row — по нему свёртка строки снятия и узнаёт, что факт ещё держит другой держатель
// (kaname#919, kaname#933).
//
// nil-коллектор (без подключения sync-FGA) ничего не устраняет и возвращает вход как есть.
func (c *syncFGACollector) collectNew(tuples []domain.MembershipTuple) []domain.MembershipTuple {
	if c == nil {
		return tuples
	}
	if c.seen == nil {
		c.seen = make(map[SyncFGATuple]struct{})
	}
	fresh := tuples[:0:0]
	for _, t := range tuples {
		st := SyncFGATuple{User: t.User, Relation: t.Relation, Object: t.Object}
		if _, dup := c.seen[st]; dup {
			continue
		}
		c.seen[st] = struct{}{}
		fresh = append(fresh, t)
	}
	return fresh
}

// flushDeletes кладёт ОТЛОЖЕННЫЕ строки снятия прохода в его пишущую транзакцию —
// ПОСЛЕ сверки всех выдач прохода, когда записанное им известно целиком. Из каждого
// набора вычитаются кортежи, ЗАПИСАННЫЕ любым членом этого же прохода (соседняя
// выдача выпустила тот же кортеж — col.seen): строка снятия того, что эта же
// транзакция только что записала, ничего не даёт.
//
// Ведомости ДРУГИХ выдач здесь не читаются. Факт, который держит ведомость другой
// действующей выдачи, оставляет свёртка строки снятия: вопрос о держателях она задаёт
// под замком строки факта, после коммита любого, кто держит эту строку, — свежим
// снимком (миграция 20261019180000, kaname#919). Снимок соседей, прочитанный здесь,
// устаревал раньше, чем применялся: два прохода, читавшие друг друга живыми, оба
// оставляли факт без держателя. Своя строка ведомости к этому моменту уже забыта
// (ForgetEmittedTuples в revokeMemberTuples) либо выдача снята — свой реестр факт не
// держит.
func (r *Reconciler) flushDeletes(ctx context.Context, s ReconcileStore, c *syncFGACollector) error {
	if c == nil || len(c.pendingDeletes) == 0 {
		return nil
	}
	for _, pd := range c.pendingDeletes {
		// Кандидаты, не записанные этим проходом заново.
		var revoke []domain.MembershipTuple
		for _, t := range pd.tuples {
			if _, written := c.seen[SyncFGATuple{User: t.User, Relation: t.Relation, Object: t.Object}]; written {
				continue
			}
			revoke = append(revoke, t)
		}
		if len(revoke) == 0 {
			continue
		}
		if err := s.EmitTupleDelete(ctx, revoke); err != nil {
			return fmt.Errorf("flush deletes: emit tuple delete for %s: %w", pd.binding, err)
		}
	}
	return nil
}

// ReconcileBinding пересчитывает полное желаемое членство выдачи по
// зеркалу и сравнивает его с материализованным набором (повод (a) + обход (c)).
func (r *Reconciler) ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error {
	return r.fullPass(ctx, bindingID, false)
}

// ConvergeBinding — тот же полный проход, но СВОДЯЩИЙ: каждый неизменный
// действующий член доводится до своего желаемого набора кортежей при любом числе
// субъектов — недостающее дописывается, лишнее снимается (emitted_completion.go,
// kaname#1006). Его зовёт проход по всем действующим выдачам — при старте и
// затем по такту (seed/binding_converge.go): набор кортежей члена зависит не
// только от ключа члена, но и от вычисления (политика роли, каталог), а
// вычисление меняется выкаткой.
func (r *Reconciler) ConvergeBinding(ctx context.Context, bindingID domain.AccessBindingID) error {
	return r.fullPass(ctx, bindingID, true)
}

func (r *Reconciler) fullPass(ctx context.Context, bindingID domain.AccessBindingID, converge bool) error {
	if r.stagedBindings != nil {
		return r.stagedBindings.ReconcileStagedBinding(ctx, bindingID, converge, r.size)
	}
	col := &syncFGACollector{}
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		if err := r.reconcileBinding(ctx, s, bindingID, converge, col); err != nil {
			return err
		}
		// Отложенные строки снятия — в конце прохода; факт, который ещё держит
		// другая действующая выдача, оставляет свёртка журнала (kaname#919).
		return r.flushDeletes(ctx, s, col)
	}); err != nil {
		return err
	}
	// После коммита не применяется НИЧЕГО: откат выше возвращает управление раньше,
	// а прямой факт складывается из строки журнала триггером в той же транзакции —
	// значит незакоммиченный diff не материализуется по построению.
	return nil
}

// ReconcileObject повторно проверяет каждую выдачу с членом, ссылающимся на
// изменённый объект (повод (b) — вставка/удаление resource_mirror). Для каждой такой
// выдачи заново выводится членство ЭТОГО ОБЪЕКТА и сравнивается с материализованными
// членами ЭТОГО ОБЪЕКТА, отражая смену метки или родителя, включая
// отзыв устаревшего и переход PENDING→ACTIVE/REJECTED.
//
// ЦЕНА — проход имеет O(1) по размеру области выдачи (исправление цены производителя).
// Событие несёт ровно ОДИН изменённый объект, поэтому измениться может членство
// ровно одного объекта; проход заново выводит только его желаемых членов
// (desiredMembersForObject) и читает только его текущих членов
// (CurrentMembersForObject). Прежде он вызывал reconcileBinding — ПОЛНЫЙ пересчёт O(scope)
// желаемого набора (MatchAllInScope по всем объектам зеркала области) плюс
// ВЕСЬ материализованный набор выдачи — для каждой выдачи веера. Замер на
// стенде: две самые горячие выдачи несут по 10 140 членов в аккаунте из 10 132 объектов,
// а одно изменение объекта разворачивается в среднем на 3,2 выдачи, поэтому одна
// повторная регистрация или смена меток читала ~64 000 строк, удерживая
// ИСКЛЮЧИТЕЛЬНЫЙ advisory-замок выдачи, за которым стоят все соседние регистрации
// аккаунта. Именно это выводило материализацию выдач за бюджеты повторов клиентов
// под нагрузкой.
//
// ПОЧЕМУ СУЖЕНИЕ ТОЧНОЕ, а не приближённое:
//
//   - Ключ членов — ОБЪЕКТ (binding, rule_fp, object_type, object_id), поэтому
//     смена объекта X не может добавить, удалить или сменить статус члена объекта Y.
//     Решение для X выводит desiredMemberForObject — ТО ЖЕ пообъектное
//     место решения, что и при полном пересчёте, поэтому оба пути побайтово совпадают.
//   - Вычитание survivingClaims внутри привязки (applyDiff), определяющее,
//     какие строки журнала ЗАБЫВАЮТСЯ, затрагивает только участников с ОБЩЕЙ строкой журнала,
//     а PK журнала — (binding_id, координата члена, fga_user, relation, object):
//     общая строка означает ТУ ЖЕ координату, то есть тот же объект. Сужение
//     желаемого набора до одного объекта забывает ровно то же, что забыл бы полный набор.
//     Строку снятия кортежа, который выдача ещё выпускает ДРУГОЙ координатой на том же
//     объекте движка (тип переименован с сохранением типа модели), сужение не вычитает
//     — её оставляет свёртка: строка той координаты держит факт (kaname#919).
//   - Удержание факта, который держит ДРУГАЯ выдача, — дело свёртки журнала: она
//     спрашивает реестр под замком строки факта (kaname#919) и желаемого набора не
//     читает вовсе, поэтому сужение до объекта её не касается.
//   - Сам веер УЖЕ сужен до объекта (BindingsForObject ∪
//     SelectorBindingsMatchingObject) — не сужен был только пересчёт выдачи внутри него.
//
// Проходы по выдаче (ReconcileBinding, ExpireBinding, периодический обход)
// сохраняют ПОЛНЫЙ пересчёт O(scope): там менялись роль/селекторы/область выдачи,
// поэтому весь желаемый набор действительно нужно вывести заново. Они также остаются
// страховкой доставки хотя бы один раз, сводящей всё, что мог пропустить пообъектный проход.
func (r *Reconciler) ReconcileObject(ctx context.Context, objectType, objectID string) error {
	if objectType == "iam.group" && r.groupObjects != nil {
		return r.groupObjects.ReconcileObject(ctx, objectType, objectID)
	}
	if r.objectConfigured {
		if r.objectObjects == nil {
			return errObjectParticipantAbsent
		}
		return r.objectObjects.ReconcileObject(ctx, objectType, objectID)
	}
	col := &syncFGACollector{}
	if err := r.withObjectTx(ctx, objectType, objectID, func(ctx context.Context, s ReconcileStore) error {
		// (1) Выдачи, УЖЕ имеющие строку члена со ссылкой на объект: смена
		// метки / родителя / уход объекта из зеркала отражается
		// полным пересчётом ниже.
		existing, err := s.BindingsForObject(ctx, objectType, objectID)
		if err != nil {
			return fmt.Errorf("bindings for object %s:%s: %w", objectType, objectID, err)
		}
		// (2) БЫСТРЫЙ ПУТЬ: выдачи, чей селектор СЕЙЧАС
		// совпадает с объектом, но строки члена ещё НЕТ (новый
		// совпавший объект). Без этого только что прибывший объект
		// получает доступ при следующем обходе (задержка ≤30с); с этим путь
		// события материализует членство за ~2с. Обход остаётся дополнительной
		// страховкой. Источник совпадений зависит от источника данных:
		// питаемые зеркалом объекты читают resource_mirror; объекты iam-direct (смена меток
		// Project/Account) читают СОБСТВЕННУЮ таблицу.
		var matching []domain.AccessBindingID
		if domain.FeedSourceForType(objectType) == domain.FeedIAMDirect {
			matching, err = s.IAMDirectSelectorBindingsMatchingObject(ctx, objectType, objectID)
		} else {
			matching, err = s.SelectorBindingsMatchingObject(ctx, objectType, objectID)
		}
		if err != nil {
			return fmt.Errorf("selector bindings matching object %s:%s: %w", objectType, objectID, err)
		}
		// Проекция изменённого объекта читается ОДИН РАЗ на весь веер (каждая
		// выдача сравнивает тот же объект). Отсутствие в источнике — DELETE зеркала либо
		// строка iam, попавшая в гонку с удалением, — оставляет ПУСТОЙ желаемый набор каждой
		// выдачи, что и запускает отзыв устаревшего ниже.
		var obj domain.MirrorObject
		objPresent := false
		if domain.FeedSourceForType(objectType) == domain.FeedIAMDirect {
			obj, objPresent, err = s.GetIAMDirectObject(ctx, objectType, objectID)
		} else {
			obj, objPresent, err = s.GetMirrorObject(ctx, objectType, objectID)
		}
		if err != nil {
			return fmt.Errorf("get object %s:%s: %w", objectType, objectID, err)
		}
		// Предки объекта — не более ОДНОГО раза на веер и лишь по спросу выдачи с
		// вложенным правилом (kaname#874): по ним каждая такая выдача решает свои
		// вложенные правила. Чтение — текущей цепи, поэтому перенос объекта под
		// другой контейнер (ND-09) переносит и члены. Память предков заводится ниже,
		// после замка строки объекта: её чтение ленивое и идёт уже под замками выдач.

		// Разворачиваем веер по объединению без повторов; проход выдачи — идемпотентное
		// сравнение членства ЭТОГО ОБЪЕКТА, поэтому одного сведения выдачи достаточно
		// независимо от источника кандидата.
		//
		// КЛАСС ВЗАИМОБЛОКИРОВОК: проход берёт pg_advisory_xact_lock(hashtext(binding_id))
		// для каждой выдачи веера в ОДНОЙ транзакции записи. Два запроса
		// источников возвращают id выдач в НЕдетерминированном порядке; захват по приходу
		// позволяет двум параллельным ReconcileObject (разные объекты с
		// пересекающимися наборами выдач) брать общие замки в РАЗНОМ порядке → взаимоблокировка
		// ABBA (40P01). Сортировка объединения без повторов по возрастанию даёт каждому проходу
		// ГЛОБАЛЬНО согласованный порядок захвата.
		union := dedupSortBindingIDs(existing, matching)
		// ВСЕ advisory-замки — ДО ПЕРВОЙ ЗАПИСИ прохода, в этом же порядке.
		//
		// Сортировки одной недостаточно, и это измерено, а не предположено. Она
		// разводит проходы веера МЕЖДУ СОБОЙ — там оба ресурса одного рода, и общий
		// порядок их упорядочивает. Но проход спорит ещё и со СНЯТИЕМ выдачи, а у
		// того ресурсы РАЗНЫХ родов: свой advisory он берёт первым стейтментом, а
		// общие строки прямого факта трогает после. Пока веер брал замок перед
		// работой каждой выдачи, он приходил к очередному advisory, уже удерживая
		// строку прямого факта предыдущей выдачи, — обратный порядок родов, из
		// которого Postgres выходит, снимая одну сторону как взаимную блокировку
		// (40P01). Наблюдалось на стороне арендатора: операция снятия завершалась
		// `done:true` с ABORTED, выдача оставалась жива, и следующее создание того же
		// набора получало ALREADY_EXISTS.
		//
		// Взяв весь набор вперёд, проход ждёт чужой advisory, НЕ удерживая ни одной
		// общей строки, — и цикла ожидания не существует по построению.
		if err := s.AcquireBindingLocks(ctx, union); err != nil {
			return fmt.Errorf("acquire binding locks for object %s:%s: %w", objectType, objectID, err)
		}
		// Строки выдач и их ролей — тоже ВСЕ вперёд, тем же порядком родов, что у
		// снятия регистрации объекта: выдачи, роли, затем записи (kaname#974, шапка
		// LockBindingsAndRoles). Иначе проход брал роль очередной выдачи, уже
		// записав общий прямой факт предыдущей, а снятие — наоборот.
		if err := s.LockBindingsAndRoles(ctx, union); err != nil {
			return fmt.Errorf("lock bindings and roles for object %s:%s: %w", objectType, objectID, err)
		}
		// Строка самого объекта — третьим родом, после выдач и ролей и до первой
		// записи (kaname#975): тот же порядок, что у снятия регистрации (выдачи, роли,
		// строка зеркала). Строки, снятой после чтения выше, под замком уже нет —
		// желаемое пусто, и проход снимает члены объекта, а не пишет их.
		if objPresent {
			live, err := liveObjects(ctx, s, []MemberCoord{{ObjectType: objectType, ObjectID: objectID}})
			if err != nil {
				return fmt.Errorf("object %s:%s: %w", objectType, objectID, err)
			}
			objPresent = live(MemberCoord{ObjectType: objectType, ObjectID: objectID})
		}
		ancestors := r.ancestorsOf(ctx, s, objectType, objectID, objPresent)
		for _, bID := range union {
			if err := r.reconcileBindingForObject(ctx, s, bID, objectType, objectID, obj, objPresent, ancestors, col); err != nil {
				return err
			}
		}
		// Отложенные строки снятия — ПОСЛЕ сверки всех выдач прохода: вычитание
		// записанного проходом видит его целиком, от порядка выдач не завися.
		return r.flushDeletes(ctx, s, col)
	}); err != nil {
		return err
	}
	// Только ПОСЛЕ фиксации.
	return nil
}

// ExpireBinding снимает выдачу с истёкшим сроком в одной writer-транзакции:
// CAS-переход ACTIVE→REVOKED, затем снятие пообъектного кортежа каждого ACTIVE-члена
// и удаление строк членов. CAS (запрет #10) разводит истечение с одновременным
// удалением или активацией: 0 обновлённых строк (выдачу уже сняли) — кортежи снял
// тот путь, и проход останавливается. Выдача становится REVOKED, и следующая
// проверка права отказывает; строки членов удаляются, чтобы реконсайлер не выпустил
// их заново.
//
// ПОРЯДОК ЗАМКОВ транзакции истечения:
//
//	1  advisory-замок выдачи        pg_advisory_xact_lock(hashtext(id)) — против полного прохода, отзыва, удаления, второго истечения
//	2  строка access_bindings        FOR UPDATE (LockBindingForDeactivation) — против аддитивного форварда
//	3  строка access_bindings        FOR NO KEY UPDATE (LoadBinding) — уже покрыт шагом 2
//	4  дочерние строки выдачи        снятие членов и реестра, строки журналов
//
// Шаг 2 стоит ДО чтения членов (kaname#919): форвард решает «выдача жива» под
// `FOR KEY SHARE` и пишет членов позже, в своей транзакции; без шага 2 члены,
// легшие после чтения набора, снимать было бы некому — полный проход и сведение
// пропускают не-ACTIVE выдачу, а прямой факт вердикт читает и без неё. Отзыв и
// удаление берут тот же порядок шагов 1–2 (doRevoke, deleteOnce в access_binding,
// kaname#923), поэтому снятия одной выдачи между собой цикла не дают. Строки
// каталога (`catalog_module`, `catalog_resource` — порядок 2р→2а→4 применителей,
// kaname#913) транзакция не берёт вовсе, поэтому ребра ожидания с ними нет.
//
// Замка строки мало: исход снятия решает и ВЕРСИЯ строки журнала — свёртка в
// прямой факт снимает факт, лишь если его версия не новее версии строки снятия.
// Строка снятия несёт момент своей вставки, а не начало транзакции
// (fga_outbox, deleteStamp): иначе снятие, открывшее транзакцию раньше форварда и
// получившее строку после его коммита, писало бы строку старше факта, и факт её
// переживал. Оба порядка начала транзакций держит
// reconcile_deactivation_order_race_integration_test.go.
//
// Строку журнала смены субъекта и строку аудита снятия истечение пишет в той же
// транзакции, той же формы, что отзыв и удаление (kaname#920): по первой край
// сбрасывает кэш решений субъекта и закрывает его открытые потоки, вторая
// закрывает в следе соответствия выдачу, которую туда положило создание.
func (r *Reconciler) ExpireBinding(ctx context.Context, bindingID domain.AccessBindingID) error {
	if r.stagedBindings != nil {
		staged, ok := r.stagedBindings.(interface {
			ExpireStagedBinding(context.Context, domain.AccessBindingID) error
		})
		if !ok {
			return fmt.Errorf("binding stage has no atomic expiry adapter")
		}
		return staged.ExpireStagedBinding(ctx, bindingID)
	}
	col := &syncFGACollector{}
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		if err := s.AcquireBindingLock(ctx, bindingID); err != nil {
			return fmt.Errorf("expire: acquire binding lock %s: %w", bindingID, err)
		}
		if err := s.LockBindingForDeactivation(ctx, bindingID); err != nil {
			return fmt.Errorf("expire: lock binding %s: %w", bindingID, err)
		}
		bs, ok, err := s.LoadBinding(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("expire: load binding %s: %w", bindingID, err)
		}
		if !ok || !bs.Active {
			return nil // Уже исчезла / не ACTIVE — истекать нечему (идемпотентно).
		}
		// Сначала CAS ACTIVE→REVOKED: если другой путь уже отозвал, выходим,
		// не трогая кортежи (их отозвал тот путь).
		revoked, err := s.RevokeExpiredBinding(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("expire: cas revoke %s: %w", bindingID, err)
		}
		if !revoked {
			return nil
		}
		if err := emitSubjectChangeOfExpiry(ctx, s, bs.Subjects); err != nil {
			return fmt.Errorf("expire: subject change %s: %w", bindingID, err)
		}
		if err := emitRevokedAuditOfExpiry(ctx, s, bs); err != nil {
			return fmt.Errorf("expire: revoked audit %s: %w", bindingID, err)
		}
		// Снимается ВЕСЬ реестр выдачи, прочитанный после замков и CAS (порядок тот же,
		// что у отзыва: advisory → FOR UPDATE → реестр), а не набор, выведенный из
		// снимка каталога процесса: тип члена мог выпасть из снимка этой реплики, и
		// ключ `<тип модели>:<id>` собрать было бы нечем (kaname#933). На истечении
		// уходят ВСЕ члены выдачи, так что ни один из них реестр не держит. Факт, который
		// держит другая действующая выдача того же субъекта, оставляет свёртка журнала
		// (kaname#919): строки реестра этой выдачи забыты здесь же, и она уже REVOKED.
		if err := r.revokeWholeLedger(ctx, s, bindingID, col); err != nil {
			return fmt.Errorf("expire: %w", err)
		}
		members, err := s.CurrentMembers(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("expire: current members %s: %w", bindingID, err)
		}
		for _, m := range members {
			if err := s.DeleteMember(ctx, bindingID, m.RuleFP, m.ObjectType, m.ObjectID); err != nil {
				return fmt.Errorf("expire: delete member %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
			}
		}
		// Отложенные строки снятия; факт другой действующей выдачи оставит свёртка.
		return r.flushDeletes(ctx, s, col)
	}); err != nil {
		return err
	}
	return nil
}

// emitSubjectChangeOfExpiry — строка журнала смены субъекта на КАЖДОГО субъекта
// снятой сроком выдачи, той же формы, что пишут отзыв и удаление (`revoke.go`,
// `delete.go`): вид события `binding_revoke`, `op` `binding_delete`. По строке край
// сбрасывает кэш решений субъекта и закрывает его открытые потоки; без неё снятие
// сроком край узнавал бы лишь по бюджету потока (kaname#920). Перечень субъектов
// уже несёт откат на легаси-одиночку (BindingScope.Subjects), поэтому выдача,
// записанная до многосубъектной модели, строки не теряет.
func emitSubjectChangeOfExpiry(ctx context.Context, s ReconcileStore, subjects []domain.Subject) error {
	for _, sub := range subjects {
		if err := s.EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{
			SubjectID:   string(sub.ID),
			SubjectType: string(sub.Type),
			EventType:   "binding_revoke",
			Op:          "binding_delete",
		}); err != nil {
			return err
		}
	}
	return nil
}

// expiryAuditActor — действующее лицо аудита снятия сроком. Человека у истечения
// нет; имя называет путь, а не подставляет выдавшего, — по следу видно, что выдачу
// сняло истечение, а не тот, кто её выдал.
const expiryAuditActor = "system:expiry"

// emitRevokedAuditOfExpiry — строка аудита «отозвано» на КАЖДОГО субъекта снятой
// сроком выдачи, той же формы, что пишут отзыв и удаление (revokedAuditFor в
// access_binding): вид `iam.access_binding.revoked`, область, роль, выдача, область
// арендатора — аккаунт для выдачи на аккаунте, пусто для прочих (auditTenantAccountID
// там же). Одинаковость формы держит не перечень, а проба: строка истечения
// сверяется со строкой настоящего отзыва в той же базе
// (reconcile_expiry_revoked_audit_integration_test.go).
func emitRevokedAuditOfExpiry(ctx context.Context, s ReconcileStore, bs BindingScope) error {
	tenant := ""
	if bs.Scope.Type == "account" {
		tenant = bs.Scope.ID
	}
	for _, sub := range bs.Subjects {
		if err := s.EmitAuditEvent(ctx, abrepo.AuditEvent{
			EventType:       abrepo.AuditEventTypeRevoked,
			Actor:           expiryAuditActor,
			SubjectType:     string(sub.Type),
			SubjectID:       string(sub.ID),
			ResourceType:    bs.Scope.Type,
			ResourceID:      bs.Scope.ID,
			RoleID:          bs.RoleID,
			BindingID:       string(bs.BindingID),
			TenantAccountID: tenant,
		}); err != nil {
			return err
		}
	}
	return nil
}

// reconcileBinding — основное сравнение. Вычисляет желаемый набор членов
// выдачи и сводит его с материализованным набором в транзакции вызывающей стороны.
func (r *Reconciler) reconcileBinding(ctx context.Context, s ReconcileStore, bindingID domain.AccessBindingID, converge bool, col *syncFGACollector) error {
	// Сериализуем параллельные проходы одной выдачи на
	// транзакционном advisory-замке ДО чтения/записи, сохраняя инвариант однократной
	// материализации при N репликах.
	if err := s.AcquireBindingLock(ctx, bindingID); err != nil {
		return fmt.Errorf("acquire binding lock %s: %w", bindingID, err)
	}
	bs, ok, err := s.LoadBinding(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("load binding %s: %w", bindingID, err)
	}
	if !ok || !bs.Active {
		// Удалена либо больше не ACTIVE — повторно не материализуем.
		return nil
	}

	desired, err := r.desiredMembers(ctx, s, bs)
	if err != nil {
		return err
	}
	// Размер материализации привязки — до диффа: величина относится к тому, что
	// привязка ТРЕБУЕТ, а не к тому, сколько строк изменилось в этом проходе.
	// Иначе повторный проход по неизменившейся привязке докладывал бы ноль, и
	// «крупная привязка» стала бы неотличима от «привязка ничего не материализует».
	r.observeSize(desired)

	current, err := s.CurrentMembers(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("current members %s: %w", bindingID, err)
	}

	return r.applyDiff(ctx, s, bs, desired, current, bindingEmitted(s, bindingID, converge), col)
}

// reconcileBindingForObject — СУЖЕННЫЙ ДО ОБЪЕКТА аналог reconcileBinding: сравнивает
// членство ОДНОЙ выдачи НА ОДНОМ ОБЪЕКТЕ вместо пересчёта всего
// желаемого набора во всей области выдачи. Именно это нужно событию смены объекта
// (вставка/удаление зеркала, UPDATE меток) — обоснование точного, а не приближённого
// сужения дано в описании ReconcileObject.
//
// Сохраняется всё, что полный путь делает для объекта: решение ACTIVE/REJECTED,
// аудит включения, немедленный отзыв выбывшего члена и отложенный
// сброс удаления. Взаимное исключение с параллельным проходом той же
// выдачи тоже сохраняется — тем же EXCLUSIVE advisory-замком, — но берёт его
// ВЫЗЫВАЮЩИЙ, сразу на весь веер и до первой записи прохода (см. тело функции). Меняется лишь РАЗМЕР
// сравниваемого набора: O(1) по области вместо O(scope). Критическая
// секция теперь охватывает несколько индексированных строк вместо пересчёта всей области,
// поэтому замок выдачи, за которым стоят все соседние регистрации аккаунта, удерживается
// лишь долю прежнего времени — это и есть цель исправления пропускной способности.
//
// objPresent=false (объект ушёл из источника — DELETE зеркала) даёт ПУСТОЙ
// желаемый набор, вызывающий ровно тот отзыв устаревшего, который полный путь делал,
// когда объект переставал появляться в MatchAllInScope.
func (r *Reconciler) reconcileBindingForObject(
	ctx context.Context, s ReconcileStore, bindingID domain.AccessBindingID,
	objectType, objectID string, obj domain.MirrorObject, objPresent bool, ancestors *ancestorMemo,
	col *syncFGACollector,
) error {
	// ЗАМОК ЭТОЙ ВЫДАЧИ УЖЕ ВЗЯТ ВЫЗЫВАЮЩИМ — вместе со всеми остальными замками
	// веера и ДО первой записи прохода (ReconcileObject, AcquireBindingLocks).
	// Serialization против параллельного прохода той же выдачи от этого не слабеет:
	// ключ и режим те же, меняется только МОМЕНТ захвата. Брать его здесь повторно
	// нельзя не по стоимости, а по существу: тогда первый замок веера снова
	// оказывался бы взят после записей предыдущей выдачи, и обратный порядок родов
	// ресурсов вернулся бы вместе с ним.
	bs, ok, err := s.LoadBinding(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("load binding %s: %w", bindingID, err)
	}
	if !ok || !bs.Active {
		// Удалена либо больше не ACTIVE — повторно не материализуем.
		return nil
	}

	// Изменился КОНТЕЙНЕР вложенного правила этой выдачи (метки, удаление):
	// от него зависит охват всех его потомков, а не только он сам (kaname#874).
	// Сужение до одного объекта здесь неверно — выдача пересчитывается целиком,
	// под уже взятым замком, тем же путём, что полный проход.
	if nestsUnder(bs, objectType) {
		desired, err := r.desiredMembers(ctx, s, bs)
		if err != nil {
			return err
		}
		current, err := s.CurrentMembers(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("current members %s: %w", bindingID, err)
		}
		return r.applyDiff(ctx, s, bs, desired, current, bindingEmitted(s, bindingID, false), col)
	}

	var desired []DesiredMember
	if objPresent {
		anc, err := ancestors.forBinding(bs)
		if err != nil {
			return err
		}
		desired = desiredMembersForObject(r.cat.Facts(), bs, obj, anc)
	}

	// УЗКАЯ база сравнения: члены этой выдачи только НА ЭТОМ ОБЪЕКТЕ.
	current, err := s.CurrentMembersForObject(ctx, bindingID, objectType, objectID)
	if err != nil {
		return fmt.Errorf("current members for object %s %s:%s: %w", bindingID, objectType, objectID, err)
	}

	return r.applyDiff(ctx, s, bs, desired, current, objectEmitted(s, bindingID, objectType, objectID), col)
}

// desiredMembersForObject выводит членов, нужных ОДНОЙ выдаче НА ОДНОМ ОБЪЕКТЕ. Это
// суженный до объекта эквивалент desiredMembers/desiredRuleMembers, собранный из
// ТЕХ ЖЕ пообъектных решений: selectorMatchesObject (чистый Go-аналог
// SQL отбора ветви), пересечение с пообъектной целью, desiredMemberForObject
// (решение о включении + вывод кортежей) и scopeSelfMember, — поэтому узкий и полный
// пути не могут разойтись в доступе, выдаваемом объекту.
//
// Полный путь находит НАБОР кандидатов для ветви (MatchAllInScope / MatchByIDs /
// MatchSelector), затем решает по каждому; здесь кандидат дан, поэтому выполняется
// лишь решение по кандидату. Три ветви соответствуют точно:
//
// ARM_ANCHOR → принадлежность типу (фильтр области уже учтён: объект — тот,
//
//	что изменился, а IsContainedIn повторно проверяет его область как прежде)
//
// ARM_NAMES → условие id ∈ ResourceNames
// ARM_LABELS → условие labels @> matchLabels
//
// Член собственной области (ярус выдачи на account:<X>/project:<X>) входит в желаемый
// набор объекта ровно тогда, когда изменённый объект — СОБСТВЕННЫЙ якорь области выдачи:
// смена меток project/account приходит через iam-direct. Подавляется для
// пообъектной цели, как в desiredRuleMembers (выдача на всём якоре области
// противоречит пообъектной выдаче минимальных привилегий).
func desiredMembersForObject(cat *catalog.Facts, bs BindingScope, o domain.MirrorObject,
	ancestors []domain.MirrorObject) []DesiredMember {
	perObject := len(bs.Target.Resources) > 0

	var out []DesiredMember
	if len(bs.ScopeSelfVerbs) > 0 && !perObject &&
		o.ObjectType == "iam."+bs.Scope.Type && o.ObjectID == bs.Scope.ID {
		if sm, ok := scopeSelfMember(cat, grantees(bs, bs.ScopeSelfVerbs, false), bs.Scope.Type, bs.Scope.ID); ok {
			out = append(out, sm)
		}
	}
	// Контейнерные действия правил (kaname#1003, creator.go) — члены на объекте
	// ОБЛАСТИ: путь по объекту обязан их выводить, иначе событие аккаунта сняло бы
	// их как устаревшие.
	if o.ObjectType == "iam."+bs.Scope.Type && o.ObjectID == bs.Scope.ID {
		out = append(out, containerMembers(cat, bs)...)
	}
	// Минимальные привилегии пообъектной цели (F8, IAM-1-21): правило даёт объект лишь тогда,
	// когда цель выдачи тоже его называет. Едино для всех ветвей, ровно как
	// matchSelectorObjects пересекает совпавший набор. Вложенное правило (kaname#874)
	// судит цель по КОНТЕЙНЕРУ среди предков объекта, а не по самому объекту.
	inTarget := !perObject || bs.Target.Contains(o.ObjectType, o.ObjectID)
	for _, sel := range bs.Selectors {
		gs := selectorGrantees(bs, sel)
		if len(gs) == 0 {
			continue
		}
		if sel.Container != nil {
			if !nestedCoversObject(sel, bs, o, ancestors) {
				continue
			}
		} else if !inTarget || !selectorMatchesObject(sel, o) {
			continue
		}
		dm, ok := desiredMemberForObject(cat, bs.Policy, gs, sel, o, bs.Scope)
		if !ok {
			// У типа нет объекта FGA в модели → нет кортежа → пропускаем объект
			// (отказ по умолчанию: опечатка в типе ничего не выдаёт).
			continue
		}
		out = append(out, dm)
	}
	// Публичное чтение детям (kaname#856): тот же вывод, что у полного прохода
	// (desiredRuleMembers), — иначе два пути разошлись бы в составе.
	return withPublicReaders(cat, bs, out)
}

// desiredMembers вычисляет желаемый набор членов и решения о включении для
// выдачи. Плоская явная модель RBAC использует ЕДИНУЮ материализацию: единственный
// источник динамического членства — материализующие правила роли (ARM_ANCHOR(all) +
// ARM_NAMES + ARM_LABELS). Выдача роли без материализующих селекторов
// тонкая — без материализованных членов (кортежи яруса прежней роли только с разрешениями
// относятся к Create, а не к этому коду).
func (r *Reconciler) desiredMembers(ctx context.Context, s ReconcileStore, bs BindingScope) ([]DesiredMember, error) {
	if len(bs.Selectors) > 0 {
		return r.desiredRuleMembers(ctx, s, bs)
	}
	return nil, nil // Тонкая выдача — без материализованных членов.
}

// matchSelectorObjects находит кандидатов ОДНОГО селектора по его ветви,
// по обоим источникам (зеркало + iam-direct, раздельно): ARM_ANCHOR(all) →
// MatchAllInScope; ARM_NAMES → MatchByIDs; ARM_LABELS → MatchSelector(labels @>).
// Включение повторно проверяет вызывающая сторона (IsContainedIn); здесь определяется лишь
// набор кандидатов. `scope` выдачи передаётся ветви ANCHOR, чтобы набор кандидатов
// сужался в SQL до O(scope), а не читался по кластеру с последующим сужением в Go:
// окончательна проверка Go (SQL-предикат — доказанное надмножество).
//
// ПООБЪЕКТНАЯ ЦЕЛЬ (F8, IAM-1-21): если выдача несёт пообъектную цель
// (target.Resources непуст), ветвь ANCHOR находит кандидатов ПО id цели
// (MatchByIDs) вместо MatchAllInScope, поэтому выдача минимальных привилегий никогда не
// читает/материализует всю область, а совпадения КАЖДОЙ ветви в конце ПЕРЕСЕКАЮТСЯ
// с целью (правило роли даёт объект, только если цель тоже его называет).
func (r *Reconciler) matchSelectorObjects(ctx context.Context, s ReconcileStore, sel domain.RuleSelector, scope domain.ScopeAnchor, target domain.AccessTarget) ([]domain.MirrorObject, error) {
	mirrorTypes, iamTypes := partitionByFeed(sel.ObjectTypes)
	var matched []domain.MirrorObject
	if len(mirrorTypes) > 0 {
		objs, err := r.matchByArm(ctx, sel, mirrorTypes, false, s, scope, target)
		if err != nil {
			return nil, fmt.Errorf("match rule selector %s (mirror): %w", sel.RuleFP, err)
		}
		matched = append(matched, objs...)
	}
	if len(iamTypes) > 0 {
		objs, err := r.matchByArm(ctx, sel, iamTypes, true, s, scope, target)
		if err != nil {
			return nil, fmt.Errorf("match rule selector %s (iam-direct): %w", sel.RuleFP, err)
		}
		matched = append(matched, objs...)
	}
	// Пересечение с пообъектной целью: оставляем ТОЛЬКО названные целью объекты (едино для
	// всех ветвей: якорь уже разрешён по id цели, но имена/метки могут совпасть с объектами
	// вне цели, поэтому отсекаем их пересечением; минимальные привилегии, IAM-1-21).
	if len(target.Resources) > 0 {
		matched = filterMatchedToTarget(matched, target)
	}
	return matched, nil
}

// matchByArm направляет отбор ветви к нужному источнику (зеркало или iam-direct).
// Ветвь ANCHOR передаёт `scope` выдачи для сужения области в SQL; ветви NAMES/LABELS
// уже узкие (конкретные id / метки), И совпадение чужой области нужно для
// аудита REJECTED по включению, поэтому они НЕ ОГРАНИЧЕНЫ ОБЛАСТЬЮ (сведение перепроверяет).
//
// Для ПООБЪЕКТНОЙ цели ветвь ANCHOR находит кандидатов ПО id цели
// (MatchByIDs) вместо MatchAllInScope: выдача минимальных привилегий материализует лишь
// названные объекты, никогда всю область (IAM-1-21). Ветви NAMES/LABELS сохраняют свой узкий
// отбор; вызывающая сторона пересекает его с целью (matchSelectorObjects).
func (r *Reconciler) matchByArm(ctx context.Context, sel domain.RuleSelector, types []string, iamDirect bool, s ReconcileStore, scope domain.ScopeAnchor, target domain.AccessTarget) ([]domain.MirrorObject, error) {
	switch sel.Arm {
	case domain.ArmNames:
		if iamDirect {
			return s.MatchByIDsIAMDirect(ctx, types, sel.ResourceNames)
		}
		return s.MatchByIDs(ctx, types, sel.ResourceNames)
	case domain.ArmLabels:
		if iamDirect {
			return s.MatchIAMDirect(ctx, types, sel.MatchLabels)
		}
		return s.MatchSelector(ctx, types, sel.MatchLabels)
	default: // ArmAnchor (все).
		if len(target.Resources) > 0 {
			// Пообъектная цель: находим кандидатов якоря по id цели этих
			// типов (никогда не читаем всю область). Пусто ⇒ кандидатов этих типов нет.
			ids := target.ResourceIDsForTypes(types)
			if len(ids) == 0 {
				return nil, nil
			}
			if iamDirect {
				return s.MatchByIDsIAMDirect(ctx, types, ids)
			}
			return s.MatchByIDs(ctx, types, ids)
		}
		if iamDirect {
			return s.MatchAllInScopeIAMDirect(ctx, types, scope)
		}
		return s.MatchAllInScope(ctx, types, scope)
	}
}

// filterMatchedToTarget оставляет лишь совпавшие объекты, названные пообъектной целью
// (точные точечный тип + id). Это единое пересечение для КАЖДОЙ ветви, когда
// выдача несёт пообъектную цель, поэтому правило роли (якорь/имена/метки) может дать
// только названный целью объект (минимальные привилегии, IAM-1-21). Не вызывается для
// AllInScope/пустой цели (вызывающий проверяет len(target.Resources) > 0).
func filterMatchedToTarget(matched []domain.MirrorObject, target domain.AccessTarget) []domain.MirrorObject {
	out := matched[:0:0]
	for _, o := range matched {
		if target.Contains(o.ObjectType, o.ObjectID) {
			out = append(out, o)
		}
	}
	return out
}

// desiredRuleMembers вычисляет желаемое членство по правилам для выдачи,
// управляемой role.rules (единая материализация). Для КАЖДОГО материализующего селектора
// (rule_fp) находит кандидатов по его ветви, проверяет включение
// и выпускает пообъектные кортежи, ВЫВЕДЕННЫЕ ИЗ ГЛАГОЛОВ ПРАВИЛА (v_* по глаголам +
// ярус — те же доменные функции, что у прежнего пути выпуска). Совпавший чужой
// объект получает REJECTED (без кортежа + аудит, защита границ области). ОДИН объект
// под двумя правилами даёт двух желаемых членов с разными rule_fp.
func (r *Reconciler) desiredRuleMembers(ctx context.Context, s ReconcileStore, bs BindingScope) ([]DesiredMember, error) {
	var out []DesiredMember
	// Каталожный факт берётся ОДИН раз на проход: обновление снимка подменяет
	// указатель, и три чтения могли бы увидеть два разных каталога — член
	// правила по одному, член `public_reader` по другому.
	cat := r.cat.Facts()

	// perObject — выдача несёт пообъектную цель (Target.Resources непуст):
	// выдача ограничена РОВНО названными объектами (минимальные привилегии, IAM-1-21).
	// Выдача на якоре собственной области подавляется; совпадения каждого селектора
	// пересекаются ниже с набором цели.
	perObject := len(bs.Target.Resources) > 0

	// Член собственной области: ярус роли (+ глагольные v_*) НА
	// СОБСТВЕННОМ ОБЪЕКТЕ ОБЛАСТИ ВЫДАЧИ (`account:<X>`/`project:<X>`). Это
	// якорь проверки записи / сохранения доступа, который давал снятый выпуск
	// при создании выдачи; теперь он материализуется ЕДИНСТВЕННЫМ путём сведения. Это НЕ объект
	// содержимого, совпавший с селектором: у роли суперпользователя `*.*` пустой
	// ObjectTypes селектора (шаблон пропущен), поэтому без этого субъект потерял бы ярус
	// на области полностью. Ключуется
	// сигнальным rule_fp, чтобы иметь свою строку члена + происхождение в реестре (симметричный
	// отзыв). Путь супер-администратора кластера обрывается раньше и здесь не материализуется.
	//
	// ПОДАВЛЯЕТСЯ для пообъектной цели: выдача яруса на ВСЁМ объекте области
	// (account:<X>/project:<X>) противоречит пообъектной выдаче минимальных привилегий: цель
	// называет конкретное содержимое, а не якорь области. Поэтому пообъектная цель никогда не
	// материализует члена собственной области (защита от избыточной выдачи, IAM-1-21).
	if len(bs.ScopeSelfVerbs) > 0 && !perObject {
		if sm, ok := scopeSelfMember(cat, grantees(bs, bs.ScopeSelfVerbs, false), bs.Scope.Type, bs.Scope.ID); ok {
			out = append(out, sm)
		}
	}

	for _, sel := range bs.Selectors {
		// Субъекты, которым правило что-то даёт: классу — только чтение, а
		// вложенное правило классу не применяется вовсе (subjects.go). Никому —
		// правило не материализует ничего и кандидатов не ищет.
		gs := selectorGrantees(bs, sel)
		if len(gs) == 0 {
			continue
		}
		if sel.Container != nil {
			// Вложенное правило (kaname#874): потомки контейнеров, выбранных
			// выдачей; классам выдачи — ни одного (ND-10, nested.go).
			matched, err := r.matchNestedObjects(ctx, s, sel, bs)
			if err != nil {
				return nil, err
			}
			for _, o := range matched {
				if dm, ok := desiredMemberForObject(cat, bs.Policy, gs, sel, o, bs.Scope); ok {
					out = append(out, dm)
				}
			}
			continue
		}
		// Правило, которое на своих типах называет одни контейнерные действия
		// (kaname#1003), объектам не даёт ничего: его член — на объекте области
		// (containerMembers). Кандидатов оно не ищет вовсе — перебора учёток
		// аккаунта у выдачи роли создателя нет.
		if !selectorWritesObjects(cat, sel) {
			continue
		}
		var matched []domain.MirrorObject
		var err error
		if sel.CreatedBySubject {
			// Селектор создателя: кандидаты — объекты области, созданные
			// субъектами-учётками выдачи, отбором по индексу (аккаунт, создатель),
			// а не перебором объектов области (§3 приёмки, «производительность»).
			matched, err = r.matchCreatorObjects(ctx, s, sel, bs)
		} else {
			// Передаём область и цель привязки, чтобы ветвь ANCHOR разрешила набор кандидатов
			// по цели (по id для пообъектной; иначе O(scope) с проталкиванием фильтра), а совпадения
			// каждой ветви пересекаются с целью. IsContainedIn ниже остаётся
			// окончательной повторной проверкой включения.
			matched, err = r.matchSelectorObjects(ctx, s, sel, bs.Scope, bs.Target)
		}
		if err != nil {
			return nil, err
		}
		for _, o := range matched {
			// Пообъектное решение ОБЩЕЕ с быстрым прямым путём
			// (desiredMemberForObject), поэтому полный пересчёт и прямой путь
			// выводят ПОБАЙТОВО ОДИНАКОВЫЕ кортежи (идемпотентность: прямой и асинхронный полный
			// пути выпускают один набор, а запись FGA по разнице чтения пропускает повторы).
			dm, ok := desiredMemberForObject(cat, bs.Policy, gs, sel, o, bs.Scope)
			if !ok {
				// У типа нет объекта FGA в модели → нет кортежа → пропускаем объект
				// (отказ по умолчанию: опечатка в типе ничего не выдаёт).
				continue
			}
			out = append(out, dm)
		}
	}
	// Контейнерные действия правил (kaname#1003, creator.go): члены на объекте
	// области — тот же вывод, что у пути по объекту.
	out = append(out, containerMembers(cat, bs)...)
	// Публичное чтение детям (kaname#856): член `public_reader` на каждом
	// объявленном контейнере, который выдача уже даёт действующим членом, — тот
	// же вывод, что у прямого пути по объекту (desiredMembersForObject).
	return withPublicReaders(cat, bs, out), nil
}

// desiredMemberForObject вычисляет DesiredMember, порождённого материализующим селектором
// для ОДНОГО кандидата. Это единственное пообъектное место решения, ОБЩЕЕ для
// полного пересчёта (desiredRuleMembers) и АДДИТИВНОГО быстрого прямого пути
// (forwardObjectForBinding), поэтому пути не могут разойтись в кортежах доступа
// объекта (идемпотентность прямого пути + асинхронной страховки).
//
//   - Вне области выдачи (подмена меток через границу области / чужой родитель)
//     → член REJECTED (ok=true, без кортежей). Полный путь записывает его и аудит;
//     прямой путь пропускает (только добавляющий путь не пишет не-ACTIVE члена).
//   - В области → ACTIVE-член с пообъектными кортежами, выведенными из ГЛАГОЛОВ
//     правила (v_* + совместимый прежний ярус через ruleObjectTuples). Правила ARM_LABELS/ANCHOR
//     исключены из CompileRules, поэтому кортежи идут из глаголов правила, а не RolePerms.
//   - Типу объекта не соответствует тип объекта FGA → ok=false (пропуск; опечатка в типе
//     ничего не выдаёт, отказ по умолчанию).
func desiredMemberForObject(cat *catalog.Facts, policy domain.RulePolicy, gs []grantee, sel domain.RuleSelector, o domain.MirrorObject, scope domain.ScopeAnchor) (DesiredMember, bool) {
	// Селектор создателя (kaname#1003, creator.go): объект входит в охват правила
	// только для субъекта, который его создал. Никому — объект правилом не
	// выбран вовсе (ни члена, ни отвергнутого члена: охвата нет, а не вне области).
	gs = creatorGrantees(sel, gs, o)
	if len(gs) == 0 {
		return DesiredMember{}, false
	}
	if !o.IsContainedIn(scope) {
		return DesiredMember{
			RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
			Status: domain.VerificationRejected,
		}, true
	}
	// Кортежи — объединение по субъектам `gs`, каждому со своими глаголами
	// (subjects.go, kaname#880). Отказ «у типа нет объекта модели» от субъекта
	// не зависит: первый же отказ — отказ всего члена.
	var tuples []domain.MembershipTuple
	for _, g := range gs {
		// Контейнерные действия кортежей на объекте не пишут (kaname#1003): их
		// отношение лежит на родителе (containerMembers). Правило, у которого на
		// типе объекта кроме них ничего нет, объекту не даёт ничего — даже яруса.
		verbs := objectVerbsOf(cat, o.ObjectType, g.verbs)
		if len(verbs) == 0 {
			continue
		}
		t, ok := ruleObjectTuples(cat, policy, g.subject, verbs, o.ObjectType, o.ObjectID)
		if !ok {
			return DesiredMember{}, false
		}
		if sel.CreatedBySubject {
			t = verbTuplesOnly(t)
		}
		tuples = append(tuples, t...)
	}
	if len(tuples) == 0 {
		return DesiredMember{}, false
	}
	return DesiredMember{
		RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
		Status: domain.VerificationActive, Tuples: tuples,
	}, true
}

// applyDiff сводит желаемый набор с текущим материализованным: записывает через
// UPSERT членов со сменой статуса, выпускает/немедленно отзывает пообъектный кортеж FGA
// при переходах ACTIVE, пишет аудит включения при REJECTED и
// удаляет членов, ушедших из желаемого набора (немедленно отзывает их кортеж).
func (r *Reconciler) applyDiff(ctx context.Context, s ReconcileStore, bs BindingScope, desired []DesiredMember, current []domain.TargetMember, emitted *emittedView, col *syncFGACollector) error {
	// Ключ — (rule_fp, объект): член связан с породившим его правилом role.rules,
	// поэтому ОДИН объект под двумя правилами — два члена,
	// а снятое правило немедленно отзывает ТОЛЬКО своих членов.
	currentByKey := make(map[string]domain.TargetMember, len(current))
	for _, m := range current {
		currentByKey[memberRuleKey(m.RuleFP, m.ObjectType, m.ObjectID)] = m
	}
	// Объект, по которому проход ПИШЕТ член, — под замком строки зеркала до первой
	// записи (kaname#975): объект, чью регистрацию сняли после чтения отбора, члена
	// не получает, а снятие ждёт фиксации прохода, если замок взят раньше.
	desired, err := keepLiveDesired(ctx, s, desired, currentByKey)
	if err != nil {
		return err
	}
	// Только пустая исходная материализация и только ACTIVE после прежнего
	// keepLiveDesired: переходы статусов, отзыв и completion остаются ниже.
	if len(current) == 0 {
		allActive := true
		for _, d := range desired {
			if d.Status != domain.VerificationActive {
				allActive = false
				break
			}
		}
		if allActive {
			return r.applyColdActiveDiff(ctx, s, bs, desired, col)
		}
	}

	desiredByKey := make(map[string]struct{}, len(desired))

	// survivingClaims — кортежи, на которые после прохода ещё претендуют желаемые
	// ACTIVE-члены этой выдачи: целиком и по координате члена. Ключ реестра —
	// (выдача, координата члена, кортеж) без rule_fp, поэтому два члена ОДНОЙ
	// координаты (тот же объект под двумя правилами, член `public_reader` со сменой
	// ключа) делят одну строку: уходящий член забывает только строки, на которые не
	// претендует выживший член его же координаты. Строку снятия в движок получает
	// лишь кортеж, на который не претендует ни один выживший член выдачи. Набор
	// вычислен под advisory-блокировкой выдачи (параллельного прохода этой выдачи
	// нет), гонки в нём нет.
	survivingClaims := desiredActiveClaims(desired)

	for _, d := range desired {
		key := memberRuleKey(d.RuleFP, d.ObjectType, d.ObjectID)
		desiredByKey[key] = struct{}{}
		prev, existed := currentByKey[key]
		prevStatus := domain.VerificationStatus("")
		if existed {
			prevStatus = prev.VerificationStatus
		}
		if existed && prevStatus == d.Status {
			// Ключ и статус совпали. Набор кортежей члена ключом не определён: ключ
			// не несёт ни субъектов выдачи (kaname#880), ни политики роли и каталога
			// (kaname#1006), — член сводится к желаемому набору по реестру
			// выпущенного (emitted_completion.go).
			if d.Status == domain.VerificationActive {
				if err := r.convergeMemberTuples(ctx, s, bs, d, emitted, survivingClaims, col); err != nil {
					return err
				}
			}
			continue
		}

		// Сохраняем новый статус члена (UPSERT по полной координате правила).
		if err := s.UpsertMember(ctx, domain.TargetMember{
			BindingID: bs.BindingID, RoleID: domain.RoleID(bs.RoleID), RuleFP: d.RuleFP,
			ObjectType: d.ObjectType, ObjectID: d.ObjectID, VerificationStatus: d.Status,
		}); err != nil {
			return fmt.Errorf("upsert member %s/%s:%s: %w", d.RuleFP, d.ObjectType, d.ObjectID, err)
		}

		// Набор кортежей этого члена: заранее вычислен из глаголов породившего правила
		// (d.Tuples).
		tuples, tupleOK := r.memberTuples(d)
		switch d.Status {
		case domain.VerificationActive:
			if !tupleOK {
				return fmt.Errorf("membership tuple inconsistent for %s/%s:%s (role coverage desync)", d.RuleFP, d.ObjectType, d.ObjectID)
			}
			// Ставим ТОЛЬКО кортежи, ещё не поставленные этим проходом, и учитываем
			// тот же набор в коллекторе прохода; его читает вычитание удаления
			// ниже, поэтому повторно записанный здесь кортеж никогда не снимет отзыв соседнего члена
			// того же прохода.
			if fresh := col.collectNew(tuples); len(fresh) > 0 {
				if err := s.EmitTupleWrite(ctx, fresh); err != nil {
					return fmt.Errorf("emit tuple write %s:%s: %w", d.ObjectType, d.ObjectID, err)
				}
			}
			// Коммитим выданный кортеж участника в журнале вместе с остальным по координате
			// участника — на этом держатся симметричный отзыв и сведение Role.Update
			// (ban #10).
			if err := s.RecordEmittedTuples(ctx, bs.BindingID, desiredCoord(d), tuples); err != nil {
				return fmt.Errorf("record emitted tuple %s:%s: %w", d.ObjectType, d.ObjectID, err)
			}
		case domain.VerificationRejected:
			// Был ACTIVE? Немедленно отзываем устаревший кортеж и забываем его.
			// Набор отзыва — СОХРАНЁННЫЙ реестр члена (d.Tuples пуст при
			// переходе в REJECTED), а НЕ d.Tuples.
			if prevStatus == domain.VerificationActive {
				if err := r.revokeMemberTuples(ctx, s, bs, prev, survivingClaims, col); err != nil {
					return err
				}
			}
			if err := s.EmitContainmentAudit(ctx, bs.BindingID, d.ObjectType, d.ObjectID, bs.Scope); err != nil {
				return fmt.Errorf("emit containment audit %s:%s: %w", d.ObjectType, d.ObjectID, err)
			}
		case domain.VerificationPending:
			// Кортежа нет; если был ACTIVE (объект ушёл из зеркала), отзываем и забываем.
			if prevStatus == domain.VerificationActive {
				if err := r.revokeMemberTuples(ctx, s, bs, prev, survivingClaims, col); err != nil {
					return err
				}
			}
		}
	}

	// Члены, полностью ушедшие из желаемого набора (снято правило /
	// метка): немедленно отзываем кортеж и удаляем строку. Набор кортежей выбывшего
	// члена читается из сохранённых для него строк реестра
	// (revokeTuplesFor): глаголы снятого правила исчезли, поэтому реестр — единственный
	// источник истины.
	for key, m := range currentByKey {
		if _, stillDesired := desiredByKey[key]; stillDesired {
			continue
		}
		if m.VerificationStatus == domain.VerificationActive {
			if err := r.revokeMemberTuples(ctx, s, bs, m, survivingClaims, col); err != nil {
				return err
			}
		}
		if err := s.DeleteMember(ctx, bs.BindingID, m.RuleFP, m.ObjectType, m.ObjectID); err != nil {
			return fmt.Errorf("delete member %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
		}
	}
	return nil
}

// Пределы одного сброса: число членов и верхняя оценка кортежей реестра/новых кортежей.
// Один большой член сохраняется целиком, отдельной партией, как в прежнем diff.
const (
	coldActiveBatchMembers = 4096
	coldActiveBatchTuples  = 4096
)

// applyColdActiveDiff вызывается после общего замка и фильтра keepLiveDesired.
// Все партии используют тот же store/tx и общий collector: порядок первых кортежей
// и реестр каждой полной координаты сохраняются между партиями и правилами.
func (r *Reconciler) applyColdActiveDiff(ctx context.Context, s ReconcileStore, bs BindingScope, desired []DesiredMember, col *syncFGACollector) error {
	var writes forwardWriteSet
	for _, d := range desired {
		tuples, ok := r.memberTuples(d)
		if !ok {
			return fmt.Errorf("membership tuple inconsistent for %s/%s:%s (role coverage desync)", d.RuleFP, d.ObjectType, d.ObjectID)
		}
		// Проверка до collectNew не меняет общий collector и порядок первых tuples.
		// Ledger содержит все tuples члена, fresh — только их подмножество.
		if len(writes.members) > 0 && (len(writes.members) == coldActiveBatchMembers || len(tuples) > coldActiveBatchTuples-len(writes.ledger)) {
			if err := writes.writeLive(ctx, s); err != nil {
				return err
			}
			writes = forwardWriteSet{}
		}
		d.Tuples = tuples
		if err := r.materializeForwardMember(ctx, s, bs, d, col, &writes); err != nil {
			return err
		}
		if len(writes.members) == coldActiveBatchMembers || len(writes.ledger) >= coldActiveBatchTuples {
			// Исходный keepLiveDesired уже отфильтровал весь набор под замками этой tx.
			if err := writes.writeLive(ctx, s); err != nil {
				return err
			}
			writes = forwardWriteSet{}
		}
	}
	if len(writes.members) == 0 {
		return nil
	}
	return writes.writeLive(ctx, s)
}

// mirrorFed — объект питается зеркалом регистраций: его строку удаляет снятие
// регистрации. Объекты собственных таблиц iam (`iam.*`) зеркала не имеют.
func mirrorFed(objectType string) bool {
	return domain.FeedSourceForType(objectType) == domain.FeedMirror
}

// liveObjects запирает строки зеркала объектов `objs` (LockMirrorObjects,
// kaname#975) и отвечает, есть ли строка объекта. Объект собственной таблицы iam
// замка зеркала не берёт и считается живым: его снятие — не снятие регистрации.
func liveObjects(ctx context.Context, s ReconcileStore, objs []MemberCoord) (func(MemberCoord) bool, error) {
	seen := make(map[MemberCoord]struct{}, len(objs))
	mirror := make([]MemberCoord, 0, len(objs))
	for _, o := range objs {
		if !mirrorFed(o.ObjectType) {
			continue
		}
		if _, dup := seen[o]; dup {
			continue
		}
		seen[o] = struct{}{}
		mirror = append(mirror, o)
	}
	if len(mirror) == 0 {
		return func(MemberCoord) bool { return true }, nil
	}
	present, err := s.LockMirrorObjects(ctx, mirror)
	if err != nil {
		return nil, fmt.Errorf("lock mirror objects: %w", err)
	}
	return func(o MemberCoord) bool {
		if !mirrorFed(o.ObjectType) {
			return true
		}
		_, ok := present[o]
		return ok
	}, nil
}

// keepLiveDesired — желаемые члены без тех, чей объект проход собирается ЗАПИСАТЬ
// (член новый либо меняет статус), а строки его зеркала под замком уже нет
// (kaname#975). Такой объект выбыл из отбора между чтением и записью: член по нему
// не пишется, а прежний член той же координаты выпадает из желаемого и снимается
// тем же проходом. Члены без записи (статус прежний) замка не берут — их объект
// проход не трогает, и периодическое сведение не платит замком за каждый объект
// области. Ожидающий член (PENDING) объекта зеркала не имеет по определению и
// фильтром не судится.
func keepLiveDesired(ctx context.Context, s ReconcileStore, desired []DesiredMember, current map[string]domain.TargetMember) ([]DesiredMember, error) {
	writes := make(map[MemberCoord]struct{})
	for _, d := range desired {
		if d.Status == domain.VerificationPending {
			continue
		}
		if prev, ok := current[memberRuleKey(d.RuleFP, d.ObjectType, d.ObjectID)]; ok && prev.VerificationStatus == d.Status {
			continue
		}
		writes[desiredCoord(d)] = struct{}{}
	}
	if len(writes) == 0 {
		return desired, nil
	}
	objs := make([]MemberCoord, 0, len(writes))
	for c := range writes {
		objs = append(objs, c)
	}
	live, err := liveObjects(ctx, s, objs)
	if err != nil {
		return nil, err
	}
	out := desired[:0:0]
	for _, d := range desired {
		c := desiredCoord(d)
		if _, written := writes[c]; written && d.Status != domain.VerificationPending && !live(c) {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}

// memberTuples возвращает набор кортежей FGA ЖЕЛАЕМОГО члена. В модели RBAC
// на правилах каждый материализованный член происходит из правила ARM_LABELS
// роли role.rules, его кортежи заранее выведены из глаголов правила (d.Tuples).
// Член без кортежей — ACTIVE-член с неизвестным типом FGA, уже пропущенный вызывающим в
// desiredRuleMembers; считается рассогласованием покрытия (отказ по умолчанию).
func (r *Reconciler) memberTuples(d DesiredMember) ([]domain.MembershipTuple, bool) {
	if len(d.Tuples) > 0 {
		return d.Tuples, true
	}
	return nil, false
}

// revokeMemberTuples немедленно отзывает живые кортежи FGA прежде ACTIVE-члена
// (переход ACTIVE→REJECTED/PENDING ЛИБО выбывший член) и синхронно забывает их
// из реестра (ban #10). Набор отзыва — СОХРАНЁННЫЙ для члена
// набор кортежей — строки реестра ЕГО координаты (revokeTuplesFor), НЕ выведенные заново из
// возможно изменённой роли (глаголы снятого правила исчезли, поэтому единственный источник истины —
// реестр).
//
// Множеств два (claims — набор выживших ACTIVE-членов этой выдачи после прохода):
//   - ЗАБЫТЬ: строки своей координаты минус кортежи, на которые претендует выживший
//     член ТОЙ ЖЕ координаты, — его строка та же, и забытая она оставила бы его без
//     записи о выданном;
//   - СНЯТЬ в движке: свои кортежи минус кортежи ВСЕХ выживших членов выдачи —
//     кортеж, который выдача ещё выпускает другой координатой, не снимается.
//
// Строка снятия ОТЛОЖЕНА в коллектор (deferDelete) и уходит в конце прохода
// (flushDeletes). Факт, который держит другая действующая выдача того же субъекта либо
// строка другой координаты, оставляет свёртка строки снятия под замком строки факта
// (kaname#919) — для этого своя строка ведомости ОБЯЗАНА уйти до строки снятия, иначе
// выдача держит факт сама: ForgetEmittedTuples стоит здесь, inline, раньше любого
// flushDeletes.
func (r *Reconciler) revokeMemberTuples(ctx context.Context, s ReconcileStore, bs BindingScope, m domain.TargetMember, claims *memberClaims, col *syncFGACollector) error {
	coord := coordOf(m)
	tuples, err := r.revokeTuplesFor(ctx, s, bs, m)
	if err != nil {
		return err
	}
	var forget []LedgerRow
	var revoke []domain.MembershipTuple
	for _, t := range tuples {
		if claims.claimedAt(coord, t) {
			continue // выживший член той же координаты держит ту же строку.
		}
		forget = append(forget, LedgerRow{Member: coord, Tuple: t})
		if claims.claimed(t) {
			continue // выдача ещё выпускает кортеж другой координатой.
		}
		revoke = append(revoke, t)
	}
	if len(forget) == 0 {
		return nil
	}
	// Своя строка реестра — раньше строки снятия (kaname#919).
	if err := s.ForgetEmittedTuples(ctx, bs.BindingID, forget); err != nil {
		return fmt.Errorf("forget emitted tuple %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
	}
	if len(revoke) > 0 {
		// Строка снятия — в конец прохода (вычитание записанного тем же проходом).
		col.deferDelete(bs.BindingID, revoke)
	}
	return nil
}

// memberClaims — кортежи, на которые после прохода претендуют желаемые ACTIVE-члены
// выдачи: целиком (all) и по координате члена (byCoord). nil — не претендует никто
// (истечение снимает выдачу целиком).
type memberClaims struct {
	all     map[domain.MembershipTuple]struct{}
	byCoord map[MemberCoord]map[domain.MembershipTuple]struct{}
}

func (c *memberClaims) claimed(t domain.MembershipTuple) bool {
	if c == nil {
		return false
	}
	_, ok := c.all[t]
	return ok
}

func (c *memberClaims) claimedAt(coord MemberCoord, t domain.MembershipTuple) bool {
	if c == nil {
		return false
	}
	_, ok := c.byCoord[coord][t]
	return ok
}

// desiredActiveClaims собирает все кортежи FGA, которые желаемый участник ACTIVE
// выдаст заново в этом проходе — наборы действующих притязаний для вычитания при немедленном отзыве. Только желаемые
// участники ACTIVE несут вычисленные Tuples (у REJECTED/PENDING их нет), поэтому
// это точный набор живых притязаний после прохода.
func desiredActiveClaims(desired []DesiredMember) *memberClaims {
	c := &memberClaims{
		all:     make(map[domain.MembershipTuple]struct{}),
		byCoord: make(map[MemberCoord]map[domain.MembershipTuple]struct{}),
	}
	for _, d := range desired {
		if d.Status != domain.VerificationActive {
			continue
		}
		coord := desiredCoord(d)
		at := c.byCoord[coord]
		if at == nil {
			at = make(map[domain.MembershipTuple]struct{}, len(d.Tuples))
			c.byCoord[coord] = at
		}
		for _, t := range d.Tuples {
			c.all[t] = struct{}{}
			at[t] = struct{}{}
		}
	}
	return c
}

// revokeTuplesFor возвращает кортежи FGA для отзыва участника: СОХРАНЁННЫЕ строки журнала
// его координаты (access_binding_emitted_tuples) — «отозвать то, что было
// действительно выпущено, НЕ выводить заново из роли», потому что роль могла быть
// изменённого независимо от участника. Координата — та же, что у строки члена, и снимку
// каталога процесса здесь нечего решать: член по типу, выпавшему из снимка реплики,
// снимается тем же чтением, а строки члена ДРУГОГО типа с тем же идентификатором
// остаются нетронутыми (kaname#933). Пустой журнал ⇒ отзывать нечего.
func (r *Reconciler) revokeTuplesFor(ctx context.Context, s ReconcileStore, bs BindingScope, m domain.TargetMember) ([]domain.MembershipTuple, error) {
	tuples, err := s.LedgerTuplesForMember(ctx, bs.BindingID, coordOf(m))
	if err != nil {
		// Ошибка чтения реестра не гасится: член удаляется следом, и молча проглоченное
		// чтение оставило бы его кортежи без владельца. Откат прохода повторит снятие.
		return nil, fmt.Errorf("ledger read for member revoke %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
	}
	return tuples, nil
}

// revokeWholeLedger снимает ВЕСЬ учтённый реестром набор выдачи: строки реестра всех
// координат забываются здесь же, в той же транзакции (ban #10), строки снятия — в
// коллектор (уходят в конце прохода), по кортежу один раз. Набор берётся из реестра,
// а не из каталога процесса.
func (r *Reconciler) revokeWholeLedger(ctx context.Context, s ReconcileStore, bindingID domain.AccessBindingID, col *syncFGACollector) error {
	rows, err := s.LedgerTuples(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("read ledger of binding %s: %w", bindingID, err)
	}
	if len(rows) == 0 {
		return nil
	}
	if err := s.ForgetEmittedTuples(ctx, bindingID, rows); err != nil {
		return fmt.Errorf("forget ledger of binding %s: %w", bindingID, err)
	}
	seen := make(map[domain.MembershipTuple]struct{}, len(rows))
	tuples := make([]domain.MembershipTuple, 0, len(rows))
	for _, row := range rows {
		if _, dup := seen[row.Tuple]; dup {
			continue
		}
		seen[row.Tuple] = struct{}{}
		tuples = append(tuples, row.Tuple)
	}
	col.deferDelete(bindingID, tuples)
	return nil
}

// partitionByFeed разделяет типы селектора на питаемые зеркалом (compute/vpc/
// nlb) и iam-direct (iam.project/iam.account) по чистому доменному
// классификатору источника данных. Порядок внутри каждой части сохраняется.
func partitionByFeed(types []string) (mirror, iamDirect []string) {
	for _, t := range types {
		switch domain.FeedSourceForType(t) {
		case domain.FeedIAMDirect:
			iamDirect = append(iamDirect, t)
		default:
			mirror = append(mirror, t)
		}
	}
	return mirror, iamDirect
}

// memberRuleKey соединяет (ruleFP, objectType, objectID) разделителями NUL —
// это идентичность члена. rule_fp различает ОДИН объект, выбранный
// двумя правилами (разные члены, возможно на разных ярусах), поэтому
// сравнение applyDiff отзывает ровно членов снятого правила. NUL никогда не
// встречается в шестнадцатеричном отпечатке / точечном типе / id crockford, поэтому соединение
// однозначно.
func memberRuleKey(ruleFP, objectType, objectID string) string {
	return ruleFP + "\x00" + objectType + "\x00" + objectID
}

// dedupSortBindingIDs объединяет наборы id источников веера в срез без повторов,
// отсортированный по возрастанию. Сортировка даёт вееру ReconcileObject ГЛОБАЛЬНО согласованный
// порядок захвата advisory-замков параллельных проходов (исправление класса взаимоблокировок):
// два прохода разных объектов с пересекающимися наборами выдач
// берут общие замки в ОДНОМ порядке, поэтому взаимоблокировка невозможна (ABBA / 40P01).
func dedupSortBindingIDs(sets ...[]domain.AccessBindingID) []domain.AccessBindingID {
	seen := make(map[domain.AccessBindingID]struct{})
	for _, set := range sets {
		for _, id := range set {
			seen[id] = struct{}{}
		}
	}
	out := make([]domain.AccessBindingID, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ancestorsOf — предки объекта пути по объекту (kaname#874), читаемые ЛЕНИВО: не
// более одного раза на веер и только когда их спросила выдача с вложенным
// селектором. Без вложенных правил путь по объекту не платит лишним обращением.
// Объекту, ушедшему из источника, и собственному объекту iam предки не читаются:
// первому желаемых членов нет вовсе, второй контейнера-предка в зеркале не имеет.
func (r *Reconciler) ancestorsOf(ctx context.Context, s ReconcileStore, objectType, objectID string, present bool) *ancestorMemo {
	return &ancestorMemo{load: func() ([]domain.MirrorObject, error) {
		if !present || domain.FeedSourceForType(objectType) == domain.FeedIAMDirect {
			return nil, nil
		}
		out, err := s.AncestorObjects(ctx, objectType, objectID)
		if err != nil {
			return nil, fmt.Errorf("ancestors of %s:%s: %w", objectType, objectID, err)
		}
		return out, nil
	}}
}

// ancestorMemo — предки одного объекта, прочитанные не более одного раза. Живёт в
// одном проходе одной горутины.
type ancestorMemo struct {
	load func() ([]domain.MirrorObject, error)
	done bool
	out  []domain.MirrorObject
	err  error
}

// forBinding — предки объекта, если выдача `bs` их спрашивает (у неё есть
// вложенный селектор и её субъект не класс); иначе пусто без обращения к базе.
func (m *ancestorMemo) forBinding(bs BindingScope) ([]domain.MirrorObject, error) {
	if !hasNestedSelector(bs) {
		return nil, nil
	}
	if !m.done {
		m.out, m.err = m.load()
		m.done = true
	}
	return m.out, m.err
}
