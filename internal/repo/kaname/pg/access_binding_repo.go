// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// access_binding_repo.go — pgxpool-реализация access_binding.ReaderIface / WriterIface;
// автомат жизненного цикла по access_bindings.status (PENDING → ACTIVE → REVOKED).
//
// Строгая вставка:
//
//   `INSERT INTO kaname.access_bindings (...)`
//   `VALUES ($newID, $st, $sid, $rid, $rt, $rid2, $status, $cond, $exp, $grb, $rva, $rvb, now())`
//   `RETURNING id, ..., created_at;`
//
// На дубле (subject_id, subject_type, role_id, resource_type, resource_id)
// с revoked_at IS NULL — partial UNIQUE access_bindings_active_grant_uniq
// (migration 0003) поднимает 23505 → mapErr → ErrAlreadyExists с verbatim
// «`these permissions are already granted to <subject_id> on <res_type>:<res_id>`».
// Прежний `ON CONFLICT DO UPDATE SET id = access_bindings.id` (silent
// idempotent-upsert) удален — он маскировал реальный duplicate-grant и
// засорял audit-чейн.
//
// Полное покрытие столбцов (12):
//   id, subject_type, subject_id, role_id, resource_type, resource_id,
//   status (PENDING|ACTIVE|REVOKED — по умолчанию 'ACTIVE'),
//   expires_at (срок, может отсутствовать), granted_by_user_id (аудит),
//   revoked_at (может отсутствовать), revoked_by_user_id (может отсутствовать), created_at.
//
// Автомат: PENDING → ACTIVE → REVOKED (конечное).
// TransitionStatus(...) — одним оператором CAS UPDATE WHERE status IN (ожидаемые);
// 0 строк из RETURNING → ErrFailedPrecondition (без TOCTOU: ссылки внутри службы
// держит база).
//
// Ссылки внутри службы — инварианты уровня базы:
//   - UNIQUE access_bindings_active_grant_uniq (пятёрка при revoked_at IS NULL)
//     → 23505 → ErrAlreadyExists (дословный текст по кодировке idHint).
//   - FK access_bindings_role_fk → SQLSTATE 23503 → ErrFailedPrecondition.
//   - CHECK access_bindings_status_ck — SQLSTATE 23514 → ErrInvalidArg.
//   - CHECK access_bindings_revoked_consistency_ck — то же.
//   - subject_id/resource_id — мягкая ссылка (нет FK; полиморфная и между базами).

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

type abReader struct {
	tx pgx.Tx
}

// abCols — столбцы access_bindings (RBAC v2 + область + deletion_protection + цель
// F8). Порядок SELECT и RETURNING совпадает ПОСТРОЕНИЕМ: оба места
// интерполируют эту константу, и разойтись им нечем. `target_digest` только
// пишется (ключ индекса, вычисляется во Insert) и НЕ читается, поэтому его здесь
// нет намеренно.
//
// Здесь стоял поимённый перечень глаголов, несущих RETURNING. Он разошёлся с
// деревом в ОБЕ стороны: называл `DeleteGuarded`, который эту проекцию не
// возвращает, и молчал о `RevokeGuarded` и `UpdateLabels`, которые возвращают.
// Рукописный перечень рядом с тем, что и так держится построением, гарантии не
// добавляет — он добавляет второе место, стареющее молча (kacho#1951).
//
// `role_id` читается через COALESCE: у ФОРМЫ ОТНОШЕНИЯ (системная выдача) роли
// нет, и колонка допускает NULL. Пустая строка здесь — не подмена значения, а его
// отсутствие в том же виде, в каком отсутствие выражено во всём домене: форму
// выдачи различает пара (role_id, granted_relation), и ровно одна из них непуста.
const abCols = "id, subject_type, subject_id, COALESCE(role_id, '') AS role_id, resource_type, resource_id, " +
	"status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, created_at, scope, " +
	"deletion_protection, labels, target, granted_relation, is_system, COALESCE(revocation_reason, '') AS revocation_reason, " +
	"COALESCE(delegation_id, '') AS delegation_id"

func (r *abReader) Get(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings WHERE id = $1`, abCols), string(id))
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// GetForNoKeyUpdate — Get с замком строки выдачи `FOR NO KEY UPDATE`.
// Реконсайлер γ зовёт его ПЕРВЫМ оператором своей ПОЛНОЙ пишущей транзакции
// (LoadBinding), и два одновременных полных прохода ОДНОЙ выдачи выстраиваются на
// замке строки: второй ждёт, пока первый зафиксирует разницу членства, затем
// перечитывает CurrentMembers, видит уже ACTIVE-члена (статус не меняется ⇒
// идемпотентный пропуск) и не выпускает НИ ОДНОГО повторного кортежа fga_outbox.
// Это критическая секция на замке родительской строки. Строки нет ⇒ ErrNotFound
// (выдачу удалили — реконсайлер тогда ничего не делает).
//
// ПОЧЕМУ `FOR NO KEY UPDATE`, А НЕ `FOR UPDATE` — И ЧТО ЭТО НЕ ОСЛАБЛЯЕТ.
//
// Взаимное исключение полных проходов сохраняется дословно: `FOR NO KEY UPDATE`
// конфликтует и с `FOR UPDATE`, и сам с собой, и с обычным UPDATE строки, — то есть
// со всем, что меняет биндинг (истечение срока, отзыв, удаление). Ключ строки
// (id) реконсайлер не меняет НИКОГДА, поэтому более сильный режим здесь ничего не
// охранял.
//
// А охранял он лишнее — и это измерено. `FOR UPDATE` — единственный режим, который
// конфликтует с `FOR KEY SHARE`, а именно `FOR KEY SHARE` берёт на этой же строке
// КАЖДАЯ вставка в дочерние таблицы по внешнему ключу (access_binding_target_members
// / access_binding_emitted_tuples). Из-за этого аддитивный форвард пути СОЗДАНИЯ — тот,
// ради которого свежий ресурс виден создателю сразу, — не мог писать, пока фоновый
// полный проход держит строку, и вынужден был брать SHARE-advisory, чтобы не словить
// перекрёстное ожидание (40P01). То есть окно видимости своего свежего ресурса
// определялось не работой форварда, а сроком чужой транзакции.
//
// Замер (тёплый 12-ядерный стенд, волна vpc+compute+nlb, выборка pg_stat_activity
// раз в 5 с): 99 наблюдений бэкенда в ожидании `pg_advisory_xact_lock_shared` —
// это и есть форвард — со средним 0.88 с и максимумом 4.6 с. На ранере вчетверо
// меньшей мощности те же ожидания растягиваются за клиентский бюджет
// чтения-своих-записей, и создатель получает отказ на СВОЙ ресурс.
//
// Сняв конфликт в его корне, форвард перестаёт брать advisory-блокировку вовсе
// (reconcile/forward.go). Свойство держит проба
// TestReconcileForward_07_DoesNotQueueBehindInFlightFullPass: она держит полный
// проход в полёте ЕГО ЖЕ первыми стейтментами и требует, чтобы форвард прошёл, — с
// парным положительным контролем, что тот же форвард без держателя материализует
// объект (иначе «не ждёт» зеленело бы на проходе, который ничего не делает).
func (r *abReader) GetForNoKeyUpdate(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	// ПОРЯДОК ЗАХВАТА (kaname#922): после advisory-замка этой выдачи (полный
	// проход, проход по объекту — в порядке id веера, истечение). Перепись —
	// docs/changes/kn-922/lock-order-census.md.
	return r.getLocked(ctx, id, lockNoKeyUpdate)
}

// GetForKeyShare — строка выдачи под `FOR KEY SHARE` до конца транзакции: чтение
// аддитивного форварда (reconcile LoadBindingForForward, kaname#919). Режим совместим
// с `FOR NO KEY UPDATE` полного прохода и с `FOR KEY SHARE` дочерних вставок, а
// конфликтует ТОЛЬКО с `FOR UPDATE` — замком снятия выдачи: истечения срока, отзыва и
// удаления (getForUpdate, kaname#923) и отзыва по снятию регистрации
// (`UnregisteredKeyStore.ActiveBindingsNamingKey`, kaname#963, F1). Форвард поэтому
// не встаёт в очередь за фоновой работой, а решение «выдача жива» верно до его
// коммита: либо снятие ждёт фиксации форварда и снимает записанное по реестру, либо
// форвард ждёт фиксации снятия и читает строку уже отозванной. Строки нет ⇒
// ErrNotFound.
func (r *abReader) GetForKeyShare(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	// ПОРЯДОК ЗАХВАТА (kaname#922): форвард по выдаче берёт строку первой и без
	// advisory; FOR KEY SHARE совместим с FOR NO KEY UPDATE полного прохода и ждёт
	// лишь FOR UPDATE снятий.
	return r.getLocked(ctx, id, lockKeyShare)
}

// rowLock — режим строчного замка чтения выдачи. Закрытый набор постоянных: текст
// вставляется в оператор, поэтому значения извне сюда не попадают.
type rowLock string

const (
	lockNoKeyUpdate rowLock = "FOR NO KEY UPDATE"
	lockKeyShare    rowLock = "FOR KEY SHARE"
)

func (r *abReader) getLocked(ctx context.Context, id domain.AccessBindingID, lock rowLock) (domain.AccessBinding, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings WHERE id = $1 %s`, abCols, lock), string(id))
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// getForUpdate — Get с замком строки выдачи `FOR UPDATE`: замок СНЯТИЯ выдачи.
// Единственный дом этого чтения — его берут и отзыв с удалением
// (abWriter.GetForDeactivation), и истечение срока
// (reconcileStore.LockBindingForDeactivation). Строки нет ⇒ ErrNotFound.
func (r *abReader) getForUpdate(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	// ПОРЯДОК ЗАХВАТА (kaname#922): у всех снятий (отзыв, удаление, истечение, снос
	// области) — после advisory-замка этой выдачи и до чтения ведомости. Перепись —
	// docs/changes/kn-922/lock-order-census.md.
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings WHERE id = $1 FOR UPDATE`, abCols), string(id))
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// GetForDeactivation — строка выдачи под замком снятия `FOR UPDATE` (контракт —
// у порта WriterIface): отзыв и удаление ждут коммита аддитивного форварда,
// решившего «выдача жива», и читают реестр уже с его записями (kaname#923).
func (w *abWriter) GetForDeactivation(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	return w.getForUpdate(ctx, id)
}

// accountScopePredicate — «привязка лежит в области ЭТОГО аккаунта»: либо
// привязана к самому аккаунту, либо к любому его проекту. Один placeholder,
// названный дважды: аккаунт и его проекты сверяются с одним и тем же значением.
//
// ОДНО написание на двух вызывающих — `List` (поле AccountID, kacho#1737) и
// `ListByAccount`. Прежде их было два, и приёмка требует от них ОДИНАКОВОГО
// охвата; держать это требование на двух написаниях значило бы завести два
// ответа на вопрос «чья это привязка», которые разойдутся молча. Третье место
// того же написания — подзапрос набора в bindingHasSubjectTypeInAccount
// (kaname#888): там неквалифицированные resource_type/resource_id разрешаются в
// столбцы области строки access_binding_subjects, и вопрос «в области ли этого
// аккаунта» задаётся набору тем же текстом, что и выдаче.
//
// Третье написание в этом файле — `membershipHoldingBindingsPredicate` (kacho#1686) —
// сюда НЕ сводится: копия там объявлена копией НАМЕРЕННО, чтобы правка одной
// стороны заставляла открыть вторую, и у неё свой предмет (отказ исключения).
//
// Within-service refs (ban #10): подзапрос читает FK-проверенную таблицу
// projects — ни кросс-сервисного вызова, ни TOCTOU.
func accountScopePredicate(argPos int) string {
	return fmt.Sprintf(
		`((resource_type = 'account' AND resource_id = $%[1]d)
		   OR (resource_type = 'project'
		       AND resource_id IN (SELECT id FROM projects WHERE account_id = $%[1]d)))`,
		argPos)
}

// bindingNamesSubject — предикат «выдача `ab` называет субъекта ($typePos,
// $idPos)», где бы он в выдаче ни стоял (kaname#888, остаток класса
// kaname#880).
//
// У выдачи ДВЕ проекции субъектов: одиночная пара строки `access_bindings`
// (subject_type, subject_id) — это её ПЕРВЫЙ субъект — и набор
// `access_binding_subjects`, где назван КАЖДЫЙ. Чтение по одной паре видит
// только первого: второму выдача не показана, хотя права по ней у него есть.
// Пара — одна из строк набора у КАЖДОЙ выдачи, и держит это база:
// отложенная до коммита проверка `access_bindings_carry_a_subject` судит
// вставку выдачи, смену пары, снятие и смену строки набора (kaname#902,
// kaname#907), а лежащих выдач с парой вне набора нет — накат миграции
// kaname#907 их пересчитывает и отказывает на ненулевом числе. Ветвь пары
// поэтому по смыслу избыточна: всякую выдачу, которую она находит, находит и
// ветвь набора. Снять её — правка формы чтения, которую судит план запроса,
// а не этот инвариант; здесь она не делается.
//
// Форма — `id = ANY (ARRAY(подзапрос))`, а не `EXISTS` и не `IN`: подзапрос
// без ссылок наружу исполняется ОДИН раз (InitPlan) по индексу
// `access_binding_subjects_subject_scope_idx`, и обе ветви дизъюнкции остаются
// индексными — `access_bindings_subject_idx` для пары и первичный ключ для
// набора, — поэтому чтение, которое субъект и ведёт, не сползает в обход
// таблицы выдач. `EXISTS` под `OR` не поднимается в полусоединение и
// исполнялся бы на каждой строке-кандидате.
func bindingNamesSubject(ab string, typePos, idPos int) string {
	return fmt.Sprintf(
		`((%[1]s.subject_type = $%[2]d AND %[1]s.subject_id = $%[3]d)
		   OR %[1]s.id = ANY (ARRAY(SELECT s.binding_id FROM access_binding_subjects s
		                             WHERE s.subject_type = $%[2]d AND s.subject_id = $%[3]d)))`,
		ab, typePos, idPos)
}

// bindingNamesSubjectID — тот же вопрос, что у bindingNamesSubject, но по одному
// идентификатору субъекта без вида (фильтр `subject` у List): выдача называет
// субъекта $pos в паре или в наборе.
//
// Вид вопросу не известен, а оба индекса субъекта ведутся видом
// (`access_bindings_subject_idx` и `access_binding_subjects_subject_scope_idx`
// — subject_type, subject_id). Голое `subject_id = $pos` ведущего столбца не
// называет, и подзапрос набора читал access_binding_subjects целиком —
// субъектов всех арендаторов на каждый запрос (kaname#888: 40010 строк, 5 мс
// из 6 на 20000 выдачах). Поэтому вид назван закрытым словарём
// bindingSubjectKindsSQL: `subject_type = ANY (словарь) AND subject_id = $pos`
// — индексное условие по обоим столбцам, по одному спуску на вид. Словарь
// сверен со схемой пробой (TestSubjectFilterPlan): новый вид в ограничении
// без него в словаре — красное, а не молча выпавшие выдачи.
//
// Форма набора — та же `id = ANY (ARRAY(подзапрос))`: с `EXISTS` планировщик
// исполнял набор хэшированным подпланом и обходил всю таблицу выдач по курсору.
func bindingNamesSubjectID(pos int) string {
	return fmt.Sprintf(
		`((subject_type = ANY (%[2]s) AND subject_id = $%[1]d)
		   OR id = ANY (ARRAY(SELECT s.binding_id FROM access_binding_subjects s
		                       WHERE s.subject_type = ANY (%[2]s) AND s.subject_id = $%[1]d)))`,
		pos, bindingSubjectKindsSQL())
}

// bindingSubjectKinds — закрытый словарь вида субъекта выдачи: тот же набор,
// что держат ограничения `access_bindings_subject_ck` и
// `access_binding_subjects_type_ck`. Нужен чтению, не знающему вида
// (bindingNamesSubjectID), чтобы назвать ведущий столбец индекса субъекта.
var bindingSubjectKinds = []domain.SubjectType{
	domain.SubjectTypeUser,
	domain.SubjectTypeServiceAccount,
	domain.SubjectTypeGroup,
	domain.SubjectTypeSystemClass,
}

// bindingSubjectKindsSQL — словарь литералом массива. Значения — константы
// домена без кавычек внутри, вход вызывающего сюда не попадает.
func bindingSubjectKindsSQL() string {
	quoted := make([]string, len(bindingSubjectKinds))
	for i, k := range bindingSubjectKinds {
		quoted[i] = "'" + string(k) + "'"
	}
	return "ARRAY[" + strings.Join(quoted, ", ") + "]::text[]"
}

// bindingHasSubjectTypeInAccount — выдача несёт субъекта вида $typePos в паре
// или в наборе (фильтр вида у ListByAccount); $accountPos — аккаунт области.
//
// Набор спрашивается той же формой `id = ANY (ARRAY(подзапрос))`, а подзапрос
// сужен той же областью аккаунта, что и само чтение (accountScopePredicate по
// столбцам области строки набора — их держит триггер набора), поэтому массив не
// шире выдач этого аккаунта. Замер kaname#888 (EXPLAIN ANALYZE, 20000 выдач в
// одном аккаунте, у каждой два субъекта-человека):
//
//	фильтр         прежняя пара   EXISTS под OR   эта форма
//	group (редкий)   0,06 мс        5,6 мс          0,17 мс (BitmapOr по индексам)
//	user (частый)    0,09 мс       12,1 мс          9,7 мс
//
// Цена названа: подзапрос строит массив ВСЕХ выдач аккаунта с субъектом этого
// вида, и для частого вида он линеен по числу выдач аккаунта, хотя странице
// нужно 50 строк. Граница этой цены — один аккаунт: подзапрос сужен его
// областью, и выдачи других арендаторов в массив не входят, сколько бы их ни
// было. Прежняя пара была дешевле и неверна.
func bindingHasSubjectTypeInAccount(typePos, accountPos int) string {
	return fmt.Sprintf(
		`(subject_type = $%[1]d
		   OR id = ANY (ARRAY(SELECT s.binding_id FROM access_binding_subjects s
		                       WHERE s.subject_type = $%[1]d AND %[2]s)))`,
		typePos, accountScopePredicate(accountPos))
}

// List — единое чтение (redesign-2026 F11). Собирает WHERE из тех
// необязательных предикатов, что несёт фильтр (субъект/роль/вид области/область),
// и листает ключом (created_at, id) ASC. ВИДИМОСТЬ здесь НЕ предикат — сценарий
// применяет её к каждому объекту отданной страницы (internal/authzfilter);
// прежнее проталкивание видимых id из движка прав упиралось в его потолок 1000
// объектов и молча прятало собственные выдачи арендатора. Разбор page_token —
// окончательный рубеж формата (мусор → InvalidArgument), независимый от
// предпроверки обработчика.
//
// IncludeRevoked по умолчанию ЛОЖЬ: мягкий отзыв F10 ОСТАВЛЯЕТ строку со
// status='REVOKED', и без предиката отозванная выдача стояла бы в перечне рядом с
// живыми, — а так как частичная UNIQUE действующей выдачи ключуется по
// revoked_at, повторная такая же выдача даёт ВТОРУЮ строку, то есть одна выдача
// показана дважды. Согласно с ListByAccount / ListByRole, где они скрыты по
// умолчанию.
func (r *abReader) List(ctx context.Context, f access_binding.ListFilter) ([]domain.AccessBinding, string, error) {
	// page_size вне [0..maxListPageSize] ОТВЕРГАЕТСЯ, а не усекается: усечение
	// отвечает 200 OK страницей короче запрошенной, и ничто в ответе не отличает
	// её от полного ответа.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	conditions := []string{}
	args := []any{}
	argIdx := 1
	addEq := func(col, val string) {
		conditions = append(conditions, fmt.Sprintf("%s = $%d", col, argIdx))
		args = append(args, val)
		argIdx++
	}
	// Субъект — любой из субъектов выдачи, а не только первый (kaname#888).
	if f.SubjectID != "" {
		conditions = append(conditions, bindingNamesSubjectID(argIdx))
		args = append(args, f.SubjectID)
		argIdx++
	}
	if f.RoleID != "" {
		addEq("role_id", f.RoleID)
	}
	if f.ScopeType != "" {
		addEq("resource_type", f.ScopeType)
	}
	if f.ScopeID != "" {
		addEq("resource_id", f.ScopeID)
	}
	// Сужение до области ОДНОГО аккаунта (kacho#1737): сам аккаунт плюс каждый его
	// проект. Тот же предикат, что у ListByAccount, — одно написание на оба
	// глагола, поэтому «одинаковый охват» есть свойство кода, а не совпадение.
	//
	// Стоит ОТДЕЛЬНО от сужения кандидатов ниже и от него не зависит: у
	// администратора облака и у держателя cluster-scoped выдачи Candidates равен
	// nil, и предикат, спрятанный внутрь того блока, для них не исполнился бы
	// вовсе — ответ остался бы на вид исправным и шире запрошенного.
	if f.AccountID != "" {
		conditions = append(conditions, accountScopePredicate(argIdx))
		args = append(args, f.AccountID)
		argIdx++
	}
	// Предикат без параметра (как у ListByAccount/ListByRole) — его добавление не
	// сдвигает argIdx.
	if !f.IncludeRevoked {
		conditions = append(conditions, "status <> 'REVOKED'")
	}
	// Курсор. Разобранный (After) имеет приоритет: путь, который его задаёт,
	// токена не передаёт вовсе, поэтому «оба заданы» здесь не встречается — но
	// порядок назван явно, чтобы это было свойством кода, а не совпадением.
	switch {
	case f.After != nil:
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, f.After.CreatedAt, f.After.ID)
		argIdx += 2
	case f.PageToken != "":
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	// Сужение набора КАНДИДАТОВ (задача kacho#645). Оно стоит здесь, в отборе строк, а
	// не после него: постфильтр по видимости теряет всякую привязку, перед которой
	// лежит больше `page_size` невидимых предшественников — она до фильтра просто
	// не доезжает.
	//
	// Аккаунт привязки не колонка, а вывод из её области, и выражение ниже —
	// то же самое, которым пользуется ListByAccount (`resource_type='account'`
	// прямо, `resource_type='project'` через проект), обобщённое с одного аккаунта
	// на набор. Держать его в двух написаниях значило бы завести два ответа на
	// вопрос «чья это привязка», которые разойдутся молча.
	//
	// nil — не сужать (администратор облака); непустой указатель с пустыми
	// наборами не называет ни одной строки и потому не пропускает ни одной.
	if f.Candidates != nil {
		conditions = append(conditions, fmt.Sprintf(
			`(id = ANY($%[2]d)
			   OR (resource_type = 'account' AND resource_id = ANY($%[1]d))
			   OR (resource_type = 'project'
			       AND resource_id IN (SELECT id FROM projects WHERE account_id = ANY($%[1]d))))`,
			argIdx, argIdx+1))
		args = append(args, nonNilStrings(f.Candidates.AccountIDs), nonNilStrings(f.Candidates.ObjectIDs))
		argIdx += 2
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	q := fmt.Sprintf(`SELECT %s FROM access_bindings %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		abCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.AccessBinding
	for rows.Next() {
		ab, serr := scanAB(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", "")
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

func (r *abReader) ListByScope(ctx context.Context, resourceType domain.ResourceType, resourceID string, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	return r.listWithConds(ctx, f,
		[]string{"resource_type = $%d", "resource_id = $%d"},
		[]any{string(resourceType), resourceID})
}

// ListBySubject — выдачи, называющие субъекта, где бы он в выдаче ни стоял
// (kaname#888): предикат bindingNamesSubject ссылается на оба параметра дважды,
// поэтому условие собрано здесь готовым, а не шаблоном listWithConds.
func (r *abReader) ListBySubject(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	return r.listWhere(ctx, f,
		[]string{bindingNamesSubject("access_bindings", 1, 2)},
		[]any{string(subjectType), string(subjectID)})
}

// ListByAccount — путь администратора: каждая выдача в области аккаунта:
//
//   - выдачи прямо на аккаунт (`resource_type='account'`
//     `AND resource_id = $accountID`); плюс
//   - выдачи на каждый проект, чей `account_id = $accountID`
//     (`resource_type='project' AND resource_id IN (SELECT id FROM projects`
//     `WHERE account_id = $accountID)`).
//
// Необязательный SubjectTypeFilter сужает до одного вида субъекта — любого из
// субъектов выдачи (kaname#888). IncludeRevoked=false (умолчание) скрывает
// строки status='REVOKED'.
//
// Порядок: (created_at DESC, id ASC) — новые выдачи первыми; равенство
// разрешает id ASC, чтобы курсор ключа был детерминирован.
//
// Формат курсора тот же, что у encodePageToken/decodePageToken (непрозрачный
// base64 (created_at, id)), но предикат — убывающий
// `(created_at, id) < ($prev_ts, $prev_id)`.
//
// Ссылки внутри службы (запрет #10): подзапрос читает проверенную внешним
// ключом таблицу projects — ни вызова в чужую базу, ни TOCTOU.
func (r *abReader) ListByAccount(ctx context.Context, accountID domain.AccountID, f access_binding.AccountPageFilter) ([]domain.AccessBinding, string, error) {
	// page_size вне [0..maxListPageSize] ОТВЕРГАЕТСЯ, а не усекается: усечение
	// отвечает 200 OK страницей короче запрошенной, и ничто в ответе не отличает
	// её от полного ответа.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	// $1 = accountID — упомянут дважды (прямо и через область проекта).
	args := []any{string(accountID)}
	argIdx := 2

	// Тот же предикат, что у `List` с полем AccountID (kacho#1737) — одно написание,
	// поэтому охват обоих глаголов совпадает by construction.
	conditions := []string{accountScopePredicate(1)}

	if !f.IncludeRevoked {
		conditions = append(conditions, `status <> 'REVOKED'`)
	}

	// Вид — любого из субъектов выдачи, а не только первого (kaname#888).
	if f.SubjectTypeFilter != "" {
		conditions = append(conditions, bindingHasSubjectTypeInAccount(argIdx, 1))
		args = append(args, f.SubjectTypeFilter)
		argIdx++
	}

	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		// Убывающий предикат ключа: (created_at, id) < (последний created_at,
		// последний id) при порядке created_at DESC + id ASC. id ASC разрешает
		// равенство: `(created_at < ts) OR (created_at = ts AND id > prev_id)`.
		conditions = append(conditions,
			fmt.Sprintf(`(created_at < $%d OR (created_at = $%d AND id > $%d))`,
				argIdx, argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	q := fmt.Sprintf(`SELECT %s FROM access_bindings WHERE %s
		ORDER BY created_at DESC, id ASC LIMIT $%d`,
		abCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.AccessBinding
	for rows.Next() {
		ab, err := scanAB(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}

	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// ListSubjectPrivileges — обогащённое чтение для вида «права субъекта».
// Отдаёт выдачи субъекта, соединённые LEFT JOIN с `roles`, чтобы читаемое имя
// роли разрешалось на сервере ОДНИМ запросом (`access_bindings ab ⋈ roles r ON
// ab.role_id = r.id`; та же схема kaname, внешний ключ access_bindings_role_fk —
// без N+1 по строкам).
//
// LEFT JOIN, а не INNER: висячая роль (удалённая после отзыва) не роняет строку —
// выдача отдаётся с role_name="".
//
// Отдаются только строки PENDING/ACTIVE (status <> 'REVOKED' — как у
// ListByAccount.include_revoked=false). Выдача принадлежит субъекту, когда
// называет его — либо группу, где он состоит, — В ЛЮБОМ месте своего набора
// субъектов, а не только первым (kaname#888).
//
// Порядок и курсор — как у ListBySubject: (created_at, id) ASC с непрозрачным
// base64 (created_at, id) в page_token; предикат (created_at, id) > (прежний).
// page_size: 0 → DefaultPageSize(50), потолок 1000.
//
// Ссылки внутри службы (запрет #10): JOIN читает проверенную внешним ключом
// таблицу `roles` — ни вызова в чужую базу, ни TOCTOU. Только чтение — пути CAS
// и гонки нет.
func (r *abReader) ListSubjectPrivileges(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f access_binding.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	// page_size вне [0..maxListPageSize] ОТВЕРГАЕТСЯ, а не усекается: усечение
	// отвечает 200 OK страницей короче запрошенной, и ничто в ответе не отличает
	// её от полного ответа.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	// Совпадение субъекта: ПРЯМОЕ (выдача называет самого субъекта) ИЛИ ЧЕРЕЗ
	// ГРУППУ (выдача называет группу, где субъект состоит) — каждое по ОБЕИМ
	// проекциям субъектов выдачи: одиночной паре строки (её ПЕРВЫЙ субъект) и
	// набору access_binding_subjects (КАЖДЫЙ субъект). Вопрос к одной паре прятал
	// выдачу от всех, кого она называла не первым (kaname#888).
	//
	// Каждая ветвь — равенство либо `= ANY(массив InitPlan)`: ветви пары ведёт
	// access_bindings_subject_idx, ветвь набора — первичный ключ по id, которые
	// набор отдаёт через access_binding_subjects_subject_scope_idx; план замерен
	// EXPLAIN в kaname#888.
	//
	// Групповая сторона читает kaname.group_members через group_members_member_idx.
	// Группы НЕ вкладываются (group_members_type_check допускает только user /
	// service_account), поэтому шаг ровно ОДИН и рекурсии нет: когда ЗАПРОШЕННЫЙ
	// субъект сам группа, набор несущих групп пуст и действует только ПРЯМАЯ ветвь.
	const carrierGroups = `ARRAY(SELECT gm.group_id FROM group_members gm
		                         WHERE gm.member_type = $1 AND gm.member_id = $2)`
	direct := bindingNamesSubject("ab", 1, 2)
	conditions := []string{
		`(   ` + direct + `
		  OR (ab.subject_type = 'group' AND ab.subject_id = ANY (` + carrierGroups + `))
		  OR ab.id = ANY (ARRAY(SELECT s.binding_id FROM access_binding_subjects s
		                         WHERE s.subject_type = 'group'
		                           AND s.subject_id = ANY (` + carrierGroups + `))) )`,
		"ab.status <> 'REVOKED'",
	}
	args := []any{string(subjectType), string(subjectID)}
	argIdx := 3

	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions,
			fmt.Sprintf("(ab.created_at, ab.id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	// COALESCE(r.name, ''): промах LEFT JOIN (висячая роль) читается как "" —
	// приёмник в Go — простая строка, NULL ему не годится.
	//
	// COALESCE(ab.role_id, '') — по той же причине, что в abCols: у ФОРМЫ
	// ОТНОШЕНИЯ (системная выдача, access_bindings_grant_form_ck) роли нет и
	// колонка NULL. Голый ab.role_id ронял перечень ЦЕЛИКОМ на первой такой
	// строке («cannot scan NULL into *string»), а наружу это уходило внутренней
	// ошибкой. Пустая строка — отсутствие роли в том виде, в каком его выражает
	// весь домен; для такой строки LEFT JOIN не находит роли, и role_name тоже "".
	//
	// Два последних столбца объясняют строку: `is_direct` истинен, когда выдача
	// называет самого субъекта (в любой проекции); иначе субъект дошёл до неё через
	// группу, названную в `via_group_id`. Выдача, которая и прямая, и групповая,
	// считается ПРЯМОЙ (более сильное, самоочевидное объяснение) и даёт ОДНУ
	// строку: предикат — дизъюнкция над той же строкой, а не соединение, поэтому
	// на выдачу приходится одна строка и курсор (created_at, id) остаётся верным.
	//
	// `via_group_id` называет группу, где субъект СОСТОИТ, — первую такую в порядке
	// субъектов выдачи (пара — порядковый 0). Назвать первого субъекта выдачи лишь
	// потому, что он группа, значило бы отправить администратора снимать членство,
	// которого у субъекта нет, когда несущая группа стоит второй.
	q := fmt.Sprintf(`
		SELECT ab.id, COALESCE(ab.role_id, ''), COALESCE(r.name, ''),
		       ab.resource_type, ab.resource_id, ab.scope, ab.status,
		       ab.created_at, ab.granted_by_user_id, ab.expires_at,
		       %[1]s AS is_direct,
		       CASE WHEN %[1]s THEN ''
		            ELSE COALESCE(
		                   CASE WHEN ab.subject_type = 'group' AND ab.subject_id = ANY (%[2]s)
		                        THEN ab.subject_id END,
		                   (SELECT s.subject_id FROM access_binding_subjects s
		                     WHERE s.binding_id = ab.id AND s.subject_type = 'group'
		                       AND s.subject_id = ANY (%[2]s)
		                     ORDER BY s.ordinal ASC, s.subject_id ASC
		                     LIMIT 1),
		                   '') END AS via_group_id
		  FROM access_bindings ab
		  LEFT JOIN roles r ON ab.role_id = r.id
		 WHERE %[3]s
		 ORDER BY ab.created_at ASC, ab.id ASC
		 LIMIT $%[4]d`, direct, carrierGroups, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.SubjectPrivilege
	for rows.Next() {
		sp, serr := scanSubjectPrivilege(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", "")
		}
		out = append(out, sp)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}

	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.BindingID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// scanSubjectPrivilege — переводит строку ListSubjectPrivileges в обогащённую
// проекцию домена. role_id и role_name уже сведены COALESCE к "" (у формы
// отношения роли нет, и LEFT JOIN её не находит). Границы scope проверяются так
// же, как в scanAB. Замыкающие столбцы is_direct/via_group_id несут объяснение
// происхождения (ПРЯМАЯ либо ЧЕРЕЗ ГРУППУ — см. комментарий у запроса).
func scanSubjectPrivilege(row scanner) (domain.SubjectPrivilege, error) {
	var (
		sp         domain.SubjectPrivilege
		expiresAt  sql.NullTime
		scopeI     int16
		isDirect   bool
		viaGroupID string
	)
	err := row.Scan(
		(*string)(&sp.BindingID),
		(*string)(&sp.RoleID),
		(*string)(&sp.RoleName),
		(*string)(&sp.ResourceType),
		&sp.ResourceID,
		&scopeI,
		(*string)(&sp.Status),
		&sp.CreatedAt,
		(*string)(&sp.GrantedByUserID),
		&expiresAt,
		&isDirect,
		&viaGroupID,
	)
	if err != nil {
		return domain.SubjectPrivilege{}, err
	}
	if !isDirect {
		sp.Derivation = domain.DerivationGroup
		sp.ViaGroupID = domain.GroupID(viaGroupID)
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		sp.ExpiresAt = &t
	}
	if scopeI < 0 || scopeI > 3 {
		sp.Scope = domain.ScopeUnspecified
	} else {
		sp.Scope = domain.Scope(scopeI)
	}
	return sp, nil
}

// listWithConds — общий path-builder для ListByScope/ListBySubject.
//
// ОГРАНИЧЕНИЕ НА ВЫЗЫВАЮЩИХ: `condTmpls` попадает в fmt.Sprintf как СТРОКА
// ФОРМАТА и уезжает в ТЕКСТ запроса. Значит каждый элемент обязан быть
// литералом кода вида `"<колонка> = $%d"` — ровно один глагол `%d` под номер
// плейсхолдера. Данные вызывающего идут ТОЛЬКО через `condArgs` (их связывает
// pgx), в шаблон — НИКОГДА.
//
// Сегодня это выполняется: метод неэкспортирован, вызывающих двое
// (ListByScope/ListBySubject), оба передают литеральные срезы. Но ни сигнатура,
// ни тип этого не держат — `[]string` примет что угодно, поэтому ограничение
// записано здесь. Вызывающий, собравший элемент из значения запроса, получит
// прямую SQL-инъекцию, и ни компилятор, ни сканер не возразят: правила
// инъекции (G201/G202) эту форму не матчат — приёмник pgx, Sprintf инлайном.
//
// Два смежных капкана той же строки: шаблон без `%d` молча вставит в SQL
// `%!(EXTRA int=…)`, а шаблон с `%s` съест номер плейсхолдера как текст.
func (r *abReader) listWithConds(ctx context.Context, f access_binding.PageFilter, condTmpls []string, condArgs []any) ([]domain.AccessBinding, string, error) {
	conditions := make([]string, 0, len(condTmpls))
	for i, tmpl := range condTmpls {
		conditions = append(conditions, fmt.Sprintf(tmpl, i+1))
	}
	return r.listWhere(ctx, f, conditions, condArgs)
}

// listWhere — страница выдач по готовым условиям: conditions уже ссылаются на
// $1..$len(args), курсор и предел страницы встают следующими номерами. Тот же
// запрет, что у listWithConds: в условие не попадает значение запроса, только
// номер параметра.
func (r *abReader) listWhere(ctx context.Context, f access_binding.PageFilter, conditions []string, condArgs []any) ([]domain.AccessBinding, string, error) {
	// page_size вне [0..maxListPageSize] ОТВЕРГАЕТСЯ, а не усекается: усечение
	// отвечает 200 OK страницей короче запрошенной, и ничто в ответе не отличает
	// её от полного ответа.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}
	conditions = append([]string(nil), conditions...)
	args := append([]any(nil), condArgs...)
	argIdx := len(args) + 1
	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	q := fmt.Sprintf(`SELECT %s FROM access_bindings WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		abCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.AccessBinding
	for rows.Next() {
		ab, err := scanAB(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

type abWriter struct {
	abReader
}

// Insert — strict create. На дубле (subject_type, subject_id, role_id,
// resource_type, resource_id) с revoked_at IS NULL — partial UNIQUE
// access_bindings_active_grant_uniq (миграция 0003) поднимает SQLSTATE 23505,
// который маппится в ErrAlreadyExists с verbatim text:
//
//	`these permissions are already granted to <subject_id> on <resource_type>:<resource_id>`
//
// Прежняя идемпотентность (ON CONFLICT DO UPDATE SET id = access_bindings.id)
// удалена: silent-upsert скрывал реальный duplicate-grant и заставлял ревьюера
// разбираться, почему один и тот же тапл создавался под разными id. Use-case
// больше не вызывает FindExisting для pre-resolution candidate-id; reseats
// strictly create-or-conflict.
//
// Записывает все 12 колонок. Пустой Status проходит как DB-default ACTIVE
// (через COALESCE(NULLIF($7, ”), 'ACTIVE')). Nullable поля (expires_at,
// revoked_at, revoked_by_user_id) передаются через
// nullableString/nullableTimePtr хелперы.
func (w *abWriter) Insert(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	now := time.Now().UTC()
	// Scope: явное значение, когда оно не Unspecified, иначе область выводит из
	// resource_type триггер access_bindings_scope_default_trg (миграция 0005).
	// SMALLINT NULL нарушил бы NOT NULL ПОСЛЕ триггера лишь тогда, когда триггер
	// оставил бы NEW.scope пустым, — а он не оставляет никогда (у него есть ветвь
	// ELSE).
	// labels — own-resource tenant-facing метки самого binding-ресурса,
	// делают AccessBinding label-selectable (catalog-видимость через viewer ∪ v_list).
	labelsJSON, err := marshalLabels(b.Labels)
	if err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	// F8: сохраняется выбор объектов (target) и его отпечаток по множеству.
	// Отпечаток — ключевой столбец частичной UNIQUE действующей выдачи (одинаковая
	// цель → столкновение, разные пообъектные цели сосуществуют). Пусто или весь
	// якорь → "all". Форма хранения одна — `relverdict.EncodeTarget`.
	targetJSON, err := relverdict.EncodeTarget(b.Target)
	if err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument target: %s", err.Error())
	}
	targetDigest := b.Target.Digest()
	if err := holdRegisteredKeys(ctx, w.tx, b.HeldTargets, func(ref domain.ResourceRef) error {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"target resource %s %s was unregistered before the access binding was written", ref.Type, ref.ID)
	}); err != nil {
		return domain.AccessBinding{}, err
	}
	q := fmt.Sprintf(`
		INSERT INTO access_bindings (
			id, subject_type, subject_id, role_id, resource_type, resource_id,
			status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, created_at, scope,
			deletion_protection, labels, target, target_digest, granted_relation, is_system,
			delegation_id
		)
		VALUES (
			$1, $2, $3,
			-- Роли может не быть: у формы отношения колонка NULL, и внешний ключ
			-- пропускает её by construction. Пустая строка вместо NULL уехала бы в
			-- ключ и дала бы отказ ссылочной целостности на несуществующую роль.
			NULLIF($4, ''), $5, $6,
			COALESCE(NULLIF($7, ''), 'ACTIVE'),
			$8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
			-- Ссылку на делегирование ставит только делегированный путь права
			-- выдавать (kaname#986); у выдачи держателя права колонка NULL.
			NULLIF($20, '')
		)
		RETURNING %s`, abCols)
	var scopeArg any
	if b.Scope == domain.ScopeUnspecified {
		scopeArg = nil
	} else {
		scopeArg = int16(b.Scope)
	}
	row := w.tx.QueryRow(ctx, q,
		string(b.ID), string(b.SubjectType), string(b.SubjectID), string(b.RoleID),
		string(b.ResourceType), b.ResourceID,
		string(b.Status),
		nullableTimePtr(b.ExpiresAt),
		string(b.GrantedByUserID),
		nullableTimePtr(b.RevokedAt),
		nullableUserIDPtr(b.RevokedByUserID),
		now,
		scopeArg,
		b.DeletionProtection,
		labelsJSON,
		targetJSON,
		targetDigest,
		b.GrantedRelation,
		b.System,
		string(b.DelegationID),
	)
	out, err := scanAB(row)
	if err != nil {
		// Подсказка несёт ТРИ слота: "<subject_id>|<resource_type>:<resource_id>|<role_id>".
		// Разбирает её splitBindingHint, и каждый потребитель берёт своё: текст UNIQUE —
		// субъекта и область, ветвь FK по роли — роль. Роль добавлена, потому что без неё
		// FK-ветвь печатала всю подсказку в слот роли и называла вызывающему сущности,
		// о которых он не спрашивал (issue kacho#105).
		idHint := fmt.Sprintf("%s|%s:%s|%s", b.SubjectID, b.ResourceType, b.ResourceID, b.RoleID)
		return domain.AccessBinding{}, mapErr(err, "", idHint)
	}
	return out, nil
}

// Delete — простой DELETE. 0 строк → NotFound. Его зовут пути, уже установившие,
// что выдачу можно удалить (reconcile/expire), и пробы; публичный сценарий Delete
// идёт через DeleteGuarded (P6, CAS по deletion_protection).
func (w *abWriter) Delete(ctx context.Context, id domain.AccessBindingID) error {
	// ПОРЯДОК ЗАХВАТА (kaname#922): у сноса области строка уже взята FOR UPDATE
	// (GetForDeactivation) после advisory-замка этой выдачи, выдачи — по возрастанию id.
	tag, err := w.tx.Exec(ctx, `DELETE FROM access_bindings WHERE id = $1`, string(id))
	if err != nil {
		return mapErr(err, "AccessBinding.Delete", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
	}
	return nil
}

// DeleteGuarded — атомарный CAS-delete (по образцу vpc.address.DeleteGuarded). Single-statement
// `DELETE … WHERE id=$1 AND deletion_protection=false` берет row-lock: конкурентный
// writer ждет commit, затем видит строку уже удаленной (его CAS → 0 строк →
// NotFound) ИЛИ строку с deletion_protection=true (его CAS → 0 строк →
// FailedPrecondition). Никакого software TOCTOU (ban #10). 0 строк → повторное
// чтение различает not-found / protected.
func (w *abWriter) DeleteGuarded(ctx context.Context, id domain.AccessBindingID) error {
	// ПОРЯДОК ЗАХВАТА (kaname#922): строка уже взята FOR UPDATE (GetForDeactivation)
	// после advisory-замка этой выдачи; оператор нового замка не добавляет.
	tag, err := w.tx.Exec(ctx,
		`DELETE FROM access_bindings WHERE id = $1 AND deletion_protection = false`, string(id))
	if err != nil {
		return mapErr(err, "AccessBinding.Delete", string(id))
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	// 0 строк: нет строки либо защищена — перечитываем в этой же транзакции.
	cur, gerr := w.Get(ctx, id)
	if gerr != nil {
		return gerr // ErrNotFound (или иная)
	}
	if cur.DeletionProtection {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before Delete", id)
	}
	// Строка есть, не защищена, а удалено 0 строк → гонку выиграло соседнее удаление.
	return iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}

// RevokeGuarded — атомарный CAS мягкого отзыва (redesign-2026 F10 IAM-1-28).
// Зеркало CAS защиты из DeleteGuarded и перехода в REVOKED из TransitionStatus, но
// строка ОСТАЁТСЯ: один оператор `UPDATE … SET status='REVOKED', revoked_at=now(),`
// `revoked_by_user_id=$2 WHERE id=$1 AND status='ACTIVE' AND deletion_protection=false`
// `RETURNING …` берёт замок строки, и при гонке выигрывает ровно один отзыв
// (проигравший ждёт фиксации, его `WHERE status='ACTIVE'` уже не совпадает → 0
// строк, запрет #10 — без программного TOCTOU). 0 строк → перечитывание в этой
// транзакции различает: нет строки → NotFound; защищена → FailedPrecondition; не
// ACTIVE (конечное REVOKED / PENDING либо выигравший соседний отзыв) →
// FailedPrecondition. revoked_at проставляется, чтобы частичная UNIQUE
// действующей выдачи (`WHERE revoked_at IS NULL`) освободила место повторной выдаче.
func (w *abWriter) RevokeGuarded(ctx context.Context, id domain.AccessBindingID, revokedBy domain.UserID) (domain.AccessBinding, error) {
	// ПОРЯДОК ЗАХВАТА (kaname#922): строка уже взята FOR UPDATE (GetForDeactivation)
	// после advisory-замка этой выдачи; оператор нового замка не добавляет.
	if revokedBy == "" {
		// CHECK access_bindings_revoked_consistency_ck требует, чтобы revoked_at
		// менялся вместе со status='REVOKED'; строка REVOKED без отозвавшего
		// недопустима.
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg,
			"revoked_by_user_id is required for REVOKED transition")
	}
	now := time.Now().UTC()
	row := w.tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE access_bindings
		   SET status             = 'REVOKED',
		       revoked_at         = $2,
		       revoked_by_user_id = $3,
		       revocation_reason  = 'REVOKE'
		 WHERE id = $1
		   AND status = 'ACTIVE'
		   AND deletion_protection = false
		RETURNING %s`, abCols), string(id), now, string(revokedBy))
	out, err := scanAB(row)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.RevokeGuarded", string(id))
	}
	// Обновлено 0 строк — перечитываем в этой транзакции, чтобы различить промах CAS.
	cur, gerr := w.Get(ctx, id)
	if gerr != nil {
		return domain.AccessBinding{}, gerr // ErrNotFound (либо временный сбой)
	}
	if cur.DeletionProtection {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before revoke", id)
	}
	// Не ACTIVE (уже REVOKED / PENDING либо замок строки выиграл соседний отзыв).
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
		"access binding %s is not active (status %s); cannot revoke", id, cur.Status)
}

// SetDeletionProtection — атомарный CAS UPDATE флага deletion_protection.
// Один оператор `UPDATE … WHERE id=$1 RETURNING …`; 0 строк → NotFound. Его зовёт
// путь `Update(update_mask=["deletion_protection"])`, снимающий флаг.
func (w *abWriter) SetDeletionProtection(ctx context.Context, id domain.AccessBindingID, protected bool) (domain.AccessBinding, error) {
	// ПОРЯДОК ЗАХВАТА (kaname#922): строка выдачи FOR NO KEY UPDATE — первым и
	// единственным строчным замком транзакции правки; advisory не берётся.
	row := w.tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE access_bindings
		   SET deletion_protection = $2
		 WHERE id = $1
		RETURNING %s`, abCols), string(id), protected)
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.SetDeletionProtection", string(id))
	}
	return out, nil
}

// UpdateLabels — атомарный одним оператором UPDATE собственных меток ресурса
// (изменяемый набор выдачи расширен до {deletion_protection, labels}).
// `UPDATE … SET labels=$2 WHERE id=$1 RETURNING …` берет row-lock: конкурентный
// writer ждет commit и видит обновленный row (last-writer-wins, не TOCTOU, ban #10).
// 0 rows RETURNING → NotFound. Identity/scope/subject поля не затрагиваются.
func (w *abWriter) UpdateLabels(ctx context.Context, id domain.AccessBindingID, labels domain.Labels) (domain.AccessBinding, error) {
	// ПОРЯДОК ЗАХВАТА (kaname#922): строка выдачи FOR NO KEY UPDATE — первым и
	// единственным строчным замком транзакции правки; advisory не берётся. Перепись —
	// docs/changes/kn-922/lock-order-census.md.
	labelsJSON, err := marshalLabels(labels)
	if err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	row := w.tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE access_bindings
		   SET labels = $2
		 WHERE id = $1
		RETURNING %s`, abCols), string(id), labelsJSON)
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.UpdateLabels", string(id))
	}
	return out, nil
}

// TransitionStatus — atomic CAS UPDATE для state machine (PENDING → ACTIVE → REVOKED).
// Single-statement `UPDATE … WHERE id=$1 AND status = ANY($expected) RETURNING …`;
// 0 rows из RETURNING → ErrFailedPrecondition (терминальный state или mismatch).
// SQLSTATE 23514 (CHECK violation для невалидного newState) → ErrInvalidArg.
//
// При transition в REVOKED обязательно передается revokedByUserID (CHECK
// access_bindings_revoked_consistency_ck). Для PENDING→ACTIVE / ACTIVE→ACTIVE
// revokedByUserID игнорируется (NULL в DB).
//
// Race-safety: row-level lock Postgres гарантирует one-winner на одну row;
// параллельный writer ждет commit-а первого и видит уже измененное значение.
func (w *abWriter) TransitionStatus(
	ctx context.Context,
	id domain.AccessBindingID,
	expected []domain.AccessBindingStatus,
	newStatus domain.AccessBindingStatus,
	revokedByUserID *domain.UserID,
) (domain.AccessBinding, error) {
	if err := newStatus.Validate(); err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if len(expected) == 0 {
		return domain.AccessBinding{},
			iamerr.Wrapf(iamerr.ErrInvalidArg, "expected statuses must not be empty")
	}
	expStrings := make([]string, len(expected))
	for i, s := range expected {
		expStrings[i] = string(s)
	}
	now := time.Now().UTC()
	var (
		revAtArg any
		revByArg any
	)
	if newStatus == domain.AccessBindingStatusRevoked {
		revAtArg = now
		if revokedByUserID == nil || *revokedByUserID == "" {
			return domain.AccessBinding{},
				iamerr.Wrapf(iamerr.ErrInvalidArg, "revoked_by_user_id is required for REVOKED transition")
		}
		revByArg = string(*revokedByUserID)
	} else {
		// PENDING / ACTIVE — revoked_at / revoked_by обязаны быть NULL (CHECK).
		revAtArg = nil
		revByArg = nil
	}
	q := fmt.Sprintf(`
		UPDATE access_bindings
		   SET status              = $2,
		       revoked_at          = $3,
		       revoked_by_user_id  = $4
		 WHERE id = $1
		   AND status = ANY($5)
		RETURNING %s`, abCols)
	row := w.tx.QueryRow(ctx, q,
		string(id), string(newStatus), revAtArg, revByArg, expStrings,
	)
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"AccessBinding %s cannot transition to %s (not in expected states %v)",
				id, newStatus, expected)
		}
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.TransitionStatus", string(id))
	}
	return out, nil
}

func scanAB(row scanner) (domain.AccessBinding, error) {
	return scanABWithVersion(row)
}

// scanABWithVersion — ЕДИНСТВЕННОЕ объявление порядка назначений под abCols.
// Когда передан versionOut (γ GetWithVersion), запрос ОБЯЗАН начинаться столбцом
// `xmin::text`, и метка пишется в *versionOut[0] — список приёмников Scan
// собирается со слотом версии первым, чтобы совпасть. Без versionOut это обычное
// чтение abCols: сюда делегирует `scanAB`, поэтому список один на Get /
// GetWithVersion / пути перечней.
//
// Прежняя редакция обещала «parity with the prior scanAB». Отдельного `scanAB`
// со своим списком уже нет — сверять стало не с чем, и утверждение о совпадении
// пережило свой предмет. Расходиться внутри пакета этому списку теперь нечем;
// остаточную ось «abCols против списка» держит проба арности
// TestProjectionScanArityMatchesItsColumns (kacho#1951).
func scanABWithVersion(row scanner, versionOut ...*string) (domain.AccessBinding, error) {
	var (
		ab           domain.AccessBinding
		expiresAt    sql.NullTime
		revokedAt    sql.NullTime
		revokedByUID sql.NullString
		scopeI       int16
		labelsJSON   []byte
		targetJSON   []byte
	)
	dest := make([]any, 0, 21)
	if len(versionOut) > 0 {
		dest = append(dest, versionOut[0])
	}
	dest = append(dest,
		(*string)(&ab.ID),
		(*string)(&ab.SubjectType),
		(*string)(&ab.SubjectID),
		(*string)(&ab.RoleID),
		(*string)(&ab.ResourceType),
		&ab.ResourceID,
		(*string)(&ab.Status),
		&expiresAt,
		(*string)(&ab.GrantedByUserID),
		&revokedAt,
		&revokedByUID,
		&ab.CreatedAt,
		&scopeI,
		&ab.DeletionProtection,
		&labelsJSON,
		&targetJSON,
		&ab.GrantedRelation,
		&ab.System,
		(*string)(&ab.RevocationReason),
		(*string)(&ab.DelegationID),
	)
	err := row.Scan(dest...)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	ab.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	ab.Target, err = relverdict.DecodeTarget(targetJSON)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		ab.ExpiresAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		ab.RevokedAt = &t
	}
	if revokedByUID.Valid {
		u := domain.UserID(revokedByUID.String)
		ab.RevokedByUserID = &u
	}
	// gosec G115 — проверка границ при переводе int16 → int8. Значения scope —
	// {0,1,2,3}, их стережёт CHECK access_bindings_scope_ck; любое иное — испорченная
	// строка, и она выходит наружу явным Unspecified, а не молча усекается.
	if scopeI < 0 || scopeI > 3 {
		ab.Scope = domain.ScopeUnspecified
	} else {
		ab.Scope = domain.Scope(scopeI)
	}
	return ab, nil
}

// EmitSubjectChangeEvent — пишет и унаследованные денормализованные столбцы, И
// канонические event_type + payload jsonb одной вставкой. Вставка одной строки
// атомарна по построению; вместе с объемлющей пишущей транзакцией строка журнала
// фиксируется тогда и только тогда, когда фиксируется окружающая мутация домена
// (ссылки внутри службы держит база).
//
// payload ОБЯЗАТЕЛЕН по контракту SELECT дренажа corelib — Decoder[T] получает
// ТОЛЬКО байты payload, а не прочие столбцы строки.
func (w *abWriter) EmitSubjectChangeEvent(ctx context.Context, evt access_binding.SubjectChangeEvent) error {
	if evt.SubjectID == "" {
		return fmt.Errorf("emit subject_change_outbox: subject_id required")
	}
	if evt.EventType == "" {
		evt.EventType = deriveEventTypeFromOp(evt.Op)
	}
	if evt.Op == "" {
		evt.Op = deriveOpFromEventType(evt.EventType)
	}

	// Величины предмета (`resource_type`/`resource_id`) в нагрузку не идут — ни
	// колонкой, ни близнецом внутри неё: читателя у них не было ни одного, а
	// платила за них каждая мутация выдачи (kacho#1462).
	payload, err := json.Marshal(struct {
		SubjectID   string `json:"subject_id"`
		SubjectType string `json:"subject_type,omitempty"`
		Op          string `json:"op"`
		EventType   string `json:"event_type"`
	}{
		SubjectID:   evt.SubjectID,
		SubjectType: evt.SubjectType,
		Op:          evt.Op,
		EventType:   evt.EventType,
	})
	if err != nil {
		return fmt.Errorf("emit subject_change_outbox: marshal payload: %w", err)
	}

	_, err = w.tx.Exec(ctx, `
		INSERT INTO kaname.subject_change_outbox
			(subject_id, op, event_type, payload)
		VALUES ($1, $2, $3, $4::jsonb)`,
		evt.SubjectID, evt.Op, evt.EventType, payload)
	if err != nil {
		return fmt.Errorf("emit subject_change_outbox: %w", err)
	}
	return nil
}

// EmitRelationWrite — атомарно добавляет N строк выдачи в kaname.fga_outbox
// (event_type='fga.tuple.write') в текущей пишущей транзакции (атомарность
// обязательна — см. ссылки внутри службы). Триггер на этой вставке сворачивает
// каждую строку в прямой факт в той же фиксации.
//
// Вставка выдачи и постановка в журнал фиксируются либо откатываются вместе —
// записи после фиксации, способной разойтись с базой при сбое, нет.
func (w *abWriter) EmitRelationWrite(ctx context.Context, tuples []access_binding.RelationTuple) error {
	return w.emitFGAOutbox(ctx, "fga.tuple.write", tuples)
}

// EmitRelationDelete — зеркало EmitRelationWrite для отзыва. Вызывающий передаёт
// ТОЧНО те кортежи, что когда-то записал EmitRelationWrite (симметричный отзыв).
func (w *abWriter) EmitRelationDelete(ctx context.Context, tuples []access_binding.RelationTuple) error {
	return w.emitFGAOutbox(ctx, "fga.tuple.delete", tuples)
}

// EmitRelationJournal — выдачи и снятия транзакции одним оператором журнала
// (kaname#617). Отказ базы переводится тем же переводчиком, что у emitFGAOutbox:
// 40P01 на этом операторе — признак конфликта, а не `internal error`.
func (w *abWriter) EmitRelationJournal(ctx context.Context, writes, deletes []access_binding.RelationTuple) error {
	ws, err := relationTuplesToClients(writes)
	if err != nil {
		return err
	}
	ds, err := relationTuplesToClients(deletes)
	if err != nil {
		return err
	}
	return mapErr(fga_outbox.EmitJournalTx(ctx, w.tx, ws, ds), "", "")
}

// relationTuplesToClients — кортежи реестра в форме выпускателя журнала;
// неполный кортеж — отказ, как у emitFGAOutbox.
func relationTuplesToClients(tuples []access_binding.RelationTuple) ([]clients.RelationTuple, error) {
	out := make([]clients.RelationTuple, 0, len(tuples))
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return nil, fmt.Errorf("emit fga_outbox: incomplete tuple (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		out = append(out, clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	return out, nil
}

// LockLiveTargetTypes реализует access_binding.WriterIface (kaname#904, Р2).
//
// # Почему это не чтение-и-действие (запрет #10)
//
// Чтение стоит в ТОЙ ЖЕ транзакции, что вставка выдачи, и берёт замок на
// прочитанные строки: снятие типа (применитель меняет `live`, входящий в
// уникальные ограничения, — то есть обновляет КЛЮЧ и берёт `FOR UPDATE`) с этим
// замком конфликтует и ждёт фиксации выдачи. В обратную сторону — запись ждёт
// незафиксированного снятия, и при READ COMMITTED перепроверяет условие `live`
// на зафиксированной версии строки: снятая строка в ответ не попадает.
//
// # Почему `FOR KEY SHARE`, а не внешний ключ
//
// Ключ на `(dotted, live)` запретил бы СНЯТИЕ типа, пока на него есть хоть одна
// выдача, — а лежащая выдача обязана пережить снятие своего типа (Р5, приёмка
// ATC-14). Условие приёма новой записи и постоянный инвариант — разные
// утверждения; здесь нужно первое. Тот же замок и тот же порядок берёт писатель
// селекторов роли (`roleWriter.ReplaceRuleSelectors`).
//
// # Порядок — `ORDER BY dotted`
//
// Применитель запирает строки модуля одним оператором в порядке `dotted`
// (`catalogWriter.LockModuleResources`); здесь тот же порядок назначает та же
// власть — база, — и взаимная блокировка на паре типов непредставима.
func (w *abWriter) LockLiveTargetTypes(ctx context.Context, types []string) ([]string, error) {
	// ПОРЯДОК ЗАХВАТА (kaname#922): строки catalog_resource типов цели — FOR KEY
	// SHARE, ORDER BY dotted, первым оператором транзакции создания; новая строка
	// выдачи и строка роли (FOR SHARE, триггер) — после. Перепись — docs/changes/kn-922/lock-order-census.md.
	if len(types) == 0 {
		return nil, nil
	}
	rows, err := w.tx.Query(ctx, `
		SELECT dotted FROM kaname.catalog_resource
		 WHERE dotted = ANY($1) AND live
		 ORDER BY dotted
		   FOR KEY SHARE`, types)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	live := make([]string, 0, len(types))
	for rows.Next() {
		var dotted string
		if err := rows.Scan(&dotted); err != nil {
			return nil, mapErr(err, "", "")
		}
		live = append(live, dotted)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return live, nil
}

// InsertEmittedTuples сохраняет ТОЧНЫЕ кортежи прав, выпущенные для выдачи, в
// kaname.access_binding_emitted_tuples в текущей пишущей транзакции, вместе с
// парным EmitRelationWrite (запрет #10). ON CONFLICT DO NOTHING делает повторный
// выпуск (идемпотентная повторная выдача / реконсайл) пустым. len==0 — ничего.
func (w *abWriter) InsertEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []access_binding.RelationTuple) error {
	if len(tuples) == 0 {
		return nil
	}
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("insert emitted tuple: incomplete tuple (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		if _, err := w.tx.Exec(ctx,
			// source='binding': пишут Create и RoleTupleReconciler из Role.Update. Строки
			// ARM_LABELS по членам (source='member') принадлежат реконсайлеру γ
			// (RecordEmittedTuples), и путь уровня выдачи их НЕ трогает.
			// Координата члена у строки уровня выдачи пуста (kaname#933): умолчание
			// колонок, и ключ конфликта — полный ключ реестра.
			`INSERT INTO access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
			 VALUES ($1, $2, $3, $4, 'binding')
			 ON CONFLICT (binding_id, member_object_type, member_object_id, fga_user, relation, object) DO NOTHING`,
			string(bindingID), t.User, t.Relation, t.Object,
		); err != nil {
			return mapErr(err, "", string(bindingID))
		}
	}
	return nil
}

// ReplaceEmittedTuples атомарно заменяет сохранённый выпущенный набор выдачи
// (DELETE всех строк выдачи, затем INSERT нового набора) в текущей пишущей
// транзакции — веер реконсайла Role.Update пользуется им, чтобы реестр отражал
// ТЕКУЩУЮ выпущенную проекцию после смены прав (запрет #10). Пустой `tuples`
// очищает строки реестра выдачи.
func (w *abWriter) ReplaceEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []access_binding.RelationTuple) error {
	// Полная замена ограничена подмножеством УРОВНЯ ВЫДАЧИ (source='binding').
	// Реконсайл Role.Update (RoleTupleReconciler) владеет только этими кортежами;
	// строки ARM_LABELS по членам (source='member', их пишет реконсайлер γ)
	// принадлежат RoleMembershipFanout и ОБЯЗАНЫ пережить реконсайл уровня выдачи —
	// иначе Role.Update со сменой правил у своей роли, где ветвь уровня выдачи
	// соседствует с ветвью ARM_LABELS, отозвал бы весь доступ, выбранный метками
	// (прежний `DELETE … WHERE binding_id` стирал их). InsertEmittedTuples вставляет
	// новый набор заново как source='binding'.
	if _, err := w.tx.Exec(ctx,
		`DELETE FROM access_binding_emitted_tuples WHERE binding_id = $1 AND source = 'binding'`, string(bindingID),
	); err != nil {
		return mapErr(err, "", string(bindingID))
	}
	return w.InsertEmittedTuples(ctx, bindingID, tuples)
}

// emitFGAOutbox ставит кортежи выдачи в журнал СОБСТВЕННЫМ выпускателем таблицы,
// а не собирает строку здесь.
//
// Прежде здесь стояла своя вставка, строка на кортеж, со своим рукописным
// payload — второе написание формы, весь смысл которой в том, что все
// производители согласны о ней. Они разошлись в тот момент, когда строка
// перестала быть одним кортежем: этот путь продолжал дробить набор отношений
// субъекта по строкам, и выдача через привязку приходила по одному отношению,
// тогда как та же выдача через реконсайлер приходила целиком. Один выпускатель,
// одна форма, одна единица атомарности — расхождению негде случиться.
func (w *abWriter) emitFGAOutbox(ctx context.Context, eventType string, tuples []access_binding.RelationTuple) error {
	if len(tuples) == 0 {
		return nil
	}
	out := make([]clients.RelationTuple, 0, len(tuples))
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("emit fga_outbox: incomplete tuple (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		out = append(out, clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	var err error
	switch eventType {
	case fga_outbox.EventTypeWrite:
		err = fga_outbox.EmitWriteTx(ctx, w.tx, out)
	case fga_outbox.EventTypeDelete:
		err = fga_outbox.EmitDeleteTx(ctx, w.tx, out)
	default:
		return fmt.Errorf("emit fga_outbox: unknown event type %q", eventType)
	}
	// Отказ базы на записи журнала переводится ТЕМ ЖЕ переводчиком, что у каждого
	// другого стейтмента этой транзакции. Запись журнала — стейтмент, на котором
	// триггер берёт строки прямого факта, то есть именно тот, где транзакция
	// встречает взаимную блокировку; без перевода 40P01 уезжал наружу как
	// `internal error`, а не как признак конфликта, по которому снятие выдачи
	// повторяет свою транзакцию (kaname#679).
	return mapErr(err, "", "")
}

// EmitAuditEvent атомарно добавляет одну долговечную строку соответствия в
// kaname.audit_outbox в текущей пишущей транзакции (атомарность обязательна — см.
// ссылки внутри службы, запрет #10). Вставка либо удаление выдачи и постановка
// аудита фиксируются либо откатываются вместе: откаченная выдача не оставляет
// строки аудита, утверждающей, что она была, а зафиксированная всегда оставляет
// след.
//
// jsonb event_payload несёт измерения соответствия (actor / subject / resource /
// role_id / binding_id), чтобы на вопрос «кто, какую роль, кому, на какой ресурс
// и когда» отвечал запрос; «когда» даёт created_at. Строка начинает со
// status='pending' для отправителя аудита (pkg/audit).
func (w *abWriter) EmitAuditEvent(ctx context.Context, ev access_binding.AuditEvent) error {
	if ev.EventType == "" {
		return fmt.Errorf("emit audit_outbox: event_type required")
	}
	// Канонические измерения соответствия, затем слияние с ExtraPayload события
	// (например, разница старого и нового у selector_replaced). Собирается как
	// map[string]any, чтобы разнородные дополнительные поля (вложенные объекты) были
	// представимы; ключи ExtraPayload при совпадении перекрывают канонические.
	fields := map[string]any{
		"actor":         ev.Actor,
		"subject_type":  ev.SubjectType,
		"subject_id":    ev.SubjectID,
		"resource_type": ev.ResourceType,
		"resource_id":   ev.ResourceID,
		"role_id":       ev.RoleID,
		"binding_id":    ev.BindingID,
	}
	for k, v := range ev.ExtraPayload {
		fields[k] = v
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("emit audit_outbox: marshal payload: %w", err)
	}
	// tenant_account_id может отсутствовать (сужение до аккаунта, когда он известен).
	tenant := nullableString(ev.TenantAccountID)
	if _, err := w.tx.Exec(ctx,
		`INSERT INTO kaname.audit_outbox
			(id, event_type, tenant_account_id, event_payload, status, attempts, created_at, next_attempt_at)
		 VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now(), now())`,
		newAuditEventID(), string(ev.EventType), tenant, payload,
	); err != nil {
		return fmt.Errorf("emit audit_outbox %s: %w", ev.EventType, err)
	}
	return nil
}

// newAuditEventID отдаёт id audit_outbox вида `evt_<22 знака crockford-base32>`,
// удовлетворяющий регулярному выражению audit_outbox_id_check
// (`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`). Тело в 22 знака повторяет
// проверенный генератор начального администратора; domain.NewKac127ID даёт тело
// лишь в 17 знаков — ниже нижней границы CHECK в 20.
func newAuditEventID() string {
	const crockford = "0123456789abcdefghjkmnpqrstvwxyz"
	const bodyLen = 22
	var raw [14]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand.Read на исправной машине не отказывает; отказ значит, что источник
		// энтропии системы сломан, — panic здесь верный ответ.
		panic("pg: crypto/rand failed: " + err.Error())
	}
	hi := binary.BigEndian.Uint64(raw[0:8])
	lo := binary.BigEndian.Uint64(raw[6:14])

	var sb strings.Builder
	sb.Grow(len("evt_") + bodyLen)
	sb.WriteString("evt_")
	for i := 0; i < bodyLen; i++ {
		bitOff := uint(i*5) % 64 // i — ограниченный индекс цикла [0,bodyLen); i*5 не переполняет uint.
		src := hi
		if i >= 12 {
			src = lo
		}
		val := (src >> (64 - bitOff - 5)) & 0x1f
		sb.WriteByte(crockford[val])
	}
	return sb.String()
}

// deriveEventTypeFromOp — канонический event_type для унаследованного имени op.
// binding_delete→binding_revoke, binding_upsert→binding_grant, прочее — как есть.
func deriveEventTypeFromOp(op string) string {
	switch op {
	case "binding_delete":
		return "binding_revoke"
	case "binding_upsert":
		return "binding_grant"
	default:
		return op
	}
}

// deriveOpFromEventType — унаследованное имя op для канонического event_type.
// Обратная к deriveEventTypeFromOp; нужна, когда вызывающий дал только event_type
// (Op обязан удовлетворять CHECK subject_change_op_check, поэтому его заполняем).
func deriveOpFromEventType(eventType string) string {
	switch eventType {
	case "binding_revoke":
		return "binding_delete"
	case "binding_grant":
		return "binding_upsert"
	default:
		return eventType
	}
}

// SelectEmittedTuplesBySource читает только строки выпущенного набора выдачи,
// записанные ОДНИМ владельцем (source='binding' — Create и RoleTupleReconciler,
// source='member' — реконсайлер γ). Веер реконсайла Role.Update читает
// подмножество 'binding', поэтому его разница наборов никогда не видит — а значит,
// не может отозвать — кортежи ARM_LABELS по членам (КРИТИЧНАЯ правка источника
// реестра). Полный симметричный отзыв (delete.go) по-прежнему читает
// SelectEmittedTuples (весь реестр). Ноль строк ⇒ nil.
func (r *abReader) SelectEmittedTuplesBySource(ctx context.Context, bindingID domain.AccessBindingID, source string) ([]access_binding.RelationTuple, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT DISTINCT fga_user, relation, object
		   FROM access_binding_emitted_tuples
		  WHERE binding_id = $1 AND source = $2
		  ORDER BY relation, object, fga_user`, string(bindingID), source)
	if err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	defer rows.Close()
	var out []access_binding.RelationTuple
	for rows.Next() {
		var t access_binding.RelationTuple
		if err := rows.Scan(&t.User, &t.Relation, &t.Object); err != nil {
			return nil, mapErr(err, "", string(bindingID))
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	return out, nil
}

// SelectEmittedTuples читает сохранённый точный выпущенный набор выдачи
// (kaname.access_binding_emitted_tuples). Отзыв (delete.go) и веер реконсайла
// Role.Update берут его источником правды о том, какие кортежи прав на деле
// записаны, поэтому отзыв побайтно симметричен выдаче, каковы бы ни были текущие
// права роли. Кортеж, выпущенный двумя членами выдачи (две координаты), — одна
// строка ответа (kaname#933). Ноль строк ⇒ пустой срез (nil).
func (r *abReader) SelectEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID) ([]access_binding.RelationTuple, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT DISTINCT fga_user, relation, object
		   FROM access_binding_emitted_tuples
		  WHERE binding_id = $1
		  ORDER BY relation, object, fga_user`, string(bindingID))
	if err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	defer rows.Close()
	var out []access_binding.RelationTuple
	for rows.Next() {
		var t access_binding.RelationTuple
		if err := rows.Scan(&t.User, &t.Relation, &t.Object); err != nil {
			return nil, mapErr(err, "", string(bindingID))
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	return out, nil
}

// membershipHoldingBindingsPredicate — предикат «эта выдача держит членство
// человека в аккаунте». $1 = user_id, $2 = account_id.
//
// ЭТО КОПИЯ УСЛОВИЯ ТРИГГЕРА `membership_carrying_rights_is_kept` (миграция
// 472002), и копия намеренная: перенести его в общее место нельзя — триггер
// исполняется внутри базы на удалении строки, а это чтение идёт снаружи и после
// отказа. Копия названа копией здесь, чтобы правка одной стороны заставляла
// открыть вторую; расхождение наблюдаемо пробой, которая заводит выдачу каждой
// формы и требует, чтобы отвергнутое триггером было названо отказом.
//
// Три оси, ровно как у триггера: живая · адресует ЭТОГО человека (обе проекции
// субъекта) · в области ЭТОГО аккаунта либо его проекта.
const membershipHoldingBindingsPredicate = `
	  status = 'ACTIVE'
	  AND ( (subject_type = 'user' AND subject_id = $1)
	        OR EXISTS (SELECT 1 FROM access_binding_subjects s
	                    WHERE s.binding_id = access_bindings.id
	                      AND s.subject_type = 'user' AND s.subject_id = $1) )
	  AND ( (resource_type = 'account' AND resource_id = $2)
	        OR (resource_type = 'project'
	            AND resource_id IN (SELECT id FROM projects WHERE account_id = $2)) )`

// ListActiveHoldingMembership — выдачи, держащие членство (задача kacho#1686).
//
// Один запрос отдаёт и ограниченный перечень, и ПОЛНУЮ величину: два запроса
// читали бы два разных снимка, и «названо 5 из 3» стало бы наблюдаемым исходом.
// Порядок — (created_at, id) ASC: отказ, называющий одни и те же выдачи в разном
// порядке от прогона к прогону, нельзя ни сравнить, ни закрепить пробой.
//
// cursor-list-table: access_bindings
//
// Объявление стоит потому, что имя таблицы в запросе СОБИРАЕТСЯ в Go (предикат
// вынесен константой ради сверки с триггером), и обход дерева его не видит.
// Без объявления индекс под этот порядок не проверялся бы никем — а порядок тут
// не украшение: он и есть то, что делает перечень воспроизводимым.
func (r *abReader) ListActiveHoldingMembership(
	ctx context.Context, userID domain.UserID, accountID domain.AccountID, limit int,
) ([]string, int, error) {
	if limit <= 0 {
		return nil, 0, nil
	}
	rows, err := r.tx.Query(ctx, `
		SELECT id, count(*) OVER () AS total
		  FROM access_bindings
		 WHERE `+membershipHoldingBindingsPredicate+`
		 ORDER BY created_at ASC, id ASC
		 LIMIT $3`, string(userID), string(accountID), limit)
	if err != nil {
		return nil, 0, mapErr(err, "", string(userID))
	}
	defer rows.Close()

	var (
		ids   []string
		total int
	)
	for rows.Next() {
		var id string
		var t int
		if err := rows.Scan(&id, &t); err != nil {
			return nil, 0, mapErr(err, "", string(userID))
		}
		ids = append(ids, id)
		total = t
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mapErr(err, "", string(userID))
	}
	return ids, total, nil
}

// ListActiveByRole отдаёт каждую неотозванную (PENDING/ACTIVE) выдачу роли (веер
// реконсайла Role.Update). Набор ограничен действующими выдачами ОДНОЙ изменённой
// роли. Порядок (created_at, id) ASC — ради детерминированного реконсайла.
func (r *abReader) ListActiveByRole(ctx context.Context, roleID domain.RoleID) ([]domain.AccessBinding, error) {
	rows, err := r.tx.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings
		              WHERE role_id = $1 AND status <> 'REVOKED'
		              ORDER BY created_at ASC, id ASC`, abCols), string(roleID))
	if err != nil {
		return nil, mapErr(err, "", string(roleID))
	}
	defer rows.Close()
	var out []domain.AccessBinding
	for rows.Next() {
		ab, err := scanAB(rows)
		if err != nil {
			return nil, mapErr(err, "", string(roleID))
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(roleID))
	}
	return out, nil
}

// CountActiveByRole отдаёт число неотозванных выдач роли — проверка предела веера
// Role.Update (10000). Дешёвый COUNT по role_id.
func (r *abReader) CountActiveByRole(ctx context.Context, roleID domain.RoleID) (int, error) {
	var n int
	if err := r.tx.QueryRow(ctx,
		`SELECT count(*) FROM access_bindings WHERE role_id = $1 AND status <> 'REVOKED'`,
		string(roleID)).Scan(&n); err != nil {
		return 0, mapErr(err, "", string(roleID))
	}
	return n, nil
}

// ─── multi-subject set + ListByRole ───

// ListByRole отдаёт выдачи с roleID, листая ключом (created_at, id) ASC. Листание,
// чтение и курсор — как у прочих перечней; умолчание IncludeRevoked=false скрывает
// строки REVOKED (статичный предикат без параметра, поэтому запрос собран здесь,
// а не через listWithConds, который ждёт по параметру на условие).
func (r *abReader) ListByRole(ctx context.Context, roleID domain.RoleID, f access_binding.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	// page_size вне [0..maxListPageSize] ОТВЕРГАЕТСЯ, а не усекается: усечение
	// отвечает 200 OK страницей короче запрошенной, и ничто в ответе не отличает
	// её от полного ответа.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	conditions := []string{"role_id = $1"}
	args := []any{string(roleID)}
	argIdx := 2
	if !f.IncludeRevoked {
		conditions = append(conditions, "status <> 'REVOKED'")
	}
	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	q := fmt.Sprintf(`SELECT %s FROM access_bindings WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		abCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", string(roleID))
	}
	defer rows.Close()
	var out []domain.AccessBinding
	for rows.Next() {
		ab, serr := scanAB(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", string(roleID))
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", string(roleID))
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// ListSubjects отдаёт набор субъектов ОДНОЙ выдачи в порядке (ordinal,
// subject_type, subject_id). У сохранённой выдачи набор непуст — это держит база
// (`access_bindings_carry_a_subject`, kaname#902); ноль строк значит, что выдачи
// с таким идентификатором в таблице нет.
func (r *abReader) ListSubjects(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.Subject, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT subject_type, subject_id FROM access_binding_subjects
		  WHERE binding_id = $1
		  ORDER BY ordinal ASC, subject_type ASC, subject_id ASC`, string(bindingID))
	if err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	defer rows.Close()
	var out []domain.Subject
	for rows.Next() {
		var s domain.Subject
		if err := rows.Scan((*string)(&s.Type), (*string)(&s.ID)); err != nil {
			return nil, mapErr(err, "", string(bindingID))
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	return out, nil
}

// ListSubjectsForBindings пачкой читает субъектов МНОГИХ выдач одним запросом (без
// N+1 по строкам). У сохранённой выдачи набор непуст (`access_bindings_carry_a_subject`,
// kaname#902), поэтому в карте нет только идентификаторов, которых нет в таблице.
func (r *abReader) ListSubjectsForBindings(ctx context.Context, bindingIDs []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	out := make(map[domain.AccessBindingID][]domain.Subject, len(bindingIDs))
	if len(bindingIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(bindingIDs))
	for i, id := range bindingIDs {
		ids[i] = string(id)
	}
	rows, err := r.tx.Query(ctx,
		`SELECT binding_id, subject_type, subject_id FROM access_binding_subjects
		  WHERE binding_id = ANY($1)
		  ORDER BY binding_id ASC, ordinal ASC, subject_type ASC, subject_id ASC`, ids)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var bid string
		var s domain.Subject
		if err := rows.Scan(&bid, (*string)(&s.Type), (*string)(&s.ID)); err != nil {
			return nil, mapErr(err, "", "")
		}
		key := domain.AccessBindingID(bid)
		out[key] = append(out[key], s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

// ListMaterializedAtForBindings пачкой читает момент материализации каждой выдачи
// — MAX(updated_at) по её ACTIVE-строкам в access_binding_target_members (реестр
// реконсайлера). Выдач без ACTIVE-члена в карте НЕТ (вызывающий оставляет
// MaterializedAt нулевым → API отдаёт поле незаданным).
//
// Строки PENDING_VERIFICATION исключены WHERE намеренно: ожидающий проверки член
// доступом НЕ является, и показ его сказал бы администратору, что выдача работает,
// когда она не работает. Ведущий столбец binding_id первичного ключа обслуживает
// запрос, поэтому это один индексный агрегат, а не веер N+1.
func (r *abReader) ListMaterializedAtForBindings(ctx context.Context, bindingIDs []domain.AccessBindingID) (map[domain.AccessBindingID]time.Time, error) {
	out := make(map[domain.AccessBindingID]time.Time, len(bindingIDs))
	if len(bindingIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(bindingIDs))
	for i, id := range bindingIDs {
		ids[i] = string(id)
	}
	rows, err := r.tx.Query(ctx,
		`SELECT binding_id, MAX(updated_at)
		   FROM access_binding_target_members
		  WHERE binding_id = ANY($1)
		    AND verification_status = 'ACTIVE'
		  GROUP BY binding_id`, ids)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var (
			bid string
			at  time.Time
		)
		if err := rows.Scan(&bid, &at); err != nil {
			return nil, mapErr(err, "", "")
		}
		out[domain.AccessBindingID(bid)] = at
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

// InsertSubjects сохраняет набор субъектов выдачи. Строка на субъекта,
// идемпотентно (ON CONFLICT DO NOTHING — повторная вставка пуста; замок строки
// первичного ключа выстраивает одинаковые одновременные вставки в ровно одну
// строку, запрет #10). ordinal хранит порядок запроса, поэтому subjects[0] (=
// унаследованная одиночная проекция) детерминирован. Пустой набор не пишет
// ничего, и коммит такой выдачи база отвергает (`access_bindings_carry_a_subject`,
// kaname#902); набор без строки пары выдачи — тоже (kaname#907): набор пишется
// в той же транзакции, что выдача.
func (w *abWriter) InsertSubjects(ctx context.Context, bindingID domain.AccessBindingID, subjects []domain.Subject) error {
	if len(subjects) == 0 {
		return nil
	}
	for i, s := range subjects {
		if _, err := w.tx.Exec(ctx,
			`INSERT INTO access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (binding_id, subject_type, subject_id) DO NOTHING`,
			string(bindingID), string(s.Type), string(s.ID), i,
		); err != nil {
			return mapErr(err, "", string(bindingID))
		}
	}
	return nil
}

// DeleteSubject снимает строку ОДНОГО субъекта (отзыв по субъекту) и сообщает, была
// ли строка удалена на деле (идемпотентно — нет субъекта ⇒ false).
func (w *abWriter) DeleteSubject(ctx context.Context, bindingID domain.AccessBindingID, subject domain.Subject) (bool, error) {
	tag, err := w.tx.Exec(ctx,
		`DELETE FROM access_binding_subjects
		  WHERE binding_id = $1 AND subject_type = $2 AND subject_id = $3`,
		string(bindingID), string(subject.Type), string(subject.ID))
	if err != nil {
		return false, mapErr(err, "AccessBinding.DeleteSubject", string(bindingID))
	}
	return tag.RowsAffected() > 0, nil
}

// nullableString — пустую строку как NULL.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableUserIDPtr — *UserID → string/nil для pgx (NULL когда указатель nil
// либо пустой).
func nullableUserIDPtr(u *domain.UserID) any {
	if u == nil || *u == "" {
		return nil
	}
	return string(*u)
}
