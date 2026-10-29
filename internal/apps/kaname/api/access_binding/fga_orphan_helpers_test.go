// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// fga_orphan_helpers_test.go — подмости регрессионного набора о кортежах-сиротах
// (fga_orphan_test.go): расширения поддельного repo для хранимого набора
// эмитированных кортежей и перечня активных привязок роли, поддельный писатель
// Role и провязка use-case Role.Update (настоящие UpdateRoleUseCase и
// RoleTupleReconciler поверх поддельного repo).

import (
	"context"
	"errors"
	"time"

	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/domain"
	ab_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	gdrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/grant_delegation"
)

// ─── упорядоченное хранилище эмитированных кортежей без повторов ───────────────

// orderedTupleSet моделирует в поддельном repo ведомость access_binding_emitted_tuples
// ОДНОЙ привязки: семантика множества (PK по естественному ключу ⇒ без повторов)
// С сохранением порядка вставки при чтении. Настоящий SelectEmittedTuples на pg
// отдаёт детерминированный `ORDER BY relation, object, fga_user`; дублёр — порядок
// вставки. Для контракта симметричного отзыва по МНОЖЕСТВУ годятся оба (проекция
// журнала применяет множество), но голый `map[tuple]struct{}` обходится в
// СЛУЧАЙНОМ порядке, и require.Equal(written, deleted) в TestFGASymmetric от этого
// мерцает или падает. Порядок вставки детерминирован И совпадает с порядком, в
// котором create.go захватил набор записи (он подаёт ОДИН И ТОТ ЖЕ срез `tuples`
// и в EmitRelationWrite, и в InsertEmittedTuples), так что круг побайтно устойчив.
type orderedTupleSet struct {
	order []ab_repo.RelationTuple            // порядок вставки, без повторов
	seen  map[ab_repo.RelationTuple]struct{} // членство для отсева повторов
}

func newOrderedTupleSet() *orderedTupleSet {
	return &orderedTupleSet{seen: map[ab_repo.RelationTuple]struct{}{}}
}

// add дописывает кортеж, если его ещё нет (паритет с ON CONFLICT DO NOTHING).
func (s *orderedTupleSet) add(t ab_repo.RelationTuple) {
	if _, dup := s.seen[t]; dup {
		return
	}
	s.seen[t] = struct{}{}
	s.order = append(s.order, t)
}

// list отдаёт копию в порядке вставки.
func (s *orderedTupleSet) list() []ab_repo.RelationTuple {
	out := make([]ab_repo.RelationTuple, len(s.order))
	copy(out, s.order)
	return out
}

// ─── расширения поддельного repo ─────────────────────────────────────────────

// setRolePermissions меняет permissions стоящей за дублёром роли (имитирует
// Role.Update её permissions между выдачей и отзывом).
func (r *abFakeRepo) setRolePermissions(p domain.Permissions) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rolePermissions = p
}

// setRoleRules помечает стоящую за дублёром роль как роль ПРАВИЛ (модель правил
// RBAC), чтобы создание и сверка шли путём эмиссии scope_grant по типу
// (rulesBindingTuples), а не прежним схлопыванием всей роли в якорь.
func (r *abFakeRepo) setRoleRules(rules domain.Rules) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roleRules = rules
}

// setRoleCustom помечает стоящую за дублёром роль как ПОЛЬЗОВАТЕЛЬСКУЮ, которой
// владеет accountID, чтобы ворота Role.Update — полномочие владельца аккаунта и
// назначаемость — пропускали.
func (r *abFakeRepo) setRoleCustom(accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roleIsCustom = true
	r.accountID = accountID
}

// answerRoleSegments — дублёр отвечает на вопрос о сегментах роли «держится
// всё»: эхо правки роли несёт признак превью (kaname#76).
func (r *abFakeRepo) answerRoleSegments() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roleSegmentsAnswered = true
}

// InsertEmittedTuples — дублёр совместной фиксации точного эмитированного набора.
// Семантика множества (PK по естественному ключу): повторная вставка того же
// кортежа — холостой ход (паритет с ON CONFLICT DO NOTHING); порядок вставки при
// чтении сохраняется, так что круг детерминирован (см. описание orderedTupleSet).
func (w *fakeABWtr) InsertEmittedTuples(_ context.Context, id domain.AccessBindingID, tuples []ab_repo.RelationTuple) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.emittedTuples == nil {
		w.repo.emittedTuples = map[domain.AccessBindingID]*orderedTupleSet{}
	}
	if w.repo.emittedTuples[id] == nil {
		w.repo.emittedTuples[id] = newOrderedTupleSet()
	}
	for _, t := range tuples {
		w.repo.emittedTuples[id].add(t)
	}
	return nil
}

// ReplaceEmittedTuples — дублёр полной замены при сверке (снять всё и вставить
// новый набор) внутри транзакции писателя. Новый набор сохраняет переданный
// порядок вставки.
func (w *fakeABWtr) ReplaceEmittedTuples(_ context.Context, id domain.AccessBindingID, tuples []ab_repo.RelationTuple) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.emittedTuples == nil {
		w.repo.emittedTuples = map[domain.AccessBindingID]*orderedTupleSet{}
	}
	set := newOrderedTupleSet()
	for _, t := range tuples {
		set.add(t)
	}
	w.repo.emittedTuples[id] = set
	return nil
}

// SelectEmittedTuples — дублёр чтения хранимого набора на стороне читателя (база
// разности для отзыва и сверки). Отдаёт точный хранимый набор в порядке вставки
// (детерминированно; настоящий repo на pg упорядочивает по relation,object,fga_user —
// для контракта симметричного отзыва по множеству годятся оба).
func (rd *fakeABRdr) SelectEmittedTuples(_ context.Context, id domain.AccessBindingID) ([]ab_repo.RelationTuple, error) {
	rd.repo.recordTxOp("select_emitted_tuples:" + string(id))
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	if set := rd.repo.emittedTuples[id]; set != nil {
		return set.list(), nil
	}
	return nil, nil
}

// ListActiveByRole — дублёр перечня веера Role.Update: АКТИВНЫЕ привязки роли.
// Дублёр хранит одну привязку (для unit-проб этого хватает); она отдаётся, когда
// её RoleID совпадает и она не REVOKED.
func (rd *fakeABRdr) CountActiveByRole(_ context.Context, _ domain.RoleID) (int, error) {
	return 0, nil
}

func (rd *fakeABRdr) ListActiveByRole(_ context.Context, roleID domain.RoleID) ([]domain.AccessBinding, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	if rd.repo.ab == nil || rd.repo.ab.RoleID != roleID {
		return nil, nil
	}
	if rd.repo.ab.Status == domain.AccessBindingStatusRevoked {
		return nil, nil
	}
	cp := *rd.repo.ab
	return []domain.AccessBinding{cp}, nil
}

// SelectEmittedTuplesBySource — дублёр хранит лишь кортежи уровня привязки (членов
// ARM_LABELS в этих unit-пробах нет), поэтому отдаёт весь хранимый набор независимо
// от источника (настоящий repo на pg фильтрует по столбцу `source`).
func (rd *fakeABRdr) SelectEmittedTuplesBySource(ctx context.Context, id domain.AccessBindingID, _ string) ([]ab_repo.RelationTuple, error) {
	return rd.SelectEmittedTuples(ctx, id)
}

// ─── расширения дублёра для нескольких субъектов (subjects[] + ListByRole) ────

// ListByRole — дублёр перечня аудита: АКТИВНАЯ (не отозванная) привязка роли.
// Дублёр хранит одну привязку (для unit-проб этого хватает); отдаёт её, когда её
// RoleID совпадает и она не REVOKED (если не задан IncludeRevoked).
func (rd *fakeABRdr) ListByRole(_ context.Context, roleID domain.RoleID, f ab_repo.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	// Многострочная фикстура (seedABListByRole) — страница из НЕСКОЛЬКИХ строк:
	// одиночная `ab` о стоимости страницы не утверждает ничего, потому что
	// «на строку» и «на запрос» на одной строке совпадают by construction.
	if len(rd.repo.lbrRows) > 0 {
		out := make([]domain.AccessBinding, 0, len(rd.repo.lbrRows))
		for _, b := range rd.repo.lbrRows {
			if b.RoleID != roleID {
				continue
			}
			if !f.IncludeRevoked && b.Status == domain.AccessBindingStatusRevoked {
				continue
			}
			out = append(out, b)
		}
		return out, "", nil
	}
	if rd.repo.ab == nil || rd.repo.ab.RoleID != roleID {
		return nil, "", nil
	}
	if !f.IncludeRevoked && rd.repo.ab.Status == domain.AccessBindingStatusRevoked {
		return nil, "", nil
	}
	cp := *rd.repo.ab
	return []domain.AccessBinding{cp}, "", nil
}

// ListSubjects — дублёр чтения нескольких субъектов. Отдаёт субъекты привязки,
// записанные InsertSubjects (порядок вставки сохранён).
func (rd *fakeABRdr) ListSubjects(_ context.Context, id domain.AccessBindingID) ([]domain.Subject, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	subs := rd.repo.abSubjects[id]
	out := make([]domain.Subject, len(subs))
	copy(out, subs)
	return out, nil
}

// ListSubjectsForBindings — пакетный дублёр.
func (rd *fakeABRdr) ListSubjectsForBindings(_ context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	out := map[domain.AccessBindingID][]domain.Subject{}
	for _, id := range ids {
		if subs := rd.repo.abSubjects[id]; len(subs) > 0 {
			cp := make([]domain.Subject, len(subs))
			copy(cp, subs)
			out[id] = cp
		}
	}
	return out, nil
}

// ListMaterializedAtForBindings — пакетный дублёр чтения ведомости сверщика, на
// которой стоит AccessBinding.materialized_at. Видны лишь привязки, засеянные
// seedMaterializedAt (как в настоящем repo: нет АКТИВНОГО члена ⇒ записи нет).
func (rd *fakeABRdr) ListMaterializedAtForBindings(_ context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID]time.Time, error) {
	rd.repo.mu.Lock()
	defer rd.repo.mu.Unlock()
	out := map[domain.AccessBindingID]time.Time{}
	for _, id := range ids {
		if at, ok := rd.repo.materializedAt[id]; ok {
			out[id] = at
		}
	}
	return out, nil
}

// InsertSubjects — дублёр записи в дочернюю таблицу субъектов (идемпотентное множество).
func (w *fakeABWtr) InsertSubjects(_ context.Context, id domain.AccessBindingID, subjects []domain.Subject) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.abSubjects == nil {
		w.repo.abSubjects = map[domain.AccessBindingID][]domain.Subject{}
	}
	existing := w.repo.abSubjects[id]
	seen := map[domain.Subject]struct{}{}
	for _, s := range existing {
		seen[s] = struct{}{}
	}
	for _, s := range subjects {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		existing = append(existing, s)
	}
	w.repo.abSubjects[id] = existing
	return nil
}

// DeleteSubject — дублёр отзыва одного субъекта.
func (w *fakeABWtr) DeleteSubject(_ context.Context, id domain.AccessBindingID, subject domain.Subject) (bool, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	subs := w.repo.abSubjects[id]
	out := subs[:0:0]
	found := false
	for _, s := range subs {
		if s == subject {
			found = true
			continue
		}
		out = append(out, s)
	}
	w.repo.abSubjects[id] = out
	return found, nil
}

// ─── поддельный писатель Role ────────────────────────────────────────────────

// fakeRoleWtr — наименьший role.WriterIface для пути doUpdate в Role.Update.
type fakeRoleWtr struct{ repo *abFakeRepo }

func (w *fakeRoleWtr) Insert(_ context.Context, r domain.Role) (domain.Role, error) {
	return r, nil
}

func (w *fakeRoleWtr) Update(_ context.Context, r domain.Role, _ []string) (domain.Role, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	// Новые permissions И rules кладутся в хранилище дублёра, чтобы следующий
	// Roles().Get видел правку (сверка читает роль заново).
	w.repo.rolePermissions = r.Permissions
	w.repo.roleRules = r.Rules
	return r, nil
}

func (w *fakeRoleWtr) UpdateCAS(ctx context.Context, r domain.Role, mask []string, _ string) (domain.Role, error) {
	// Дублёр пропускает маркер OCC (unit-пробы однопоточны) — xmin-CAS проверяет
	// интеграционная проба role_occ на настоящем Postgres.
	return w.Update(ctx, r, mask)
}

func (w *fakeRoleWtr) Delete(_ context.Context, _ domain.RoleID) error { return nil }

func (w *fakeRoleWtr) ReplaceRuleSelectors(_ context.Context, _ domain.RoleID, _ []domain.RuleSelector) error {
	return nil
}

func (w *fakeRoleWtr) RegrainSelectorVerbs(_ context.Context, _ domain.RoleID, _ []domain.RuleSelector) error {
	return nil
}

// ReplaceRoleVerbs — дублёр умеет то же, что настоящий писатель: проекция
// глаголов пишется рядом с селекторами. Дублёр, не умеющий метода, делает
// невидимым ровно тот путь, ради которого его ставят.
func (w *fakeRoleWtr) ReplaceRoleVerbs(context.Context, domain.RoleID, []domain.RoleVerb) error {
	return nil
}

// ReplaceRuleRefs — ТРЕТЬЯ сторона того же правила (kacho#1030). Дублёр умеет и
// её по тому же доводу: не умеющий делает невидимым путь, ради которого стоит.
// UpsertSystemRole — писатель СИСТЕМНОЙ строки. Дублёр её не производит: путь
// этих проб к кластерному ярусу не ведёт, и молча вернуть «записано» значило бы
// сделать дублёра снисходительнее продукта.
func (w *fakeRoleWtr) UpsertSystemRole(context.Context, domain.Role) (domain.Role, bool, error) {
	return domain.Role{}, false, errors.New("дублёр системную роль не пишет")
}

// LockOwnerModule — замок строки модуля транзакции ролей модуля (kaname#913).
// Путь этих проб к ролям модуля не ведёт; отказ, а не «взято», по тому же
// доводу, что у UpsertSystemRole.
func (w *fakeRoleWtr) LockOwnerModule(context.Context, string) error {
	return errors.New("дублёр строку модуля не берёт")
}

func (w *fakeRoleWtr) ReplaceRuleRefs(context.Context, domain.RoleID, []domain.RoleRuleRef) error {
	return nil
}

// ─── провязка use-case Role.Update ───────────────────────────────────────────

// roleUpdateInput строит UpdateRoleInput, меняющий только rules роли
// (update_mask=["rules"]). Use-case заново компилирует rules→permissions, так что
// веер сверки считает разность с новым скомпилированным набором, как и прежде.
// `rules` — авторский вход модели правил 2026 (заменяет прежний вход permissions).
func roleUpdateInput(roleID string, rules domain.Rules) roleapp.UpdateRoleInput {
	return roleapp.UpdateRoleInput{
		ID:         domain.RoleID(roleID),
		Rules:      rules,
		UpdateMask: []string{"rules"},
	}
}

// LiveSystemRoles / RetireRole / ReviveRole — дублёр: отзыв роли этот путь не
// исполняет. Отдаётся пустое, а не правдоподобное: дублёр, отвечающий «снял»,
// сделал бы невидимым ровно тот дефект, ради которого его подставляют.
func (w *fakeRoleWtr) LiveSystemRoles(context.Context) ([]domain.Role, error) { return nil, nil }

func (w *fakeRoleWtr) RetireRole(context.Context, domain.RoleID, string, string, string) (
	domain.RoleRetirement, error) {
	return domain.RoleRetirement{}, nil
}

func (w *fakeRoleWtr) ReviveRole(context.Context, domain.RoleID) (bool, error) { return false, nil }

// GrantorLastPresentedAt — системный класс субъекта (kaname#829) этим дублёром не судится.
func (_ *fakeABRdr) GrantorLastPresentedAt(context.Context, domain.UserID) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

// PublicReadContainer — публичное чтение контейнера (kaname#856) этим дублёром не
// судится: тип цели не объявлен, детей нет.
func (_ *fakeABRdr) PublicReadContainer(context.Context, string) (domain.PublicReadContainer, error) {
	return domain.PublicReadContainer{}, nil
}

func (_ *fakeABRdr) ClassGrantsKeyedModules(context.Context) (domain.ClassGrantsKeyedModules, error) {
	return domain.ClassGrantsKeyedModules{}, nil
}

// GuardSystemClassReads — системный класс субъекта (kaname#829) этим дублёром не судится.
func (_ *fakeRoleWtr) GuardSystemClassReads(context.Context, domain.RoleID, bool) error { return nil }

func (w *fakeRoleWtr) RulesForRegrain(context.Context, domain.RoleID) (domain.Rules, domain.RulePolicy, bool, error) {
	return nil, domain.RulePolicy{}, false, nil
}

// GrantDelegations — делегирований этот дублёр не несёт (kaname#986): пробы файла
// делегированного пути права выдавать не касаются.
func (rd *fakeABRdr) GrantDelegations() gdrepo.ReaderIface { return nil }
