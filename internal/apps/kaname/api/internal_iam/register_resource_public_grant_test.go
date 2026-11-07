// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// register_resource_public_grant_test.go — публикация ресурса для анонимного
// чтения — намерение КОРТЕЖА, а не утверждение о ресурсе.
//
// kacho-registry публикует репозиторий передачей кортежа чтения с подстановкой
// `user:* # v_get @ registry_repository:<reg>/<repo>`; это намерение не несёт
// родительской области и меток, поскольку они не менялись. Ключ строки зеркала —
// ТОТ ЖЕ объект, что у собственной регистрации репозитория, поэтому
// трактовка выдачи как регистрации привела бы к следующему:
//
// При register — замена родительской области репозитория пустой,
//                переданной выдачей (теряется включение: выдачи в области
//                проекта-владельца перестают совпадать);
// При unregister — полное УДАЛЕНИЕ строки зеркала репозитория, хотя сам
//                  репозиторий существует (перевод в закрытое состояние
//                  стёр бы его из проекции авторизации).
//
// Поэтому чистая выдача пишет/удаляет кортеж и больше ничего не трогает.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
)

// ── Двойники ──────────────────────────────────────────────────────────────

// mirrorSpy запоминает записанные и снятые строки зеркала, сохраняя последнее состояние
// каждого объекта, чтобы проба проверяла сохранение родительской области репозитория.
type mirrorSpy struct {
	noDescendants
	mu      sync.Mutex
	rows    map[string]service.ResourceMirrorRow
	upserts int
	deletes int
}

func newMirrorSpy() *mirrorSpy {
	return &mirrorSpy{rows: map[string]service.ResourceMirrorRow{}}
}

func (m *mirrorSpy) UpsertTx(_ context.Context, _ service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserts++
	key := row.ObjectType + ":" + row.ObjectID
	if prev, ok := m.rows[key]; ok && !row.SourceVersion.After(prev.SourceVersion) {
		return false, false, nil
	}
	m.rows[key] = row
	// Эти случаи касаются выдачи с подстановкой, которая вообще не пишет проекцию;
	// они не заявляют отсутствие устаревания, поэтому защищённая точка входа остаётся обязательной.
	return true, false, nil
}

func (m *mirrorSpy) DeleteTx(_ context.Context, _ service.Tx, ot, oid string, tombstone time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	key := ot + ":" + oid
	if prev, ok := m.rows[key]; ok && !prev.SourceVersion.After(tombstone) {
		delete(m.rows, key)
		return true, nil
	}
	return false, nil
}

func (m *mirrorSpy) row(key string) (service.ResourceMirrorRow, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[key]
	return r, ok
}

func (m *mirrorSpy) counts() (upserts, deletes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upserts, m.deletes
}

// grantReq — вход register/unregister в форме реального намерения публичной выдачи:
// только кортеж, без родительской области и меток.
type grantReq struct {
	subject, relation, object string
	parentProject             string
	labels                    map[string]string
	version                   time.Time
}

func (r *grantReq) GetSubjectId() string { return r.subject }
func (r *grantReq) GetRelation() string  { return r.relation }
func (r *grantReq) GetObject() string    { return r.object }
func (r *grantReq) GetSourceVersion() *timestamppb.Timestamp {
	return timestamppb.New(r.version)
}
func (r *grantReq) GetLabels() map[string]string { return r.labels }
func (r *grantReq) GetParentProjectId() string   { return r.parentProject }
func (r *grantReq) GetParentAccountId() string   { return "" }
func (r *grantReq) GetParentChain() []string     { return nil }

const publicGrantObject = "registry_repository:reg53eeeg3578y4ah0q9/team/app"

// publicGrantContainer — реестр репозитория: указатель `parent` репозитория
// называет его, и регистрация репозитория — регистрация этим указателем
// (политика записи посева, kaname#982).
const publicGrantContainer = "registry_registry:reg53eeeg3578y4ah0q9"

// publicGrantProject / publicGrantAccount — область реестра проб публикации.
const (
	publicGrantProject = "prj0000000000000proj"
	publicGrantAccount = "acc0000000000000acc1"
)

func publicGrantRig() (*RegisterResourceUseCase, *mirrorSpy, *countingEmitter, *countingReconcileEvents, *recordingPublisher) {
	m := newMirrorSpy()
	e := &countingEmitter{}
	ev := &countingReconcileEvents{}
	pub := &recordingPublisher{}
	uc := NewRegisterResourceUseCase(e, m, &smTxBeginner{}, seededCatalogTypes{}, pub, &recordingWithdrawal{}, noAudit{}, publicGrantScene()).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"}).WithReconcile(ev)
	return uc, m, e, ev, pub
}

// mirrorKey — ключ строки зеркала для утверждений ниже: имя типа в словаре
// КАТАЛОГА плюс идентификатор.
//
// Перевод спрашивается у ТОГО ЖЕ дублёра, что провязан в use-case этих проб
// (`seededCatalogTypes`), а не выписывается второй копией: разойдясь, ожидание
// и продукт совпадали бы ровно там, где совпадают, и проба перестала бы
// утверждать про ключ хоть что-нибудь.
func mirrorKey(t *testing.T, object string) string {
	t.Helper()
	ti := tupleIntent{object: object}
	fgaType, oid := ti.splitObject()
	identity, ok, err := seededCatalogTypes{}.CatalogTypeTx(context.Background(), nil, fgaType)
	require.NoError(t, err)
	dotted := identity.Dotted
	if !ok {
		dotted = fgaType
	}
	return dotted + ":" + oid
}

// ── Пробы ────────────────────────────────────────────────────────────────

// TestRegisterResource_PublicGrant_LeavesTheResourceProjectionAlone — выдача
// не должна заново описывать ресурс: родительская область репозитория сохраняется.
func TestRegisterResource_PublicGrant_LeavesTheResourceProjectionAlone(t *testing.T) {
	uc, mirror, emitter, events, pub := publicGrantRig()
	ctx := context.Background()
	key := mirrorKey(t, publicGrantObject)

	base := time.Now()
	// (1) Репозиторий регистрирует себя: родительская область + метки.
	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: publicGrantContainer, relation: "parent", object: publicGrantObject,
		parentProject: "prj0000000000000proj", labels: map[string]string{"tier": "gold"},
		version: base,
	}))
	row, ok := mirror.row(key)
	require.True(t, ok, "the repository registration writes the mirror row")
	require.Equal(t, "prj0000000000000proj", row.ParentProjectID)

	upsertsBefore, _ := mirror.counts()
	eventsBefore := events.count()

	// (2) Репозиторий становится публичным: только кортеж чтения с подстановкой
	// и обязательно БОЛЕЕ ПОЗДНЯЯ версия (это более поздняя строка outbox).
	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: "user:*", relation: "v_get", object: publicGrantObject,
		version: base.Add(5 * time.Millisecond),
	}))

	// Выдача идёт через порт публикации С версией владельца и никогда не
	// достигает простого выпуска журнала: туда пришла лишь собственная регистрация репозитория.
	assert.Equal(t, 1, emitter.writes, "the grant must not be enqueued as a bare tuple")
	assertPublications(t, []publicationCall{{
		objectType: "registry_repository", objectID: "reg53eeeg3578y4ah0q9/team/app",
		published: true, version: base.Add(5 * time.Millisecond),
	}}, pub.seen(), "the grant is applied as a publication in the owner's order")
	row, ok = mirror.row(key)
	require.True(t, ok, "the repository must still be projected")
	assert.Equal(t, "prj0000000000000proj", row.ParentProjectID,
		"publishing a repository must not blank its parent scope")
	assert.Equal(t, map[string]string{"tier": "gold"}, row.Labels,
		"publishing a repository must not blank its labels")

	upsertsAfter, _ := mirror.counts()
	assert.Equal(t, upsertsBefore, upsertsAfter, "a pure grant does not restate the resource projection")
	assert.Equal(t, eventsBefore, events.count(), "a pure grant changes no projection, so it enqueues no reconcile event")
}

// TestUnregisterResource_PublicGrant_DoesNotDeleteTheResourceProjection —
// закрытие репозитория снимает кортеж с подстановкой, а не сам репозиторий.
func TestUnregisterResource_PublicGrant_DoesNotDeleteTheResourceProjection(t *testing.T) {
	uc, mirror, emitter, _, pub := publicGrantRig()
	ctx := context.Background()
	key := mirrorKey(t, publicGrantObject)

	base := time.Now()
	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: publicGrantContainer, relation: "parent", object: publicGrantObject,
		parentProject: "prj0000000000000proj", version: base,
	}))
	require.NotEqual(t, 0, emitter.writes)

	// Репозиторий становится закрытым: кортеж с подстановкой снимается.
	require.NoError(t, uc.Unregister(ctx, &grantReq{
		subject: "user:*", relation: "v_get", object: publicGrantObject,
		version: base.Add(5 * time.Millisecond),
	}))

	assert.Equal(t, 0, emitter.deletes, "the withdrawal must not be enqueued as a bare tuple")
	assertPublications(t, []publicationCall{{
		objectType: "registry_repository", objectID: "reg53eeeg3578y4ah0q9/team/app",
		published: false, version: base.Add(5 * time.Millisecond),
	}}, pub.seen(), "the grant is withdrawn as a publication in the owner's order")
	row, ok := mirror.row(key)
	require.True(t, ok, "withdrawing the public grant must NOT delete the repository's projection")
	assert.Equal(t, "prj0000000000000proj", row.ParentProjectID)
	_, deletes := mirror.counts()
	assert.Equal(t, 0, deletes, "a pure grant withdrawal must not reach the mirror at all")
}

// TestUnregisterResource_Repository_StillDeletesTheProjection — защита
// узкая: обычное снятие иерархической регистрации (уходит сам репозиторий)
// всё ещё удаляет проекцию.
func TestUnregisterResource_Repository_StillDeletesTheProjection(t *testing.T) {
	uc, mirror, _, _, pub := publicGrantRig()
	ctx := context.Background()
	key := mirrorKey(t, publicGrantObject)

	base := time.Now()
	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: publicGrantContainer, relation: "parent", object: publicGrantObject,
		parentProject: "prj0000000000000proj", version: base,
	}))
	require.NoError(t, uc.Unregister(ctx, &grantReq{
		subject: publicGrantContainer, relation: "parent", object: publicGrantObject,
		version: base.Add(5 * time.Millisecond),
	}))

	_, ok := mirror.row(key)
	assert.False(t, ok, "removing the repository must still remove its projection")
	// …и его публикацию под ТОЙ ЖЕ версией: id репозитория — его имя,
	// поэтому пережившая репозиторий публикация открыла бы следующий с таким именем.
	assertPublications(t, []publicationCall{{
		objectType: "registry_repository", objectID: "reg53eeeg3578y4ah0q9/team/app",
		published: false, version: base.Add(5 * time.Millisecond),
	}}, pub.seen(), "the object's withdrawal must withdraw its publication under its own version")
}

// TestUnregisterResource_TypeWithoutPublications_LeavesThePublicationPortAlone —
// законный близнец предыдущего случая: у объекта типа без публикаций
// нечего снимать, и его удаление не должно создавать отметку снятия публикации.
func TestUnregisterResource_TypeWithoutPublications_LeavesThePublicationPortAlone(t *testing.T) {
	uc, _, _, _, pub := publicGrantRig()
	uc.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "vpc"})
	scopes := publicGrantScene()
	scopes.pointers = map[string][]string{"vpc_network:enp0000000000000net1": {"project:prj0000000000000proj"}}
	uc.scopes = scopes
	ctx := context.Background()
	const network = "vpc_network:enp0000000000000net1"

	base := time.Now()
	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: "project:prj0000000000000proj", relation: "project", object: network,
		parentProject: "prj0000000000000proj", version: base,
	}))
	require.NoError(t, uc.Unregister(ctx, &grantReq{
		subject: "project:prj0000000000000proj", relation: "project", object: network,
		version: base.Add(5 * time.Millisecond),
	}))
	assert.Empty(t, pub.seen(), "a type that admits no publication must not reach the publication port")
}

// TestRegisterResource_PublicGrant_CarriesTheOwnersVersion — публикация упорядочивается
// по версии, поставленной владельцем. Ноль здесь (потеря версии
// по пути) сделал бы каждую доставку неупорядоченной — дефект kaname#107.
func TestRegisterResource_PublicGrant_CarriesTheOwnersVersion(t *testing.T) {
	uc, _, _, _, pub := publicGrantRig()
	v := time.Date(2026, 9, 16, 1, 2, 3, 456789000, time.UTC)
	require.NoError(t, uc.Register(context.Background(), &grantReq{
		subject: "user:*", relation: "v_get", object: publicGrantObject, version: v,
	}))
	require.NoError(t, uc.Unregister(context.Background(), &grantReq{
		subject: "user:*", relation: "v_get", object: publicGrantObject, version: v.Add(time.Second),
	}))
	calls := pub.seen()
	require.Len(t, calls, 2)
	assert.True(t, calls[0].published)
	assert.True(t, v.Equal(calls[0].version), "publication version = %v, owner stamped %v", calls[0].version, v)
	assert.False(t, calls[1].published)
	assert.True(t, v.Add(time.Second).Equal(calls[1].version), "withdrawal version = %v", calls[1].version)
}

// TestRegisterResource_PublicGrant_StoreFailureIsARefusal — не принятая хранилищем публикация
// возвращается вызывающему ОШИБКОЙ, никогда молчаливым успехом: постоянная очередь
// потребителя доставит её повторно, лишь получив отказ.
func TestRegisterResource_PublicGrant_StoreFailureIsARefusal(t *testing.T) {
	uc, _, _, _, pub := publicGrantRig()
	pub.err = assertAnError
	err := uc.Register(context.Background(), &grantReq{
		subject: "user:*", relation: "v_get", object: publicGrantObject, version: time.Now(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, assertAnError)
}

// publicGrantScene — сцена проб публикации: реестр репозитория зарегистрирован в
// проекте prj0000000000000proj, и проект известен kaname (вывод родителя
// репозитория, kaname#982).
func publicGrantScene() sceneScopes {
	s := unitScopes()
	s.containers = map[string]domain.ContainerScope{
		publicGrantObject:    {Registered: true, ProjectID: publicGrantProject, AccountID: publicGrantAccount},
		publicGrantContainer: {Registered: true, ProjectID: publicGrantProject, AccountID: publicGrantAccount},
	}
	return s
}
