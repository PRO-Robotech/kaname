// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authzsnapshot закрепляет одну опубликованную модель на весь запрос.
package authzsnapshot

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ErrUnconfirmed обозначает закрытый отказ при неизвестной текущей модели.
var ErrUnconfirmed = errors.New("authorization model is not confirmed current")

// ErrInvalidPublication обозначает голову, чьи данные не сходятся с отпечатком.
var ErrInvalidPublication = errors.New("authorization publication is invalid")

// Snapshot связывает планы, каталог и системные роли одной редакции. После
// передачи Store поля, Facts и Roles не изменяются вызывающими.
type Snapshot struct {
	Revision    int64
	Digest      string
	CatalogID   string
	ConfirmedAt time.Time
	Plans       *authzmodel.Plans
	Facts       *catalog.Facts
	Roles       []domain.Role
}

func (s *Snapshot) valid() bool {
	return s != nil && s.Revision > 0 && s.Digest != "" && !s.ConfirmedAt.IsZero() &&
		s.Plans != nil && s.Facts != nil
}

type requestSnapshotKey struct{}

// WithContext закрепляет снимок до первого решения о правах вызывающего.
func WithContext(ctx context.Context, snapshot *Snapshot) (context.Context, error) {
	if !snapshot.valid() {
		return nil, ErrUnconfirmed
	}
	return context.WithValue(ctx, requestSnapshotKey{}, snapshot), nil
}

func FromContext(ctx context.Context) (*Snapshot, bool) {
	snapshot, ok := ctx.Value(requestSnapshotKey{}).(*Snapshot)
	return snapshot, ok
}

// PlansForRequest сохраняет текущий путь для вызовов вне опубликованной модели.
func PlansForRequest(ctx context.Context) (*authzmodel.Plans, error) {
	if snapshot, ok := FromContext(ctx); ok {
		return snapshot.Plans, nil
	}
	return authzmodel.Shared()
}

// FactsForRequest выбирает каталог закреплённой публикации; вне такого
// запроса сохраняет источник прежнего пути.
func FactsForRequest(ctx context.Context, fallback catalog.Source) *catalog.Facts {
	if snapshot, ok := FromContext(ctx); ok {
		return snapshot.Facts
	}
	if fallback == nil {
		return nil
	}
	return fallback.Facts()
}

// Source читает авторитетную голову журнала. ConfirmActivePublication проверяет
// только идентичность уже прочитанной модели и возвращает начало чтения из БД.
type Source interface {
	LoadActivePublication(context.Context) (Snapshot, error)
	ConfirmActivePublication(context.Context, *Snapshot) (time.Time, error)
}

type Store struct {
	source  Source
	maxAge  time.Duration
	now     func() time.Time
	current atomic.Pointer[Snapshot]

	refreshMu       sync.Mutex
	latest          *Snapshot
	minimumRevision int64
	minimumDigest   string
}

func NewStore(source Source, maxAge time.Duration) (*Store, error) {
	if source == nil || maxAge <= 0 {
		return nil, errors.New("authzsnapshot: требуется источник и положительное окно актуальности")
	}
	return &Store{source: source, maxAge: maxAge, now: time.Now}, nil
}

// ObserveCommittedRevision запрещает выдавать прежний снимок после локальной
// фиксации публикации, даже пока новая редакция ещё не принята читателем.
// Более поздний снимок сохраняется, если другая реплика уже продвинула голову.
func (s *Store) ObserveCommittedRevision(revision int64, digest string) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if revision > s.minimumRevision {
		s.minimumRevision, s.minimumDigest = revision, digest
	} else if revision == s.minimumRevision && digest != s.minimumDigest {
		// Два отпечатка одной редакции означают нарушение неизменяемости.
		s.minimumDigest = ""
	}
	if current := s.current.Load(); current != nil && !s.matchesObservedHead(current) {
		s.current.Store(nil)
	}
}

func (s *Store) matchesObservedHead(snapshot *Snapshot) bool {
	return snapshot.Revision > s.minimumRevision ||
		snapshot.Revision == s.minimumRevision && snapshot.Digest == s.minimumDigest
}

// Refresh заново загружает данные только при смене головы. Повреждённая
// голова или ошибка связи оставляет прежнее подтверждение до его исходного
// срока. Переходная фаза закрывает снимок, когда её подтвердило чтение.
func (s *Store) Refresh(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	previous := s.current.Load()
	if previous != nil {
		at, err := s.source.ConfirmActivePublication(ctx, previous)
		switch {
		case err == nil:
			confirmed := *previous
			confirmed.ConfirmedAt = at
			return s.install(ctx, &confirmed)
		case !errors.Is(err, ErrUnconfirmed):
			return err
		}
	}
	snapshot, err := s.source.LoadActivePublication(ctx)
	if err != nil {
		if previous != nil && !errors.Is(err, ErrInvalidPublication) {
			s.current.Store(nil)
		}
		return err
	}
	return s.install(ctx, &snapshot)
}

func (s *Store) install(ctx context.Context, snapshot *Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.fresh(snapshot) || !s.matchesObservedHead(snapshot) ||
		s.latest != nil && (snapshot.Revision < s.latest.Revision ||
			snapshot.ConfirmedAt.Before(s.latest.ConfirmedAt) ||
			snapshot.Revision == s.latest.Revision && !samePublication(snapshot, s.latest)) {
		s.current.Store(nil)
		return ErrUnconfirmed
	}
	s.latest = snapshot
	s.current.Store(snapshot)
	return nil
}

func samePublication(left, right *Snapshot) bool {
	return left.Revision == right.Revision && left.Digest == right.Digest && left.CatalogID == right.CatalogID
}

func (s *Store) fresh(snapshot *Snapshot) bool {
	if !snapshot.valid() {
		return false
	}
	age := s.now().Sub(snapshot.ConfirmedAt)
	return age >= 0 && age < s.maxAge
}

func (s *Store) Pin(ctx context.Context) (context.Context, error) {
	snapshot := s.current.Load()
	if !s.fresh(snapshot) {
		return nil, ErrUnconfirmed
	}
	return WithContext(ctx, snapshot)
}

// ConfirmPin проверяет, что решение успело выйти в подтверждённое окно и
// пока выполнялось, реплика не увидела смену головы. Повторная проверка не
// выполняет запрос к базе и не меняет модель уже принятого решения.
func (s *Store) ConfirmPin(ctx context.Context) error {
	pinned, ok := FromContext(ctx)
	current := s.current.Load()
	if !ok || !s.fresh(pinned) || current == nil || !samePublication(pinned, current) {
		return ErrUnconfirmed
	}
	return nil
}
