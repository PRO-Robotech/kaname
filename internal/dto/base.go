// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package dto — table-driven generic-based DTO transfers for kacho-iam
// (parity with kacho-vpc/internal/dto/base.go).
//
// Layout:
//   - dto/base.go (this file): generic Interface, RegTransfer / FindTransfer,
//     FromTo helper, Transfer entry-point with type-set generic constraint
//     (Transferrable).
//   - dto/toproto/*.go: implementations of Interface[domain.X, *iamv1.X] +
//     init()-time registration in the registry.
//
// Usage (caller-site):
//
//	var dst *iamv1.Account
//	if err := dto.Transfer(dto.FromTo(d, &dst)); err != nil { ... }
//	return anypb.New(dst)
package dto

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Interface — generic transfer-функтор F → T.
type Interface[F any, T any] interface {
	Transfer(F) (T, error)
}

// Fn — adapter: обычная Go-функция как Interface.
type Fn[F any, T any] func(F) (T, error)

func (f Fn[F, T]) Transfer(src F) (T, error) { return f(src) }

// Fn2Face оборачивает функцию в Interface — синтаксический helper для init().
func Fn2Face[F any, T any](fn func(F) (T, error)) Interface[F, T] { return Fn[F, T](fn) }

// ---- Registry ----------------------------------------------------------------

type tag[_ any, _ any] struct{}

var (
	regMu        sync.RWMutex
	transfersReg = map[reflect.Type]any{}
)

// RegTransfer регистрирует трансфер F → T под ключом reflect.TypeFor[tag[F,T]].
func RegTransfer[F any, T any](impl Interface[F, T]) {
	key := reflect.TypeFor[tag[F, T]]()
	regMu.Lock()
	defer regMu.Unlock()
	if _, ok := transfersReg[key]; ok {
		panic(fmt.Sprintf("dto: duplicate transfer registration for %s", key.String()))
	}
	transfersReg[key] = impl
}

func findTransfer[F any, T any]() (Interface[F, T], bool) {
	key := reflect.TypeFor[tag[F, T]]()
	regMu.RLock()
	defer regMu.RUnlock()
	v, ok := transfersReg[key]
	if !ok {
		return nil, false
	}
	impl, ok := v.(Interface[F, T])
	if !ok {
		return nil, false
	}
	return impl, true
}

// ---- DTO entry-point (Transfer + FromTo) -------------------------------------

// DTO — pair-объект, который собирает FromTo(): хранит src + указатель на dst
// и реализует Perform() через registry-lookup.
type DTO[F any, T any] struct {
	src F
	dst *T
}

// Perform выполняет лукап Interface[F,T] и пишет результат в *dto.dst.
func (d *DTO[F, T]) Perform() error {
	impl, ok := findTransfer[F, T]()
	if !ok {
		var f F
		var t T
		return fmt.Errorf("dto: no transfer registered for %T → %T", f, t)
	}
	res, err := impl.Transfer(d.src)
	if err != nil {
		return err
	}
	*d.dst = res
	return nil
}

// FromTo — конструктор DTO. Применяется в caller-site.
func FromTo[F any, T any](src F, dst *T) *DTO[F, T] {
	return &DTO[F, T]{src: src, dst: dst}
}

// Transferrable — closed type-set generic constraint for Transfer().
// Accepts only those `*DTO[F,T]` pairs that are **explicitly** registered in
// the type-set below. New pairs are added here as new domain↔proto mappings
// are introduced.
type Transferrable interface {
	Perform() error

	*DTO[time.Time, *timestamppb.Timestamp] |
		*DTO[domain.Account, *iamv1.Account] |
		*DTO[domain.Project, *iamv1.Project] |
		*DTO[domain.User, *iamv1.User] |
		*DTO[domain.ServiceAccount, *iamv1.ServiceAccount] |
		*DTO[domain.Group, *iamv1.Group] |
		*DTO[domain.GroupMember, *iamv1.GroupMember] |
		*DTO[domain.Role, *iamv1.Role] |
		*DTO[domain.AccessBinding, *iamv1.AccessBinding]
}

// Transfer запускает Perform() на dto. Единственная публичная entry-point.
func Transfer[V Transferrable](dto V) error {
	return dto.Perform()
}
