// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package grantsource собирает обычные и системные формы выдач. Это не публичный
// gate: охват барьеров, bundle и остальные классы источников проверяет контроллер.
package grantsource

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
)

// BindingSource сохраняет получателя: одна выдача может давать несколько
// независимых носителей через прямое назначение и через группы.
// Role отсутствует у системной формы GrantedRelation. Семантику роли и модели
// проверяет будущий компилятор; сырая выдача не является разрешением.
type BindingSource struct {
	Binding           domain.AccessBinding
	Role              *domain.Role
	Recipient         domain.Subject
	CapabilityVersion int
}

var (
	ErrBindingSourceInvalid = errors.New("invalid binding source")
	ErrBindingSourceLimit   = errors.New("binding source resource limit exceeded")
)

// Пределы ограничивают весь сбор, включая повторные строки и пустые страницы.
// Достижение предела с остатком всегда ошибка, никогда не частичный успех.
const (
	bindingPageSize       = 256
	maxBindingSourcePages = 4096
	maxBindingSourceRows  = 100000
)

// CollectBindings читает только переданный writer и его время после барьеров.
// Членство уже отбирается Groups.List; отдельных IsMember здесь нет.
func CollectBindings(ctx context.Context, w kaname.AuthorityWriter, actor domain.Subject) ([]BindingSource, error) {
	return collectBindings(ctx, w, actor, &sourceBudget{})
}

// Один бюджет может обслуживать несколько классов источников semantic writer.
func collectBindings(ctx context.Context, w kaname.AuthorityWriter, actor domain.Subject, budget *sourceBudget) ([]BindingSource, error) {
	if err := actor.Validate(); err != nil {
		return nil, fmt.Errorf("%w: actor: %v", ErrBindingSourceInvalid, err)
	}
	if (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) || actor.ID == "*" {
		return nil, fmt.Errorf("%w: actor must be a named user or service account", ErrBindingSourceInvalid)
	}
	if w == nil || w.AuthorityFence() == nil {
		return nil, fmt.Errorf("%w: missing fence", ErrBindingSourceInvalid)
	}
	at := w.AuthorityFence().DecisionAt()
	if at.IsZero() {
		return nil, fmt.Errorf("%w: zero decision time", ErrBindingSourceInvalid)
	}
	charge := func(n int) error {
		if !budget.charge(n) {
			return ErrBindingSourceLimit
		}
		return nil
	}
	recipients := []domain.Subject{actor}
	seenRecipients := map[domain.Subject]bool{actor: true}
	token := ""
	seenTokens := map[string]bool{"": true}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !budget.pageAvailable() {
			return nil, ErrBindingSourceLimit
		}
		gs, next, err := w.Groups().List(ctx, group.ListFilter{Member: &actor, PageSize: bindingPageSize, PageToken: token})
		if err != nil {
			return nil, fmt.Errorf("list actor groups: %w", err)
		}
		if err := charge(len(gs)); err != nil {
			return nil, err
		}
		for _, g := range gs {
			s := domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(g.ID)}
			if err := s.Validate(); err != nil {
				return nil, fmt.Errorf("%w: group: %v", ErrBindingSourceInvalid, err)
			}
			if !seenRecipients[s] {
				seenRecipients[s] = true
				recipients = append(recipients, s)
			}
		}
		if next == "" {
			break
		}
		if seenTokens[next] {
			return nil, fmt.Errorf("%w: repeated group token", ErrBindingSourceInvalid)
		}
		seenTokens[next] = true
		token = next
	}
	bindings := make(map[domain.AccessBindingID]domain.AccessBinding)
	carriers := make(map[domain.AccessBindingID][]domain.Subject)
	ids := []domain.AccessBindingID{}
	for _, recipient := range recipients {
		token = ""
		seenTokens = map[string]bool{"": true}
		seenBindings := make(map[domain.AccessBindingID]bool)
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !budget.pageAvailable() {
				return nil, ErrBindingSourceLimit
			}
			bs, next, err := w.AccessBindings().ListBySubject(ctx, recipient.Type, recipient.ID, access_binding.PageFilter{PageSize: bindingPageSize, PageToken: token})
			if err != nil {
				return nil, fmt.Errorf("list binding recipient %v: %w", recipient, err)
			}
			if err := charge(len(bs)); err != nil {
				return nil, err
			}
			for _, b := range bs {
				if b.ID == "" {
					return nil, fmt.Errorf("%w: empty binding id", ErrBindingSourceInvalid)
				}
				if old, ok := bindings[b.ID]; ok {
					if !reflect.DeepEqual(old, b) {
						return nil, fmt.Errorf("%w: conflicting binding %s", ErrBindingSourceInvalid, b.ID)
					}
				} else {
					bindings[b.ID] = b
					ids = append(ids, b.ID)
				}
				if !seenBindings[b.ID] {
					carriers[b.ID] = append(carriers[b.ID], recipient)
					seenBindings[b.ID] = true
				}
			}
			if next == "" {
				break
			}
			if seenTokens[next] {
				return nil, fmt.Errorf("%w: repeated binding token", ErrBindingSourceInvalid)
			}
			seenTokens[next] = true
			token = next
		}
	}
	if len(ids) == 0 {
		return []BindingSource{}, nil
	}
	subjects := make(map[domain.AccessBindingID][]domain.Subject)
	versions := make(map[domain.AccessBindingID]int)
	for start := 0; start < len(ids); start += bindingPageSize {
		end := start + bindingPageSize
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[start:end]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !budget.pageAvailable() {
			return nil, ErrBindingSourceLimit
		}
		ss, err := w.AccessBindings().ListSubjectsForBindings(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("binding subjects: %w", err)
		}
		// Считаются все физически возвращённые строки, включая дубликаты между
		// страницами и metadata. Кэш не превращает чтение в бесплатное.
		subjectRows := 0
		for _, set := range ss {
			if len(set) > maxBindingSourceRows-subjectRows {
				return nil, ErrBindingSourceLimit
			}
			subjectRows += len(set)
		}
		if err := charge(subjectRows); err != nil {
			return nil, err
		}
		if !budget.pageAvailable() {
			return nil, ErrBindingSourceLimit
		}
		vv, err := w.BindingCapabilityVersions(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("binding capability versions: %w", err)
		}
		if err := charge(len(vv)); err != nil {
			return nil, err
		}
		for _, id := range batch {
			s, ok := ss[id]
			if !ok || len(s) == 0 {
				return nil, fmt.Errorf("%w: missing subjects for %s", ErrBindingSourceInvalid, id)
			}
			v, ok := vv[id]
			if !ok || (v != 0 && v != 1) {
				return nil, fmt.Errorf("%w: missing or unknown version for %s", ErrBindingSourceInvalid, id)
			}
			subjects[id] = s
			versions[id] = v
		}
	}
	roles := make(map[domain.RoleID]*domain.Role)
	out := []BindingSource{}
	for _, id := range ids {
		b := bindings[id]
		// Публичная запись требует legacy-пару первой. Для чтения источника БД
		// гарантирует её наличие в наборе, а ordinal не меняет действующие права.
		normalized, err := domain.NormalizeSubjects(subjects[id], "", "")
		if err != nil {
			return nil, fmt.Errorf("%w: binding %s subjects: %v", ErrBindingSourceInvalid, id, err)
		}
		b.Subjects = append([]domain.Subject(nil), normalized...)
		legacyFound := false
		for _, s := range b.Subjects {
			if s.Type == b.SubjectType && s.ID == b.SubjectID {
				legacyFound = true
				break
			}
		}
		if !legacyFound {
			return nil, fmt.Errorf("%w: binding %s lacks legacy recipient", ErrBindingSourceInvalid, id)
		}
		for _, recipient := range carriers[id] {
			found := false
			for _, s := range b.Subjects {
				if s == recipient {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("%w: binding %s lacks queried recipient", ErrBindingSourceInvalid, id)
			}
		}
		if err := b.Validate(); err != nil {
			return nil, fmt.Errorf("%w: binding %s: %v", ErrBindingSourceInvalid, id, err)
		}
		if b.Status != domain.AccessBindingStatusActive || b.RevokedAt != nil || (b.ExpiresAt != nil && !b.ExpiresAt.After(at)) {
			continue
		}
		var r *domain.Role
		if b.RoleID != "" {
			r = roles[b.RoleID]
			if r == nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if !budget.pageAvailable() {
					return nil, ErrBindingSourceLimit
				}
				value, err := w.Roles().Get(ctx, b.RoleID)
				if err != nil {
					return nil, fmt.Errorf("binding role %s: %w", b.RoleID, err)
				}
				if err := charge(1); err != nil {
					return nil, err
				}
				if value.ID != b.RoleID {
					return nil, fmt.Errorf("%w: role id mismatch", ErrBindingSourceInvalid)
				}
				r = &value
				roles[b.RoleID] = r
			}
		}
		for _, recipient := range carriers[id] {
			out = append(out, BindingSource{Binding: b, Role: r, Recipient: recipient, CapabilityVersion: versions[id]})
		}
	}
	return out, nil
}
