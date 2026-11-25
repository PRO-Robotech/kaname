// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Координата member не обязана совпадать с Tuple.Object: container/scope_self
// и retained ledger могут удерживать fact другого объекта. Обе TTL-ветви
// требуют его полного holder census до entry. Это не добавляет materialization
// candidates: прочитанные holders участвуют только в SOURCE/OUTPUT защите.
func (p *resourceObjectPreparation) captureFoldOutputs(ctx context.Context, parents *resourceParentCapture) error {
	if p == nil || p.effects == nil || parents == nil || parents.source != p.source || p.source.sealed {
		return kaname.ErrSourceUnconfirmed
	}
	seen := make(map[domain.ResourceRef]bool, len(p.outputs))
	for _, out := range p.outputs {
		if out == nil {
			return kaname.ErrSourceUnconfirmed
		}
		seen[out.object] = true
	}
	addOutput := func(cat resourceCatalogRow, coordinate domain.ResourceRef) error {
		if seen[coordinate] {
			return nil
		}
		out, err := captureResourceOutput(ctx, parents, cat, coordinate.ID)
		if err != nil {
			return err
		}
		p.outputs = append(p.outputs, out)
		seen[coordinate] = true
		return nil
	}
	for _, root := range p.generation.externalRoots {
		capture, err := parents.catalog(ctx, root.Type)
		if err != nil {
			return err
		}
		cat, ok := capture.selected()
		if !ok || len(capture.rows) != 1 || cat.identity.Dotted != root.Type {
			return kaname.ErrSourceUnconfirmed
		}
		// Даже пустой пересчёт должен сохранить родительскую цепь и привязку
		// к проекту, включая доказательство отсутствия этих строк.
		for _, kind := range []resourceSourceKind{resourceSourceParentEdges, resourceSourceProjectBinding} {
			if _, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: kind, typ: cat.identity.ObjectType, id: root.ID}); err != nil {
				return err
			}
		}
		// OLD scopes сохраняют все проекты lifecycle, включая уже удалённые.
		// Читаем их K1 в том же RR до seal; владельца scope не переопределяем.
		rows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: cat.identity.ObjectType, id: root.ID})
		if err != nil {
			return err
		}
		scopes, err := resourceDecodeRows[struct {
			Project string `json:"project_id"`
		}](rows)
		if err != nil {
			return err
		}
		projects := make(map[string]bool, len(scopes))
		for _, scope := range scopes {
			if scope.Project == "" {
				continue
			}
			if !nativeQuestionToken(scope.Project) {
				return kaname.ErrSourceUnconfirmed
			}
			projects[scope.Project] = true
		}
		for _, project := range resourceSortedSet(projects) {
			if _, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceProject, typ: "project", id: project}); err != nil {
				return err
			}
		}
		if err := addOutput(cat, root); err != nil {
			return err
		}
	}
	refs := make(map[string]bool, len(p.generation.outputRefs))
	// Факты поколения тоже требуют полной защиты выходных графов,
	// даже когда штатный пересчёт не подготовил для них запись или удаление.
	for _, ref := range p.generation.outputRefs {
		refs[ref] = true
	}
	for _, binding := range p.effects.Bindings {
		for _, commands := range [][]reconcile.BindingCommand{binding.Live, binding.Expired} {
			for _, command := range commands {
				if command.Kind != "write" && command.Kind != "delete" {
					continue
				}
				for _, tuple := range command.Tuples {
					if err := p.source.budget.Charge(1, 0); err != nil {
						return err
					}
					if _, _, ok := resourceFoldCoordinate(tuple.Object); !ok {
						return kaname.ErrSourceUnconfirmed
					}
					refs[tuple.Object] = true
				}
			}
		}
	}
	for _, ref := range resourceSortedSet(refs) {
		typ, id, _ := resourceFoldCoordinate(ref)
		capture, err := parents.catalog(ctx, typ)
		if err != nil {
			return err
		}
		cat, ok := capture.selected()
		if !ok || cat.identity.ObjectType != typ {
			return kaname.ErrSourceUnconfirmed
		}
		for _, row := range capture.rows {
			if row.identity.Dotted != cat.identity.Dotted || row.identity.ObjectType != typ {
				return kaname.ErrSourceUnconfirmed
			}
		}
		coordinate := domain.ResourceRef{Type: cat.identity.Dotted, ID: id}
		if err := addOutput(cat, coordinate); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func resourceFoldCoordinate(ref string) (string, string, bool) {
	typ, id, ok := strings.Cut(ref, ":")
	return typ, id, ok && nativeQuestionToken(typ) && nativeQuestionToken(id) && !strings.Contains(typ, ".") && !strings.Contains(id, ":")
}
