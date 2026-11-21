// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Только историческая метаинформация аудита очистки. Отсутствие актуального
// parent graph не запрещает снять ранее сохранённую регистрацию. Этот результат
// не используется для admission новой регистрации или доказательства полномочий.
func (c *resourceParentCapture) auditHierarchy(ctx context.Context, anchor string) (domain.ParentHierarchy, bool, error) {
	typ, id, ok := strings.Cut(anchor, ":")
	if !ok || !nativeQuestionToken(typ) || !nativeQuestionToken(id) {
		return domain.ParentHierarchy{}, false, kaname.ErrSourceUnconfirmed
	}
	if typ == "project" {
		scope, err := c.project(ctx, id)
		if err != nil || !scope.Registered {
			return domain.ParentHierarchy{}, false, err
		}
		return domain.ProjectHierarchy(id, scope.AccountID), true, nil
	}
	mirror, found, err := c.mirror(ctx, typ, id)
	if err != nil || !found {
		return domain.ParentHierarchy{}, false, err
	}
	project := mirror.Project
	if project == "" {
		project, err = c.chainProject(ctx, typ, id)
		if err != nil {
			return domain.ParentHierarchy{}, false, err
		}
	}
	scope := domain.ContainerScope{Registered: true, ProjectID: project}
	if project != "" {
		owner, err := c.project(ctx, project)
		if err != nil {
			return domain.ParentHierarchy{}, false, err
		}
		scope.AccountID = owner.AccountID
	}
	return domain.ContainerHierarchy(anchor, scope), true, nil
}
