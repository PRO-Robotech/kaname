// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Замкнутый snapshot-аналог GetMirrorObject/GetIAMDirectObject. Каждая строка
// источника сохраняется отдельно с версией, включая полный bounded перечень
// memberships личности. SQL ARRAY-подзапрос без лимита здесь не используется.
func (p *resourceParentCapture) captureObjectProjection(ctx context.Context, typ, id string) (domain.MirrorObject, bool, error) {
	var out domain.MirrorObject
	if p == nil || p.source == nil || p.source.sealed || !nativeQuestionToken(typ) || !nativeQuestionToken(id) {
		return out, false, kaname.ErrSourceUnconfirmed
	}
	kind := resourceSourceMirror
	if domain.FeedSourceForType(typ) == domain.FeedIAMDirect {
		kind = resourceSourceIAMObject
	}
	rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: kind, typ: typ, id: id})
	if err != nil {
		return out, false, err
	}
	if len(rows) == 0 {
		return out, false, nil
	}
	if len(rows) != 1 {
		return out, false, kaname.ErrSourceUnconfirmed
	}
	var row struct {
		ID            string            `json:"id"`
		ObjectType    string            `json:"object_type"`
		ObjectID      string            `json:"object_id"`
		Account       string            `json:"account_id"`
		Project       string            `json:"project_id"`
		ParentAccount string            `json:"parent_account_id"`
		ParentProject string            `json:"parent_project_id"`
		ResourceType  string            `json:"resource_type"`
		ResourceID    string            `json:"resource_id"`
		CreatorType   string            `json:"created_by_type"`
		CreatorID     string            `json:"created_by_id"`
		Labels        map[string]string `json:"labels"`
		AccessLabels  map[string]string `json:"access_labels"`
	}
	if err = json.Unmarshal(rows[0].value, &row); err != nil {
		return out, false, err
	}
	out = domain.MirrorObject{ObjectType: typ, ObjectID: id, Labels: row.Labels}
	if len(row.AccessLabels) != 0 {
		out.AccessLabels = row.AccessLabels
	}
	account, project := "", ""
	if kind == resourceSourceMirror {
		if row.ObjectType != typ || row.ObjectID != id {
			return domain.MirrorObject{}, false, kaname.ErrSourceUnconfirmed
		}
		account, project = row.ParentAccount, row.ParentProject
	} else {
		if row.ID != id {
			return domain.MirrorObject{}, false, kaname.ErrSourceUnconfirmed
		}
		switch typ {
		case "iam.project":
			account, project = row.Account, row.ID
		case "iam.account":
			account = row.ID
		case "iam.role":
			account, project = row.Account, row.Project
		case "iam.group", "iam.serviceAccount":
			account = row.Account
		case "iam.accessBinding":
			switch row.ResourceType {
			case "account":
				account = row.ResourceID
			case "project":
				project = row.ResourceID
			case "cluster":
			default:
				return domain.MirrorObject{}, false, kaname.ErrSourceUnconfirmed
			}
		case "iam.user":
			memberships, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceUserMemberships, typ: typ, id: id})
			if err != nil {
				return domain.MirrorObject{}, false, err
			}
			seen := map[string]bool{}
			for _, captured := range memberships {
				var member struct {
					User    string `json:"user_id"`
					Account string `json:"account_id"`
				}
				if err = json.Unmarshal(captured.value, &member); err != nil {
					return domain.MirrorObject{}, false, err
				}
				if member.User != id {
					return domain.MirrorObject{}, false, kaname.ErrSourceUnconfirmed
				}
				if member.Account != "" && !seen[member.Account] {
					if !nativeQuestionToken(member.Account) {
						return domain.MirrorObject{}, false, kaname.ErrSourceUnconfirmed
					}
					seen[member.Account] = true
					out.ParentAccountIDs = append(out.ParentAccountIDs, member.Account)
				}
			}
			slices.Sort(out.ParentAccountIDs)
		default:
			return domain.MirrorObject{}, false, kaname.ErrSourceUnconfirmed
		}
		if typ == "iam.serviceAccount" && row.CreatorType != "" && row.CreatorID != "" {
			out.CreatedBy = row.CreatorType + ":" + row.CreatorID
		}
	}
	if project != "" {
		if !nativeQuestionToken(project) {
			return domain.MirrorObject{}, false, kaname.ErrSourceUnconfirmed
		}
		// Даже при явном account исходная SQL projection содержит LEFT JOIN проекта.
		// Capture сохраняет этот nullable источник, не выдумывая его существование.
		scope, err := p.project(ctx, project)
		if err != nil {
			return domain.MirrorObject{}, false, err
		}
		if account == "" && scope.Registered {
			account = scope.AccountID
		}
	}
	out.ParentProjectID = project
	if account != "" {
		if !nativeQuestionToken(account) {
			return domain.MirrorObject{}, false, kaname.ErrSourceUnconfirmed
		}
		out.ParentAccountIDs = []string{account}
	}
	return out, true, nil
}
