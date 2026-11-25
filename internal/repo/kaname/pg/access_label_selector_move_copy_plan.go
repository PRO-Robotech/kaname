// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type accessLabelMoveCopyProposal struct {
	Type          string                            `json:"root_type"`
	ID            string                            `json:"root_id"`
	Physical      json.RawMessage                   `json:"physical,omitempty"`
	NewLabels     map[string]string                 `json:"new_access_labels"`
	ProjectSource *accessLabelMoveProjectCopySource `json:"project_source,omitempty"`
}

type accessLabelMoveProjectCopySource struct {
	MirrorPhysical json.RawMessage `json:"mirror_physical"`
	Definition     bool            `json:"definition"`
}

// Пакет до финальных часов покрывает все возможные копии. Для каждой
// координаты передаём полный снимок физической строки, а не проекцию модели.
func (p *resourceParentCapture) captureAccessLabelMoveCopyPlan(
	ctx context.Context, overlay map[domain.ResourceRef]domain.MirrorObject, definition bool,
) (json.RawMessage, error) {
	if p == nil || p.source == nil || p.source.budget == nil || p.source.sealed {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var buffer bytes.Buffer
	buffer.WriteByte('[')
	for i, ref := range sortedRefs(slices.Collect(maps.Keys(overlay))) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		object := overlay[ref]
		if object.ObjectType != ref.Type || object.ObjectID != ref.ID || !nativeQuestionToken(ref.Type) ||
			!nativeQuestionToken(ref.ID) || len(object.AccessLabels) == 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if err := chargeNativePolicyBudget(p.source.budget, 1+len(object.AccessLabels), 0); err != nil {
			return nil, err
		}
		kind := resourceSourceMirror
		if domain.FeedSourceForType(ref.Type) == domain.FeedIAMDirect {
			kind = resourceSourceIAMObject
		}
		rows := p.source.entries[resourceSourceKey{kind: kind, typ: ref.Type, id: ref.ID}]
		if len(rows) != 1 || len(rows[0].state) == 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if len(rows[0].state) > granteffect.MaxInputBytes-buffer.Len() {
			return nil, kaname.ErrSourceReadLimit
		}
		proposal := accessLabelMoveCopyProposal{
			Type: ref.Type, ID: ref.ID, Physical: json.RawMessage(rows[0].state), NewLabels: object.AccessLabels,
		}
		if ref.Type == domain.ScopeTypeProjectDotted {
			remainingBytes := granteffect.MaxInputBytes - buffer.Len() - len(rows[0].state)
			projectSource, err := p.accessLabelMoveProjectCopySource(ref, rows[0].value, object.AccessLabels, definition, remainingBytes)
			if err != nil {
				return nil, err
			}
			proposal.ProjectSource = projectSource
		}
		entry, err := json.Marshal(proposal)
		if err != nil {
			return nil, err
		}
		if len(entry)+2 > granteffect.MaxInputBytes-buffer.Len() {
			return nil, kaname.ErrSourceReadLimit
		}
		if i != 0 {
			buffer.WriteByte(',')
		}
		buffer.Write(entry)
	}
	buffer.WriteByte(']')
	return buffer.Bytes(), ctx.Err()
}

// Передаём точный снимок зеркала только для ненативной пары. Позиции
// правил и подходящие привязки выводит владелец БД из удержанного OLD.
func (p *resourceParentCapture) accessLabelMoveProjectCopySource(
	ref domain.ResourceRef, native json.RawMessage, proposed map[string]string, definition bool, remainingBytes int,
) (*accessLabelMoveProjectCopySource, error) {
	var project struct {
		ID           string            `json:"id"`
		Labels       map[string]string `json:"labels"`
		AccessLabels map[string]string `json:"access_labels"`
	}
	if json.Unmarshal(native, &project) != nil || project.ID != ref.ID {
		return nil, kaname.ErrSourceUnconfirmed
	}
	for key, value := range proposed {
		if _, exists := project.AccessLabels[key]; exists {
			continue
		}
		if ordinary, exists := project.Labels[key]; exists && ordinary == value {
			continue
		}
		mirror := p.source.entries[resourceSourceKey{kind: resourceSourceMirror, typ: ref.Type, id: ref.ID}]
		if len(mirror) != 1 || len(mirror[0].state) == 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if len(mirror[0].state) > remainingBytes {
			return nil, kaname.ErrSourceReadLimit
		}
		return &accessLabelMoveProjectCopySource{
			MirrorPhysical: json.RawMessage(mirror[0].state), Definition: definition,
		}, nil
	}
	return nil, nil
}
