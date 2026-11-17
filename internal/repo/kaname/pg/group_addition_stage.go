// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	groupport "github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
)

// Запрос содержит только исходную команду. Строки, разрешения, ID sequence и
// trigger origin выводит владелец БД; клиент их не передаёт.
type groupAdditionStage struct {
	member         domain.GroupMember
	request        []byte
	referenceValid bool
	stamp          time.Time
}

func prepareGroupAdditionStage(ctx context.Context, w *authorityWriteTx, plan *policyPlan, member domain.GroupMember) (*groupAdditionStage, error) {
	if w == nil || plan == nil || plan.nativeBudget == nil || member.Validate() != nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	raw, err := json.Marshal(map[string]string{"group_id": string(member.GroupID), "member_type": string(member.MemberType), "member_id": string(member.MemberID)})
	if err != nil {
		return nil, err
	}
	var encoded []byte
	if err = w.tx.QueryRow(ctx, `SELECT kaname.authority_group_add_prepare_v3($1::jsonb,$2,$3)`, raw,
		plan.nativeBudget.RemainingRows(), plan.nativeBudget.RemainingReads()).Scan(&encoded); err != nil {
		return nil, err
	}
	var cost struct {
		Rows  int `json:"rows"`
		Reads int `json:"reads"`
	}
	if err = json.Unmarshal(encoded, &cost); err != nil {
		return nil, err
	}
	if err = chargeNativePolicyBudget(plan.nativeBudget, cost.Rows, cost.Reads); err != nil {
		return nil, err
	}
	return &groupAdditionStage{member: member, request: raw}, nil
}

func (s *groupAdditionStage) finalize(ctx context.Context, w *authorityWriteTx, plan *policyPlan) error {
	if s == nil || w == nil || plan == nil || plan.nativeBudget == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	var rows, reads int
	if err := w.tx.QueryRow(ctx, `SELECT reference_valid,added_at,logical_rows,logical_reads FROM kaname.authority_group_add_finalize_v3($1::jsonb,$2,$3)`,
		s.request, plan.nativeBudget.RemainingRows(), plan.nativeBudget.RemainingReads()).Scan(&s.referenceValid, &s.stamp, &rows, &reads); err != nil {
		return err
	}
	if err := chargeNativePolicyBudget(plan.nativeBudget, rows, reads); err != nil {
		return err
	}
	if s.stamp.IsZero() || !s.stamp.Equal(w.fence.decisionAt) {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return ctx.Err()
}

type preparedGroupAdditionWriter struct {
	*semanticAuthorityWriteTx
	stage *groupAdditionStage
}

func (w *preparedGroupAdditionWriter) GroupsW() groupport.WriterIface {
	return &preparedGroupAdditionRows{WriterIface: w.semanticAuthorityWriteTx.GroupsW(), owner: w}
}

type preparedGroupAdditionRows struct {
	groupport.WriterIface
	owner *preparedGroupAdditionWriter
}

func (w *preparedGroupAdditionRows) exact(member domain.GroupMember) (*groupAdditionStage, error) {
	if w.owner == nil || w.owner.stage == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	s := w.owner.stage
	if member.GroupID != s.member.GroupID || member.MemberType != s.member.MemberType || member.MemberID != s.member.MemberID ||
		!member.AddedAt.Equal(s.member.AddedAt) || s.stamp.IsZero() {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	return s, nil
}

func (w *preparedGroupAdditionRows) RequireMemberOfGroupAccount(ctx context.Context, member domain.GroupMember) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := w.exact(member)
	if err != nil {
		return err
	}
	// Отказ остаётся в исходном теле ПОСЛЕ RequireGroupAddition. Владелец уже
	// получил нужные locks; здесь не выполняется поздний SELECT FOR SHARE.
	if !s.referenceValid {
		return iamerr.Wrapf(iamerr.ErrReferenceMissing, "%s", referenceMissingText)
	}
	return nil
}

func (w *preparedGroupAdditionRows) AddMember(ctx context.Context, member domain.GroupMember) error {
	if err := w.RequireMemberOfGroupAccount(ctx, member); err != nil {
		return err
	}
	raw, ok := w.WriterIface.(*groupWriter)
	if !ok {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	// Это время уже связано владельцем БД с exact NEW и выбранными эффектами.
	// Декоратор не заменяет независимую проверку nonce/origin/consumption в БД.
	return raw.addMemberAt(ctx, member, w.owner.stage.stamp)
}

// Закрытый Add-порт не предоставляет другой тип изменения той же группы.
func (*preparedGroupAdditionRows) Insert(context.Context, domain.Group) (domain.Group, error) {
	return domain.Group{}, kaname.ErrInvalidAuthorityFencePlan
}
func (*preparedGroupAdditionRows) Update(context.Context, domain.Group, []string) (domain.Group, error) {
	return domain.Group{}, kaname.ErrInvalidAuthorityFencePlan
}
func (*preparedGroupAdditionRows) Delete(context.Context, domain.GroupID) error {
	return kaname.ErrInvalidAuthorityFencePlan
}
func (*preparedGroupAdditionRows) RemoveMember(context.Context, domain.GroupID, domain.SubjectType, domain.SubjectID) error {
	return kaname.ErrInvalidAuthorityFencePlan
}

var _ kaname.SemanticAuthorityWriter = (*preparedGroupAdditionWriter)(nil)
var _ groupport.WriterIface = (*preparedGroupAdditionRows)(nil)
