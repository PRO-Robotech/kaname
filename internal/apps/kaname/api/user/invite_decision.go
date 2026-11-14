// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package user

import (
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"reflect"
)

// API сохраняет публичные имена порта, принадлежащего нейтральному repo слою.
type InviteDecisionIntent = kaname.InviteDecisionIntent
type PreparedInvite = kaname.PreparedInvite
type InviteMutationWriter = kaname.InviteMutationWriter
type InviteDecisionRunner = kaname.InviteDecisionRunner

func (uc *InviteUserUseCase) WithInviteDecisions(r InviteDecisionRunner) *InviteUserUseCase {
	uc.inviteDecisions, uc.inviteDecisionsConfigured = r, true
	return uc
}
func (uc *InviteUserUseCase) validateInviteDecisionSelection() error {
	if !uc.inviteDecisionsConfigured {
		return nil
	}
	if uc.inviteDecisions == nil {
		return iamerr.ErrUnavailable
	}
	v := reflect.ValueOf(uc.inviteDecisions)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		if v.IsNil() {
			return iamerr.ErrUnavailable
		}
	}
	return nil
}
