// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// invite_mail_queue_writer_injection_test.go — способность гейта единственного
// писателя очереди писем УПАСТЬ, доказанная в обе стороны по КАЖДОЙ форме
// записи, которую он объявляет, с законным близнецом рядом.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const soleWriterFile = "internal/repo/kaname/pg/invite_mail_outbox/outbox.go"

func scanMailQueue(t *testing.T, path, src string) check.InviteMailQueueScan {
	t.Helper()
	got, err := check.ScanInviteMailQueueWrites(path, []byte(src))
	require.NoError(t, err)
	return got
}

func TestInviteMailQueueWriterInjection(t *testing.T) {
	t.Run("законный писатель: списание перед записью — одна запись, списано", func(t *testing.T) {
		got := scanMailQueue(t, soleWriterFile, `package invite_mail_outbox
func EmitTx(ctx, tx, rate, userID, accountID, to, loginURL any) error {
	if err := chargeAddressRate(ctx, tx, rate, to); err != nil { return err }
	return outbox.Emit(ctx, tx, Table, kind, userID, EventSend, nil)
}`)
		require.Len(t, got.Writes, 1)
		require.Equal(t, check.InviteMailQueueSoleWriter, got.Writes[0].Func)
		require.True(t, got.Writes[0].ChargedBefore)
	})

	t.Run("дефект: писатель без списания — найден, не списано", func(t *testing.T) {
		got := scanMailQueue(t, soleWriterFile, `package invite_mail_outbox
func EmitTx(ctx, tx, rate, userID, accountID, to, loginURL any) error {
	return outbox.Emit(ctx, tx, Table, kind, userID, EventSend, nil)
}`)
		require.Len(t, got.Writes, 1)
		require.False(t, got.Writes[0].ChargedBefore)
	})

	t.Run("дефект: списание ПОСЛЕ записи — не засчитано", func(t *testing.T) {
		got := scanMailQueue(t, soleWriterFile, `package invite_mail_outbox
func EmitTx(ctx, tx, rate, userID, accountID, to, loginURL any) error {
	err := outbox.Emit(ctx, tx, Table, kind, userID, EventSend, nil)
	_ = chargeAddressRate(ctx, tx, rate, to)
	return err
}`)
		require.Len(t, got.Writes, 1)
		require.False(t, got.Writes[0].ChargedBefore)
	})

	t.Run("дефект: эмиссия константой пакета очереди из чужого пакета — найдена с координатой", func(t *testing.T) {
		got := scanMailQueue(t, "internal/apps/kaname/api/user/resend.go", `package user
func (uc *X) resend(ctx, tx any) error {
	return outbox.Emit(ctx, tx, invite_mail_outbox.Table, "InviteMail", "usr1", "mail.invite.send", nil)
}`)
		require.Len(t, got.Writes, 1)
		require.Equal(t, "internal/apps/kaname/api/user/resend.go", got.Writes[0].File)
		require.Equal(t, 3, got.Writes[0].Line)
		require.NotEqual(t, check.InviteMailQueueSoleWriter, got.Writes[0].Func)
	})

	t.Run("дефект: эмиссия константой применителя — найдена", func(t *testing.T) {
		got := scanMailQueue(t, "cmd/kaname/x.go", `package main
func f(ctx, tx any) { _ = outbox.Emit(ctx, tx, clients.InviteMailTable, "k", "id", "e", nil) }`)
		require.Len(t, got.Writes, 1)
	})

	t.Run("дефект: эмиссия литералом имени очереди — найдена", func(t *testing.T) {
		got := scanMailQueue(t, "internal/x/x.go", `package x
func f(ctx, tx any) { _ = outbox.Emit(ctx, tx, "kaname.invite_mail_outbox", "k", "id", "e", nil) }`)
		require.Len(t, got.Writes, 1)
	})

	t.Run("дефект: SQL-вставка в очередь — найдена", func(t *testing.T) {
		got := scanMailQueue(t, "internal/x/x.go", "package x\nconst q = `INSERT  INTO\n kaname.invite_mail_outbox (resource_id) VALUES ($1)`\n")
		require.Len(t, got.Writes, 1)
		require.Equal(t, 2, got.Writes[0].Line)
	})

	t.Run("близнец: эмиссия в ЧУЖУЮ очередь — молчит", func(t *testing.T) {
		got := scanMailQueue(t, "internal/x/x.go", `package x
func f(ctx, tx any) { _ = outbox.Emit(ctx, tx, fga_outbox.Table, "k", "id", "e", nil) }`)
		require.Empty(t, got.Writes)
		require.Equal(t, 1, got.Census.EmitCalls, "эмиссия осмотрена, хотя и не в нашу очередь")
	})

	t.Run("близнец: ЧТЕНИЕ очереди и упоминание в комментарии — молчат", func(t *testing.T) {
		got := scanMailQueue(t, "internal/x/x.go", "package x\n// INSERT INTO kaname.invite_mail_outbox — так пишет единственный писатель\n"+
			"const q = `SELECT id FROM kaname.invite_mail_outbox WHERE sent_at IS NULL`\n"+
			"func f(cfg any) { cfg.Table = clients.InviteMailTable }\n")
		require.Empty(t, got.Writes, "читатель очереди, её имя в настройке дренажа и комментарий писателем не являются")
		require.Equal(t, 1, got.Census.SQLLiterals)
	})
}
