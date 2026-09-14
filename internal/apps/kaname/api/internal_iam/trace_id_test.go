// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// `CheckRequest.trace_id` объявлен «Trace-id для correlation в логах» и до этой
// правки не читался НИЧЕМ: вызывающий присылал идентификатор, получал отказ и
// имел основание искать по нему свою проверку в записях — а её там не было ни в
// одной. Это «принято-и-проигнорировано» (`api-conventions.md`): успех без
// применения параметра.
//
// # Почему это ещё и РАСХОЖДЕНИЕ ПОЛОС, а не только мёртвое поле
//
// Полос проверки доступа две — публичная (`AuthorizeService.Check`) и внутренняя
// (`InternalIAMService.Check`). Публичная корреляцию НЕСЁТ и локает её своей
// пробой; внутренняя не несла. Обе валидны по отдельности; неверна их РАЗНИЦА,
// и решал её никто (`architecture.md` §«Параллельные полосы одного механизма»).
// Внутренняя полоса при этом дороже: по ней ходит КАЖДЫЙ RPC платформы, и
// именно её отказ разбирают в три часа ночи.
//
// # Где запись делается, а где НЕТ — и это то же решение, что у публичной полосы
//
// Идентификатор попадает в ту запись, которую глагол вообще делает, — на
// недоступности источника вердикта. На успешном пути записи нет и не будет:
// authz-Check стоит на КАЖДОМ RPC, и запись на каждый успешный Check утопила бы
// ту самую корреляцию, ради которой поле существует.
func captureWarnLog(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

// handlerWithUnavailableVerdict — глагол БЕЗ источника вердикта: ровно тот путь,
// на котором запись делается. Дублёров сверх необходимого нет.
func handlerWithUnavailableVerdict(t *testing.T) (*Handler, *bytes.Buffer) {
	t.Helper()
	logger, buf := captureWarnLog(t)
	return NewHandler(nil, &fakeAuthorizer{err: iamerr.ErrUnavailable}).WithLogger(logger), buf
}

func TestInternalCheck_TraceIdReachesTheLog(t *testing.T) {
	t.Parallel()

	h, buf := handlerWithUnavailableVerdict(t)

	_, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:usr_b3n7k1x9q2m5t8",
		Relation:  "viewer",
		Object:    "account:acc_b3n7k1x9q2m5t8",
		TraceId:   "trace-b3n7k1x9-q2m5t8",
	})
	require.Error(t, err, "предпосылка пробы: источник вердикта недоступен, отказ обязателен")
	require.Contains(t, buf.String(), "trace-b3n7k1x9-q2m5t8",
		"корреляционный идентификатор не доехал до записи: поле принято и не применено")
}

// Положительный контроль отрицанию ниже: без него утверждение «чужого
// идентификатора в записи нет» зеленело бы на ПУСТОЙ записи.
func TestInternalCheck_TraceIdIsTruncatedToTheDeclaredLimit(t *testing.T) {
	t.Parallel()

	h, buf := handlerWithUnavailableVerdict(t)

	long := strings.Repeat("x", 100) + "ХВОСТ"
	_, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: "user:usr_b3n7k1x9q2m5t8",
		Relation:  "viewer",
		Object:    "account:acc_b3n7k1x9q2m5t8",
		TraceId:   long,
	})
	require.Error(t, err)
	require.Contains(t, buf.String(), strings.Repeat("x", 64),
		"положительный контроль: обрезанный идентификатор обязан быть в записи")
	require.NotContains(t, buf.String(), "ХВОСТ",
		"объём записи назначает вызывающий: длина не обрезана")
}
