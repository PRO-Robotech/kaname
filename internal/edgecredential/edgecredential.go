// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edgecredential — ЧЕМ человек звонит, когда его личность передал край
// (kaname#677).
//
// # Зачем
//
// Снятие ключа доступа гасит прочие сессии человека и оставляет текущую (Ф13
// Р8). Вызывающий, предъявивший токен нашей церемонии сам, текущую называет
// выпуском (`callerorigin.CredentialIDFrom`, его кладёт читатель
// предъявленного). Личность, переданная краем, своей текущей сессии не
// называла ничем — и снятие гасило ВСЕ сессии, включая ту, из которой ключ
// сняли. Этот читатель переносит в контекст то, чем текущую называет край:
//
//   - номер записи сессии (`MetaSessionID`) — браузерная сессия: край узнаёт
//     его из ответа `InternalHumanSessionService/Resolve` о носителе;
//   - номер выпуска (`principalwire.MetaTokenJti`) — токен, проверенный краем.
//
// # Канал — тот же, что у личности, и решение о доверии — то же
//
// Значения читаются ТОЛЬКО когда общая пара извлечения платформы
// (`grpcsrv.PrincipalExtractUnary`) признала отправителя вправе говорить за
// человека: собеседник с проверенным сертификатом из перечня доверенных
// отправителей (`authn.trusted-forwarder-sans`), на слушателе без TLS — режим
// разработки, как и для самой личности. Своего решения о доверии здесь нет:
// второе решение разошлось бы с первым молча. Вердикт пары читается
// `grpcsrv.TrustedPrincipalFromContext`.
//
// Сверх доверия — три сужения, каждое на ОДИН факт:
//
//   - личность передана, и это человек (`user`): номер записи — понятие
//     сессии человека, у служебной учётки его не бывает;
//   - личность не названа предъявленным удостоверением: на той полосе выпуск
//     уже положил читатель предъявленного, проверив его сам, и метаданные края
//     его не подменяют;
//   - значение одно и годной формы (`hss-…` у номера записи); два значения или
//     чужая форма — «не названо», а не догадка, какое из них верное.
//
// # Что номер даёт и чего не даёт
//
// Номер записи ничего не аутентифицирует: им нельзя назваться и нельзя продлить
// сессию. Его единственный читатель — снятие ключа, и там он бережёт запись
// только ЕСЛИ это запись самого человека, снимающего свой ключ
// (`access_keys.RevokeInput.ActingSession`). Поддельный номер, попади он сюда,
// может лишь не сберечь чью-то запись — снять или спасти чужую он не может.
//
// # Имя ключа
//
// Оба имени — из каталога фундамента (`principalwire`): номер выпуска —
// `MetaTokenJti`, номер записи — `MetaTokenSessionID` (corelib#97). Край
// ставит то же имя из того же каталога; второе написание разошлось бы с
// первым молча. Приставка `x-kacho-token-` — подсемейство контекста
// проверенного удостоверения, которое край производит сам, снимая клиентские
// значения пространства до выбора полосы, и пропускает за мост.
package edgecredential

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/principalwire"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// MetaSessionID — ключ метаданных номера записи сессии человека, который край
// ставит на каждом запросе, проксируемом за эту сессию. Имя — каталога
// фундамента, не этого пакета (шапка, «Имя ключа»).
const MetaSessionID = principalwire.MetaTokenSessionID

// principalTypeUser — тип личности человека в метаданных края.
const principalTypeUser = "user"

// From — контекст с носителями переданного краем удостоверения. Ничего не
// названо либо отправитель не доверен — контекст возвращается как есть.
func From(ctx context.Context) context.Context {
	if callerorigin.IsPresentedCredential(ctx) {
		return ctx
	}
	p, trusted := grpcsrv.TrustedPrincipalFromContext(ctx)
	if !trusted || p.Type != principalTypeUser || p.ID == "" || p.IsAnonymous() {
		return ctx
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	if v, ok := single(md, MetaSessionID); ok {
		if id, ok := domain.ParseHumanSessionID(v); ok {
			ctx = callerorigin.WithSessionID(ctx, string(id))
		}
	}
	if v, ok := single(md, principalwire.MetaTokenJti); ok {
		ctx = callerorigin.WithCredentialID(ctx, v)
	}
	return ctx
}

// single — ровно одно непустое значение ключа.
func single(md metadata.MD, key string) (string, bool) {
	vs := md.Get(key)
	if len(vs) != 1 || vs[0] == "" {
		return "", false
	}
	return vs[0], true
}

// Unary — перехватчик публичного слушателя; стоит ПОСЛЕ цепочки личности.
func Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(From(ctx), req)
	}
}

// Stream — то же для потоковых вызовов: полоса без читателя при полосе с
// читателем — различие, которого никто не принимал.
func Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &stream{ServerStream: ss, ctx: From(ss.Context())})
	}
}

type stream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *stream) Context() context.Context { return s.ctx }
