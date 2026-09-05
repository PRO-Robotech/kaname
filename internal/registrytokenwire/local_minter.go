// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registrytokenwire

import (
	"context"
	"fmt"
	"time"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
)

// LocalMintAdapter — НАШ подписант с точки зрения контура выдачи докер-токена.
//
// Тонкий переходник без политики: срок берётся настройкой контура, субъект и
// адресат приходят от use-case, а всё, что делает токен токеном — обязательные
// `kid`, срок, тип, издатель, — проставляет подписант.
type LocalMintAdapter struct {
	signer *tokensigner.Signer
	ttl    time.Duration
}

// NewLocalMinter — построитель.
func NewLocalMinter(s *tokensigner.Signer, ttl time.Duration) *LocalMintAdapter {
	return &LocalMintAdapter{signer: s, ttl: ttl}
}

var _ registrytokenuc.LocalMinter = (*LocalMintAdapter)(nil)

// registryTokenType — объявленный тип токена этого контура.
//
// Тип ТРЕБУЕТСЯ приёмной стороной, а не «желателен»: токен без объявленного
// типа отвергается, и производитель типа обязан существовать, иначе проверка
// не может упасть ни на чём.
const registryTokenType = "at+jwt"

// MintToken выпускает токен контура.
func (a *LocalMintAdapter) MintToken(ctx context.Context, in registrytokenuc.MintInput) (registrytokenuc.MintOutput, error) {
	if in.Audience == "" {
		// Незаданный адресат означал бы «любой», а токен, годный любому
		// контуру, — это путаница адресатов, появляющаяся ровно тогда, когда
		// один подписант обслуживает два контура.
		return registrytokenuc.MintOutput{}, fmt.Errorf("registry token: audience is required")
	}
	claims := map[string]any{}
	if in.Scope != "" {
		claims["scope"] = in.Scope
	}
	req := tokensigner.Request{
		Subject:   in.Subject,
		Audience:  []string{in.Audience},
		TokenType: registryTokenType,
		TTL:       a.ttl,
		Claims:    claims,
	}
	// Привязка токена к ключу владельца (Ф1б, задача #926).
	//
	// Материал берётся ИЗ ПРЕДЪЯВЛЕННОГО при выдаче и никогда не выдумывается:
	// переходник его только переносит. Не предъявлен ⇒ указатель остаётся nil, и
	// токен выходит предъявительским — привязка не появляется там, где её не
	// просили.
	//
	// До этой провязки у возможности не было НИ ОДНОГО производственного
	// вызывающего: подписант умел проставлять привязку, а входа, которым её
	// можно было бы попросить, в контуре не существовало. Возможность без
	// вызывающего неотличима от исправной — запись в неё удаётся.
	if in.HasConfirmation() {
		req.Confirmation = &tokensigner.Confirmation{
			X5TS256: in.ConfirmationX5TS256,
			JKT:     in.ConfirmationJKT,
		}
	}
	tok, err := a.signer.Sign(ctx, req)
	if err != nil {
		return registrytokenuc.MintOutput{}, err
	}
	return registrytokenuc.MintOutput{
		AccessToken: tok.Token,
		ExpiresIn:   int(time.Until(tok.ExpiresAt).Seconds()),
	}, nil
}
