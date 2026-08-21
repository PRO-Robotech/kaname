// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytokenwire

import (
	"context"
	"fmt"
	"time"

	registrytokenuc "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho/services/iam/internal/tokensigner"
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
	tok, err := a.signer.Sign(ctx, tokensigner.Request{
		Subject:   in.Subject,
		Audience:  []string{in.Audience},
		TokenType: registryTokenType,
		TTL:       a.ttl,
		Claims:    claims,
	})
	if err != nil {
		return registrytokenuc.MintOutput{}, err
	}
	return registrytokenuc.MintOutput{
		AccessToken: tok.Token,
		ExpiresIn:   int(time.Until(tok.ExpiresAt).Seconds()),
	}, nil
}
