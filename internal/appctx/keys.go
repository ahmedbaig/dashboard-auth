package appctx

import (
	"github.com/ahmedbaig/dashboard-auth/internal/config"
	"github.com/ahmedbaig/dashboard-auth/internal/constants"
	"github.com/ahmedbaig/dashboard-auth/internal/tokens"
)

func loadKeys(c config.Config) (Keys, error) {
	priv, err := tokens.LoadPrivate(c.App.PrivateKey)
	if err != nil {
		return Keys{}, err
	}
	authPub, err := tokens.LoadPublic(c.Shared.Keys.Auth)
	if err != nil {
		return Keys{}, err
	}
	edgePub, err := tokens.LoadPublic(c.Shared.Keys.Edge)
	if err != nil {
		return Keys{}, err
	}
	return Keys{
		Signer: tokens.NewSigner(priv, constants.IssuerAuth),
		Access: tokens.NewVerifier(constants.IssuerAuth, authPub),
		Edge:   tokens.NewVerifier(constants.IssuerEdge, edgePub),
	}, nil
}
