package grants

import (
	"context"
	"log/slog"

	"github.com/dexidp/dex/server/connectors"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

// clientCredentials serves the client_credentials grant: a confidential client
// obtains tokens for itself, with no user involved.
type clientCredentials struct {
	issuer *tokens.Issuer
	logger *slog.Logger
}

func (g *clientCredentials) GrantType() string {
	return oauth2.GrantTypeClientCredentials
}

func (g *clientCredentials) RequiresClientAuth() bool {
	return true
}

var clientCredentialsScopePolicy = ScopePolicy{
	Standard: map[string]bool{
		tokens.ScopeOpenID:  true,
		tokens.ScopeEmail:   true,
		tokens.ScopeProfile: true,
		tokens.ScopeGroups:  true,
	},
	Rejected: map[string]string{
		tokens.ScopeOfflineAccess: "client_credentials grant does not support offline_access scope.",
		tokens.ScopeFederatedID:   "client_credentials grant does not support federated:id scope.",
	},
	ErrorType: oauth2.InvalidScope,
}

func (g *clientCredentials) ScopePolicy() ScopePolicy {
	return clientCredentialsScopePolicy
}

func (g *clientCredentials) ConnectorID(ctx context.Context, req *Request, client storage.Client) (string, *oauth2.Error) {
	return "", nil
}

func (g *clientCredentials) Authorize(ctx context.Context, req *Request, client storage.Client, conn connectors.Connector) (Responder, error) {
	// Build claims from the client itself — no user involved.
	claims := storage.Claims{
		UserID:            client.ID,
		Username:          client.Name,
		PreferredUsername:  client.Name,
	}
	for _, scope := range req.Scopes {
		switch scope {
		case tokens.ScopeGroups:
			if client.ClientCredentialsClaims != nil {
				claims.Groups = client.ClientCredentialsClaims.Groups
			}
		}
	}

	auth := tokens.Authorization{
		Client: client,
		Claims: claims,
		Scopes: req.Scopes,
		ConnectorID: "client",
		Nonce:       req.Nonce,
	}
	return issueTokens(ctx, g.logger, g.issuer, auth, "", false)
}
