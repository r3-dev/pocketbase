package auth

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/pocketbase/pocketbase/tools/types"
	"golang.org/x/oauth2"
)

var _ Provider = (*DonationAlerts)(nil)

// NameDonationAlerts is the unique name of the Donation Alerts provider.
const NameDonationAlerts string = "donationalerts"

// Donation Alerts  allows authentication via Discord OAuth2.
type DonationAlerts struct {
	*baseProvider
}

// NewDiscordProvider creates a new Discord provider instance with some defaults.
func NewDonationAlertsProvider() *DonationAlerts {
	// https://www.donationalerts.com/apidoc#authorization
	return &DonationAlerts{&baseProvider{
		ctx:         context.Background(),
		displayName: "Donation Alerts",
		pkce:        true,
		scopes:      []string{"oauth-user-show"},
		authUrl:     "https://www.donationalerts.com/oauth/authorize",
		tokenUrl:    "https://www.donationalerts.com/oauth/token",
		userApiUrl:  "https://www.donationalerts.com/api/v1/user/oauth",
	}}
}

// FetchAuthUser returns an AuthUser instance from Discord's user api.
//
// API reference:  https://discord.com/developers/docs/resources/user#user-object
func (p *DonationAlerts) FetchAuthUser(token *oauth2.Token) (*AuthUser, error) {
	data, err := p.FetchRawUserData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err := json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Data struct {
			Id          int    `json:"id"`
			UniqueName  string `json:"code"`
			Name        string `json:"name"`
			Avatar      string `json:"avatar"`
			Email       string `json:"email"`
			SocketToken string `json:"socket_connection_token"`
		} `json:"data"`
	}{}
	if err := json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &AuthUser{
		Id:           strconv.Itoa(extracted.Data.Id),
		Name:         extracted.Data.UniqueName,
		Username:     extracted.Data.Name,
		AvatarUrl:    extracted.Data.Avatar,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	user.Expiry, _ = types.ParseDateTime(token.Expiry)

	return user, nil
}
