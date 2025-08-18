package result

// 令牌结果
type TokenResult struct {
	AccessToken    string `json:"accessToken"`
	ExpireIn       string `json:"expireIn"`
	RefreshToken   string `json:"refreshToken"`
	Uid            string `json:"uid"`
	OpenId         string `json:"openId"`
	AccessCode     string `json:"accessCode"`
	UnionId        string `json:"unionId"`
	IsSnapshotUser string `json:"is_snapshotuser"` //是否为快照页模式虚拟账号，只有当用户是快照页模式虚拟账号时返回，值为1

	// google
	Scope     string `json:"scope"`
	TokenType string `json:"tokenType"`
	IdToken   string `json:"idToken"`

	// mi
	MacAlgorithm string `json:"macAlgorithm"`
	MacKey       string `json:"macKey"`

	// wechat
	Code       string `json:"code"`
	SessionKey string `json:"sessionKey"`

	// twitter
	OauthToken             string `json:"oauthToken"`
	OauthTokenSecret       string `json:"oauthTokenSecret"`
	UserId                 string `json:"userId"`
	ScreenName             string `json:"screenName"`
	OauthCallbackConfirmed bool   `json:"oauthCallbackConfirmed"`
}
