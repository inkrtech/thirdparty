package oauth

import (
	"errors"
	"github.com/inkrtech/thirdparty/result"
	"github.com/inkrtech/thirdparty/utils"
)

//微博授权登录
type AuthWb struct {
	BaseRequest
}

func NewAuthWb(conf *AuthConfig) *AuthWb {
	authRequest := &AuthWb{}
	authRequest.Set(utils.RegisterSourceWeibo, conf)

	authRequest.authorizeUrl = "https://api.weibo.com/oauth2/authorize"
	authRequest.TokenUrl = "https://api.weibo.com/oauth2/access_token"
	authRequest.userInfoUrl = "https://api.weibo.com/2/users/show.json"

	return authRequest
}

//获取登录地址
func (a *AuthWb) GetRedirectUrl(state string) (*result.CodeResult, error) {
	url := utils.NewUrlBuilder(a.authorizeUrl).
		AddParam("response_type", "code").
		AddParam("client_id", a.config.ClientId).
		AddParam("redirect_uri", a.config.RedirectUrl).
		AddParam("state", a.GetState(state)).
		Build()

	_, err := utils.Post(url)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

//获取token
func (a *AuthWb) GetToken(code string) (*result.TokenResult, error) {
	url := utils.NewUrlBuilder(a.TokenUrl).
		AddParam("grant_type", "authorization_code").
		AddParam("code", code).
		AddParam("client_id", a.config.ClientId).
		AddParam("client_secret", a.config.ClientSecret).
		AddParam("redirect_uri", a.config.RedirectUrl).
		Build()

	body, err := utils.Post(url)
	if err != nil {
		return nil, err
	}
	m := utils.JsonToMSS(body)
	if _, ok := m["error"]; ok {
		return nil, errors.New(m["error_description"])
	}
	token := &result.TokenResult{
		AccessToken:  m["access_token"],
		RefreshToken: m["refresh_token"],
		ExpireIn:     m["expires_in"],
		Scope:        m["scope"],
		TokenType:    m["token_type"],
	}
	return token, nil
}

//获取第三方用户信息
func (a *AuthWb) GetUserInfo(openId string, accessToken string) (*result.UserResult, error) {
	url := utils.NewUrlBuilder(a.TokenUrl).
		AddParam("uid", openId).
		AddParam("access_token", accessToken).
		Build()

	body, err := utils.Get(url)
	if err != nil {
		return nil, err
	}
	m := utils.JsonToMSS(body)
	if _, ok := m["error"]; ok {
		return nil, errors.New(m["error_description"])
	}
	user := &result.UserResult{
		UUID:      m["id"],
		UserName:  m["login"],
		NickName:  m["name"],
		AvatarUrl: m["avatar_url"],
		Company:   m["company"],
		Blog:      m["blog"],
		Location:  m["location"],
		Email:     m["email"],
		Remark:    m["bio"],
		Url:       m["html_url"],
		CreatedAt: m["created_at"],
		UpdatedAt: m["updated_at"],
		Source:    a.registerSource,
		Gender:    utils.GetRealGender("").Desc,
	}
	return user, nil
}
