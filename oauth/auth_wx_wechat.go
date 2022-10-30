package oauth

import (
	"errors"
	"github.com/libra82/thirdparty/result"
	"github.com/libra82/thirdparty/utils"
	"strconv"
)

//微信授权登录（第三方应用）
type AuthWxWechat struct {
	BaseRequest
}

func NewAuthWxWechat(conf *AuthConfig) *AuthWxWechat {
	authRequest := &AuthWxWechat{}
	authRequest.Set(utils.RegisterSourceWechat, conf)

	authRequest.authorizeUrl = "https://open.weixin.qq.com/connect/qrconnect"
	authRequest.TokenUrl = "https://api.weixin.qq.com/sns/oauth2/access_token"
	authRequest.userInfoUrl = "https://api.weixin.qq.com/sns/userinfo"

	return authRequest
}

//获取登录地址
func (a *AuthWxWechat) GetRedirectUrl(state string) (*result.CodeResult, error) {
	url := utils.NewUrlBuilder(a.authorizeUrl).
		AddParam("response_type", "code").
		AddParam("appid", a.config.ClientId).
		AddParam("redirect_uri", a.config.RedirectUrl).
		AddParam("scope", "snsapi_login").
		AddParam("state", a.GetState(state)).
		Build()

	_, err := utils.Post(url)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

//获取token
func (a *AuthWxWechat) GetWebAccessToken(code string) (*result.TokenResult, error) {
	url := utils.NewUrlBuilder(a.TokenUrl).
		AddParam("grant_type", "authorization_code").
		AddParam("code", code).
		AddParam("appid", a.config.ClientId).
		AddParam("secret", a.config.ClientSecret).
		AddParam("redirect_uri", a.config.RedirectUrl).
		Build()

	body, err := utils.Post(url)
	if err != nil {
		return nil, err
	}
	m := utils.JsonToMSS(body)
	if _, ok := m["errcode"]; ok {
		return nil, errors.New(m["errmsg"])
	}
	token := &result.TokenResult{
		AccessToken:  m["access_token"],
		RefreshToken: m["refresh_token"],
		ExpireIn:     m["expires_in"],
		OpenId:       m["openid"],
		UnionId:      m["unionid"],
		Scope:        m["scope"],
		TokenType:    m["token_type"],
	}
	if token.AccessToken == "" {
		return nil, errors.New("获取AccessToken数据为空！")
	}
	return token, nil
}

//通过移动应用获取AccessToken
func (a *AuthWxWechat) GetAppAccessToken(code string) (*result.TokenResult, error) {
	url := utils.NewUrlBuilder(a.TokenUrl).
		AddParam("grant_type", "authorization_code").
		AddParam("code", code).
		AddParam("appid", a.config.ClientId).
		AddParam("secret", a.config.ClientSecret).
		Build()

	body, err := utils.Post(url)
	if err != nil {
		return nil, err
	}
	m := utils.JsonToMSS(body)
	if _, ok := m["errcode"]; ok {
		return nil, errors.New(m["errmsg"])
	}
	token := &result.TokenResult{
		AccessToken:  m["access_token"],
		RefreshToken: m["refresh_token"],
		ExpireIn:     m["expires_in"],
		OpenId:       m["openid"],
		UnionId:      m["unionid"],
		Scope:        m["scope"],
		TokenType:    m["token_type"],
	}
	if token.AccessToken == "" {
		return nil, errors.New("获取AccessToken数据为空！")
	}
	return token, nil
}

//获取第三方用户信息
func (a *AuthWxWechat) GetUserInfo(openId string, accessToken string) (*result.UserResult, error) {
	url := utils.NewUrlBuilder(a.userInfoUrl).
		AddParam("openid", openId).
		AddParam("access_token", accessToken).
		Build()

	body, err := utils.Get(url)
	if err != nil {
		return nil, err
	}
	m := utils.JsonToMSS(body)
	if _, ok := m["errcode"]; ok {
		return nil, errors.New(m["errmsg"])
	}
	user := &result.UserResult{
		OpenId:    m["openid"],     //普通用户的标识，对当前开发者帐号唯一
		UnionId:   m["unionid"],    //用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的 unionid 是唯一的。
		UserName:  m["nickname"],   //普通用户昵称
		NickName:  m["nickname"],   //普通用户昵称
		AvatarUrl: m["headimgurl"], //用户头像，最后一个数值代表正方形头像大小（有 0、46、64、96、132 数值可选，0 代表 640*640 正方形头像），用户没有头像时该项为空
		City:      m["city"],       //普通用户个人资料填写的城市
		Province:  m["province"],   //普通用户个人资料填写的省份
		Country:   m["country"],    //国家，如中国为 CN
		Language:  m["language"],
		Source:    a.registerSource,
		Gender:    strconv.Itoa(utils.GetWechatRealGender(m["sex"]).Code), //普通用户性别，1 为男性，2 为女性
	}
	if user.OpenId == "" {
		return nil, errors.New("获取用户信息失败！")
	}
	return user, nil
}
