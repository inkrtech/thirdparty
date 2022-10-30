package main

import (
	"fmt"
	"github.com/libra82/thirdparty/oauth"
)

func main() {
	//wxConf := &oauth.AuthConfig{ClientId: "xxx", ClientSecret: "xxx", RedirectUrl: "http://www.geiqin.com"}
	//
	//wxAuth := oauth.NewAuthWxWechat(wxConf)
	//
	//fmt.Print(wxAuth.GetRedirectUrl("sate")) //获取第三方登录地址
	//
	//wxRes, err := wxAuth.GetAppAccessToken("code")
	//
	//userInfo, _ := wxAuth.GetUserInfo(wxRes.AccessToken, wxRes.OpenId)
	//
	//log.Println("ssss:", err, userInfo)

	qqConf := &oauth.AuthConfig{ClientId: "xxx", ClientSecret: "xxxxxx", RedirectUrl: ""}
	qqAuth := oauth.NewAuthQq((qqConf))
	fmt.Println(qqAuth.GetOpenUnionId("F8A2D7F2DD4954457266769B648C43aa"))
}
