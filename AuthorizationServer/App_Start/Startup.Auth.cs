using Constants;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace AuthorizationServer
{
    public partial class Startup
    {

        public void ConfigureAuth(IAppBuilder app)
        {
            // 應用程式使用 Cookie 儲存已登入使用者的資訊
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                // AuthenticationType 是用戶登陸 Authorization Server 後的登陸憑證的標記名，簡單理解為 cookie 的 key
                // 這和 OAuth/Authorize 中檢查用戶當前是否已登陸有關系
                AuthenticationType = "Application",

                // 若為 Active，authentication middleware 修改用戶進來的 reqeust 以 401 Unauthorized responses 回應
                // 若為 Passive，authentication middleware 當 AuthenticationType 明確表示時，僅會提供 identity 和 修改 responses
                AuthenticationMode = AuthenticationMode.Active,
                LoginPath = new PathString(Paths.LoginPath),
                LogoutPath = new PathString(Paths.LogoutPath),
            });

            // 設置 Authorization Server
            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                // client 端應用程式將用戶瀏覽器重新導向到用戶同意發出 token 的 path，必須以 "/" 開頭， 例如： /Authorize
                AuthorizeEndpointPath = new PathString(Paths.AuthorizePath),

                // client 端應用程式可以直接訪問並得到 assert token 的地址， 必須以 "/" 開頭，例如： /Token
                // 不用實作這個 path
                TokenEndpointPath = new PathString(Paths.TokenPath),

                // 如果希望在 /Authorize 這個地址顯示自定義錯誤信息，則設置為 true
                // 只有當瀏覽器不能重新導向到 client 端時才需要(比如 client_id 和 redirect_uri 不正確時)
                // /Authorize 可以透過增加到 OWIN 環境的 oauth.Error、oauth.ErrorDescription 和 oauth.ErrorUri 屬性來顯示錯誤
                // 如果設置為 false，client 瀏覽器將會被重導向到預設的錯誤頁面
                // 簡單的來說是錯誤是 Server 處理還是 Client 處理
                ApplicationCanDisplayErrors = true,

#if DEBUG
                // 如果允許 client 端的 return_uri 參數不是 HTTPS 地址， 則設置為 true
                // 當設置為false時，若登記的 Client 端重導向的 url 未使用https，則不重導向
                AllowInsecureHttp = true,
#endif
                // Authorization Server 的生命週期
                Provider = new OAuthAuthorizationServerProvider
                {
                    // 驗證 Client 的 redirect url
                    OnValidateClientRedirectUri = ValidateClientRedirectUri,

                    // 驗證 Client 的身份（ClientId 和 ClientSecret）
                    OnValidateClientAuthentication = ValidateClientAuthentication
                },

                // 建立和接收 authorization code

                // 提供返回給 client 而且基於安全性考量只能使用一次的 token
                // OnCreate/OnCreateAsync 生成的 token 只能在 OnReceive/OnReceiveAsync 使用一次
                // => 產生單次使用的授權碼 給 client 端使用
                AuthorizationCodeProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateAuthenticationCode,
                    OnReceive = ReceiveAuthenticationCode,
                },

                // 建立和接收 refresh token
                RefreshTokenProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateRefreshToken,
                    OnReceive = ReceiveRefreshToken,
                }
            });
        }

        /// <summary>
        /// 驗證RedirectUri身份，原則上 Client 只要有向 AuthorizationServer 發出請求就會先跑這裡
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            // context.ClientId 是 OAuth2 處理流程 context 中獲取的 ClientId

            // 如果我們有 Client的注冊機制，那麼 Clients.Client1.Id 對應的 Clients.Client1.RedirectUrl 就可能是從數據庫中讀取的。
            // 而數據庫中讀取的 RedirectUrl 則可以直接作為字符串參數傳給 context.Validated(RedirectUrl)
            if (context.ClientId == Clients.Client1.Id)
            {
                context.Validated(Clients.Client1.RedirectUrl);
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// 驗證Client身份
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // TryGetBasicCredentials 是指 Client 可以按照 Basic 身份驗證的規則提交 ClientId 和 ClientSecret

            // Basic簡單說明下就是添加如下的一個Http Header：
            // Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== 
            // Basic 後面部分是 ClientId:ClientSecret 形式的字符串進行Base64編碼後的字符串，
            // Authorization 是Http Header 的鍵名，Basic至最後是該Header的值。Form 這種只要注意兩個鍵名是 client_id 和 client_secret 。
            string clientId;
            string clientSecret;
            if (context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                // 驗證 client id 和 secret
                // 如果檢查錯誤的話，不會跑 ReceiveRefreshToken、CreateRefreshToken
                if (clientId == Clients.Client1.Id && clientSecret == Clients.Client1.Secret)
                {
                    context.Validated();
                }
            }
            return Task.FromResult(0);
        }

        /// <summary>
        ///  這裡將 identity ticket 和 restore identity ticket 存在 ConcurrentDictionary (記憶體) 
        ///  實務上應該存在 persistent data store	
        /// </summary>
        private readonly ConcurrentDictionary<string, string> authenticationCodes =
            new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        /// <summary>
        /// 建立 Authentication Code
        /// </summary>
        /// <param name="context"></param>
        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            // client 端的 AuthCode;
            context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
            
            
            authenticationCodes[context.Token] = context.SerializeTicket();
        }

        /// <summary>
        /// 接收 Authentication Code
        /// </summary>
        /// <param name="context"></param>
        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            string value;

            // 使用 TryRemove 驗證一次(取出)後即刪除了
            if (authenticationCodes.TryRemove(context.Token, out value))
            {
                context.DeserializeTicket(value);
            }
        }

        /// <summary>
        /// 建立 Refresh Token
        /// </summary>
        /// <param name="context"></param>
        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            context.SetToken(context.SerializeTicket());
        }

        /// <summary>
        /// 接收 Refresh Token
        /// </summary>
        /// <param name="context"></param>
        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            // 如果檢查錯誤的話，不會跑 CreateRefreshToken
            context.DeserializeTicket(context.Token);
        }
    }
}