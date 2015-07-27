using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace AuthorizationServer.Controllers
{
    public class OAuthController : Controller
    {
        public ActionResult Authorize()
        {
            // 如果 RedirectUrl 驗證錯誤的話，這裡會是 400
            if (Response.StatusCode != 200)
            {
                return View("AuthorizeError");
            }

            var authentication = HttpContext.GetOwinContext().Authentication;

            // 注意：這裡的 Application Type 要跟 StartUp 裡面的一樣
            var ticket = authentication.AuthenticateAsync("Application").Result;
            var identity = ticket != null ? ticket.Identity : null;
            if (identity == null)
            {
                // 先看 user 是否已經驗證通過（是否登入），如果沒有則跳轉到 LoginPath
                // 注意：這裡的 Application Type 要跟 StartUp 裡面的一樣，否則無法跳轉到 LoginPath 
                authentication.Challenge("Application");
                return new HttpUnauthorizedResult();
            }

            if (Request.HttpMethod == "POST")
            {
                // 同意授權
                if (!string.IsNullOrEmpty(Request.Form.Get("submit.Grant")))
                {
                    // 注意：這裏的AuthenticationType 需要為 "Bearer"，這是告訴 OAuth 生成 Token 的關鍵。

                    // 重新構造了 Identity，最後再進行SignIn
                    // 此時會執行 AuthorizationCodeProvider OnCreate 的實作方法
                    // 生成 Code 後會 Redirect 回 Client 的 RedirectUrl
                    // Client 再拿著 Code 來換 Token
                    // 也就是執行 AuthorizationCodeProvider OnReceive 的實作方法

                    identity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);

                    // 取得 user 傳入的 scope
                    var scopes = (Request.QueryString.Get("scope") ?? "").Split(' ');

                    foreach (var scope in scopes)
                    {
                        identity.AddClaim(new Claim("urn:oauth:scope", scope));
                    }

                    authentication.SignIn(identity);
                }

                // 切換 user 登入
                if (!string.IsNullOrEmpty(Request.Form.Get("submit.Login")))
                {
                    authentication.SignOut("Application");
                    authentication.Challenge("Application");
                    return new HttpUnauthorizedResult();
                }
            }

            return View();
        }
    }
}