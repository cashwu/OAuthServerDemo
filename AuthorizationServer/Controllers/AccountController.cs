using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace AuthorizationServer.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login()
        {
            if (Request.HttpMethod == "POST")
            {
                if (!string.IsNullOrEmpty(Request.Form.Get("submit.Signin")))
                {
                    // 單純把畫面上的 user name 寫入 cookie 
                    var claim = new Claim(ClaimsIdentity.DefaultNameClaimType, Request.Form["username"]);

                    // 注意：這裡的 Application Type (第二個參數) 要跟 StartUp 裡面的一樣
                    var claimsIdentity = new ClaimsIdentity(new[] { claim }, "Application" );

                    // 最後再調用SignIn方法, 然後再 redirect 到 AuthorizeEndpointPath
                    var authentication = HttpContext.GetOwinContext().Authentication;
                    authentication.SignIn(claimsIdentity);
                }
            }

            return View();
        }

        public ActionResult Logout()
        {
            return View();
        }
    }
}