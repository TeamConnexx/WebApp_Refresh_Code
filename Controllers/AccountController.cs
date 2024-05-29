using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using SampleMvcApp.ViewModels;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using Auth0.AspNetCore.Authentication;
using RestSharp;

namespace SampleMvcApp.Controllers
{
    public class AccountController : Controller
    {
        public string RefreshToken { get; set; }
        public async Task Login(string returnUrl = "/")
        {
            var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
                .WithScope("openid offline_access delete_tokens profile email api_access")
                .WithRedirectUri(returnUrl)
                .Build();

            await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);

        }

        public async Task GetToken(string returnUrl = "/")
        {
            //var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
            //    .WithRedirectUri(returnUrl)
            //    .WithParameter("prompt","none")
            //    .Build();
            //var res = 
            //await HttpContext.AuthenticateAsync();
            //Thread.Sleep(4000);
            await System.IO.File.WriteAllTextAsync(@"D:\VAOS\RefreshToken.txt", RefreshToken);
        }

        [Authorize]
        public async Task Logout()
        {
            var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                // Indicate here where Auth0 should redirect the user after a logout.
                // Note that the resulting absolute Uri must be whitelisted in 
                .WithRedirectUri(Url.Action("Index", "Home"))
                .Build();

            await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        [Authorize]
        public async Task<IActionResult> Profile()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            var idToken = await HttpContext.GetTokenAsync("id_token");
            RefreshToken = await HttpContext.GetTokenAsync("refresh_token");

            GetToken();

            return View(new UserProfileViewModel()
            {
                Name = User.Identity.Name,
                EmailAddress = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
                ProfileImage = User.Claims.FirstOrDefault(c => c.Type == "picture")?.Value
            });
        }


        /// <summary>
        /// This is just a helper action to enable you to easily see all claims related to a user. It helps when debugging your
        /// application to see the in claims populated from the Auth0 ID Token
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public IActionResult Claims()
        {
            GetToken();
            return View();
        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
