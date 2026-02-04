using Microsoft.AspNetCore.Antiforgery;

namespace BlazorBffOpenIDConnect.Server.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UserController : ControllerBase
{
    private readonly IAntiforgery _antiforgery;

    public UserController(IAntiforgery antiforgery)
    {
        _antiforgery = antiforgery;
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult GetCurrentUser()
    {
        // Regenerate XSRF token on each call to ensure it matches current user identity
        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
        Response.Cookies.Append("XSRF-RequestToken", tokens.RequestToken ?? "",
            new CookieOptions { HttpOnly = false, IsEssential = true, Secure = true, SameSite = SameSiteMode.Strict });
        
        return Ok(CreateUserInfo(User));
    }

    private static UserInfo CreateUserInfo(ClaimsPrincipal claimsPrincipal)
    {
        if (claimsPrincipal == null || claimsPrincipal.Identity == null 
            || !claimsPrincipal.Identity.IsAuthenticated)
        {
            return UserInfo.Anonymous;
        }

        var userInfo = new UserInfo
        {
            IsAuthenticated = true
        };

        if (claimsPrincipal.Identity is ClaimsIdentity claimsIdentity)
        {
            userInfo.NameClaimType = claimsIdentity.NameClaimType;
            userInfo.RoleClaimType = claimsIdentity.RoleClaimType;
        }
        else
        {
            userInfo.NameClaimType = ClaimTypes.Name;
            userInfo.RoleClaimType = ClaimTypes.Role;
        }

        if (claimsPrincipal.Claims?.Any() ?? false)
        {
            var claims = claimsPrincipal.Claims.Select(u => new ClaimValue(u.Type, u.Value))
                                                  .ToList();

            userInfo.Claims = claims;
        }

        return userInfo;
    }
}
