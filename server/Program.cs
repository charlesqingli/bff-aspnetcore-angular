using BffMicrosoftEntraID.Server;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using NetEscapades.AspNetCore.SecurityHeaders.Infrastructure;
using System.Security.Claims;
using System.Text.Json;
using BffMicrosoftEntraID.Server.Handlers;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.AddServerHeader = false;
});

builder.Services.AddOpenApi();

var services = builder.Services;
var configuration = builder.Configuration;

services.AddSecurityHeaderPolicies()
    .SetPolicySelector(ctx =>
    {
        if (ctx.HttpContext.Request.Path.StartsWithSegments("/api"))
        {
            return ApiSecurityHeadersDefinitions.GetHeaderPolicyCollection(builder.Environment.IsDevelopment());
        }

        return SecurityHeadersDefinitions.GetHeaderPolicyCollection(
            builder.Environment.IsDevelopment(),
            configuration["oidc:Authority"]);
    });

// services.AddScoped<MsGraphService>();
// services.AddScoped<CaeClaimsChallengeService>();

services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.Name = "__Host-X-XSRF-TOKEN";
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

services.AddHttpClient();
services.AddOptions();

// Register token refresh cookie events for automatic token refresh
services.AddScoped<TokenRefreshCookieEvents>();

services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "__bff-host-auth";
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.EventsType = typeof(TokenRefreshCookieEvents);
})
.AddOpenIdConnect(options =>
{
    configuration.Bind("Oidc", options);

    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true;
    options.SaveTokens = true;

    // Configure logout
    options.SignedOutRedirectUri = "/";
    options.RemoteSignOutPath = "/signout-oidc";

    // Explicitly set metadata address to ensure discovery works
    options.MetadataAddress = $"{configuration["Oidc:Authority"]}/.well-known/openid-configuration";

    // Don't refresh the configuration automatically to avoid race conditions
    options.RefreshOnIssuerKeyNotFound = false;

    // In development, accept self-signed certificates for the OIDC provider
    if (builder.Environment.IsDevelopment())
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        options.BackchannelHttpHandler = handler;
    }

	// Map standard claims
	options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "name",
        RoleClaimType = "role"
    };

    //Call userinfo endpoint after authentication to get additional claims
     options.Events = new OpenIdConnectEvents
     {
         OnTokenValidated = async context =>
         {
             var accessToken = context.TokenEndpointResponse?.AccessToken;
             if (string.IsNullOrEmpty(accessToken))
             {
                 return;
             }

             var httpClient = context.HttpContext.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();
             httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

             var userInfoEndpoint = context.Options.Configuration?.UserInfoEndpoint ?? configuration["Oidc:UserInfoEndpoint"];

             var userInfoResponse = await httpClient.GetAsync(userInfoEndpoint);
             if (userInfoResponse.IsSuccessStatusCode)
             {
                 var userInfoJson = await userInfoResponse.Content.ReadAsStringAsync();
                 var userInfo = JsonDocument.Parse(userInfoJson);

                 var identity = context.Principal?.Identity as ClaimsIdentity;
                 if (identity != null)
                 {
                     foreach (var element in userInfo.RootElement.EnumerateObject())
                     {
                         var claimType = element.Name;

                         // Skip claims that are already present (e.g., sub, iss)
                         if (identity.HasClaim(c => c.Type == claimType))
                         {
                             continue;
                         }

                         // Handle array values (e.g., roles, groups)
                         if (element.Value.ValueKind == JsonValueKind.Array)
                         {
                             foreach (var item in element.Value.EnumerateArray())
                             {
                                 identity.AddClaim(new Claim(claimType, item.ToString()));
                             }
                         }
                         else
                         {
                             identity.AddClaim(new Claim(claimType, element.Value.ToString()));
                         }
                     }
                 }
             }
         }
     };
});

services.AddControllersWithViews(options =>
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

services.AddRazorPages().AddMvcOptions(options =>
{
	//var policy = new AuthorizationPolicyBuilder()
	//    .RequireAuthenticatedUser()
	//    .Build();
	//options.Filters.Add(new AuthorizeFilter(policy));
});

var reverseProxyBuilder = services.AddReverseProxy()
        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

if (builder.Environment.IsDevelopment())
{
    reverseProxyBuilder.ConfigureHttpClient((context, handler) =>
    {
        handler.SslOptions.RemoteCertificateValidationCallback = 
            (sender, certificate, chain, sslPolicyErrors) => true;
    });
}

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICorrelationIdService, CorrelationIdService>();
builder.Services.AddSingleton<ITokenCacheService, TokenCacheService>();

// 3. Register all delegating handlers as TRANSIENT (new instance per HttpClient)
builder.Services.AddTransient<CorrelationIdDelegatingHandler>();
builder.Services.AddTransient<UserPrincipalNameHandler>();
builder.Services.AddTransient<ClientCredentialsTokenHandler>();

// Register HttpClient with ALL handlers in the correct order
builder.Services.AddHttpClient("DownstreamApi", client =>
	{
		client.BaseAddress = new Uri(builder.Configuration["DownstreamApi:BaseUrl"]!);
	})
.AddHttpMessageHandler<CorrelationIdDelegatingHandler>()  // 1. Add correlation ID
.AddHttpMessageHandler<UserPrincipalNameHandler>()         // 2. Add UPN header
.AddHttpMessageHandler<ClientCredentialsTokenHandler>();     // 3. Add client credentials handler


// 5. Register DownstreamApiService
builder.Services.AddScoped<DownstreamApiService>();


var app = builder.Build();

// Warm up the OIDC configuration to ensure discovery document is cached at startup
// This prevents issues with logout not working immediately after login
//using (var scope = app.Services.CreateScope())
//{
//    var options = scope.ServiceProvider
//        .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
//        .Get(OpenIdConnectDefaults.AuthenticationScheme);
    
//    try
//    {
//        // Force fetching the configuration at startup
//        var configManager = options.ConfigurationManager;
//        if (configManager != null)
//        {
//            _ = configManager.GetConfigurationAsync(CancellationToken.None).GetAwaiter().GetResult();
//        }
//    }
//    catch (Exception ex)
//    {
//        Console.WriteLine($"Warning: Failed to pre-fetch OIDC configuration: {ex.Message}");
//    }
//}

if (app.Environment.IsDevelopment())
{
    IdentityModelEventSource.ShowPII = true;

    app.UseDeveloperExceptionPage();
    app.UseWebAssemblyDebugging();
    app.MapOpenApi();
}
else
{
    app.UseExceptionHandler("/Error");
}

app.UseSecurityHeaders();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();
app.MapNotFound("/api/{**segment}");

if (app.Environment.IsDevelopment())
{
    var uiDevServer = app.Configuration.GetValue<string>("UiDevServerUrl");
    if (!string.IsNullOrEmpty(uiDevServer))
    {
        app.MapReverseProxy();
    }
}

app.MapFallbackToPage("/_Host");

app.Run();
