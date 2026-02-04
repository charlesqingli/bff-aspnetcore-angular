using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;

namespace BffMicrosoftEntraID.Server;

/// <summary>
/// Cookie authentication events that automatically refresh access tokens using refresh tokens
/// </summary>
public class TokenRefreshCookieEvents : CookieAuthenticationEvents
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptionsMonitor<OpenIdConnectOptions> _oidcOptions;
    private readonly ILogger<TokenRefreshCookieEvents> _logger;

    // Refresh tokens when they have less than this time remaining
    private static readonly TimeSpan TokenRefreshThreshold = TimeSpan.FromMinutes(5);

    public TokenRefreshCookieEvents(
        IHttpClientFactory httpClientFactory,
        IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
        ILogger<TokenRefreshCookieEvents> logger)
    {
        _httpClientFactory = httpClientFactory;
        _oidcOptions = oidcOptions;
        _logger = logger;
    }

    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var tokens = context.Properties.GetTokens().ToList();
        if (!tokens.Any())
        {
            return;
        }

        var expiresAtToken = tokens.FirstOrDefault(t => t.Name == "expires_at");
        if (expiresAtToken == null)
        {
            return;
        }

        if (!DateTimeOffset.TryParse(expiresAtToken.Value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var expiresAt))
        {
            return;
        }

        // Check if token needs refresh
        var timeRemaining = expiresAt - DateTimeOffset.UtcNow;
        if (timeRemaining > TokenRefreshThreshold)
        {
            // Token still valid, no refresh needed
            return;
        }

        var refreshToken = tokens.FirstOrDefault(t => t.Name == "refresh_token")?.Value;
        if (string.IsNullOrEmpty(refreshToken))
        {
            _logger.LogWarning("Access token expired but no refresh token available. User will need to re-authenticate.");
            context.RejectPrincipal();
            return;
        }

        try
        {
            var newTokens = await RefreshTokensAsync(refreshToken, context.HttpContext.RequestAborted);
            if (newTokens != null)
            {
                UpdateTokens(context, tokens, newTokens);
                context.ShouldRenew = true;
                _logger.LogInformation("Successfully refreshed access token");
            }
            else
            {
                _logger.LogWarning("Failed to refresh tokens. User will need to re-authenticate.");
                context.RejectPrincipal();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing tokens");
            context.RejectPrincipal();
        }
    }

    private async Task<TokenResponse?> RefreshTokensAsync(string refreshToken, CancellationToken cancellationToken)
    {
        var oidcOptions = _oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);
        var configuration = await oidcOptions.ConfigurationManager!.GetConfigurationAsync(cancellationToken);
        var tokenEndpoint = configuration.TokenEndpoint;

        if (string.IsNullOrEmpty(tokenEndpoint))
        {
            _logger.LogError("Token endpoint not found in OIDC configuration");
            return null;
        }

        var httpClient = _httpClientFactory.CreateClient();

        var parameters = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = oidcOptions.ClientId!,
            ["client_secret"] = oidcOptions.ClientSecret!
        };

        var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(parameters)
        };

        var response = await httpClient.SendAsync(request, cancellationToken);
        
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogWarning("Token refresh failed: {StatusCode} - {Error}", response.StatusCode, error);
            return null;
        }

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        return JsonSerializer.Deserialize<TokenResponse>(content);
    }

    private static void UpdateTokens(CookieValidatePrincipalContext context, List<AuthenticationToken> tokens, TokenResponse newTokens)
    {
        // Update access token
        var accessToken = tokens.FirstOrDefault(t => t.Name == "access_token");
        if (accessToken != null && !string.IsNullOrEmpty(newTokens.AccessToken))
        {
            accessToken.Value = newTokens.AccessToken;
        }

        // Update refresh token (if a new one was provided)
        if (!string.IsNullOrEmpty(newTokens.RefreshToken))
        {
            var refreshToken = tokens.FirstOrDefault(t => t.Name == "refresh_token");
            if (refreshToken != null)
            {
                refreshToken.Value = newTokens.RefreshToken;
            }
        }

        // Update ID token (if a new one was provided)
        if (!string.IsNullOrEmpty(newTokens.IdToken))
        {
            var idToken = tokens.FirstOrDefault(t => t.Name == "id_token");
            if (idToken != null)
            {
                idToken.Value = newTokens.IdToken;
            }
        }

        // Update expiry time
        var expiresAt = tokens.FirstOrDefault(t => t.Name == "expires_at");
        if (expiresAt != null && newTokens.ExpiresIn > 0)
        {
            var newExpiresAt = DateTimeOffset.UtcNow.AddSeconds(newTokens.ExpiresIn);
            expiresAt.Value = newExpiresAt.ToString("o", CultureInfo.InvariantCulture);
        }

        context.Properties.StoreTokens(tokens);
    }

    private class TokenResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("id_token")]
        public string? IdToken { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("token_type")]
        public string? TokenType { get; set; }
    }
}
