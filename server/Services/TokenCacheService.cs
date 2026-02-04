using System.Text.Json;

public interface ITokenCacheService
{
    Task<string?> GetOrRefreshTokenAsync(CancellationToken cancellationToken);
}

public class TokenCacheService : ITokenCacheService
{
    private string? _cachedToken;
    private DateTime _tokenExpiration = DateTime.MinValue;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly IConfiguration _configuration;
    private readonly ILogger<TokenCacheService> _logger;

    public TokenCacheService(IConfiguration configuration, ILogger<TokenCacheService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<string?> GetOrRefreshTokenAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_cachedToken) && DateTime.UtcNow < _tokenExpiration.AddMinutes(-5))
        {
            return _cachedToken;
        }

        await _lock.WaitAsync(cancellationToken);
        try
		{
			// Double-check after acquiring lock
			if (!string.IsNullOrEmpty(_cachedToken) && DateTime.UtcNow < _tokenExpiration.AddMinutes(-5))
			{
				return _cachedToken;
			}

			var tenantId = _configuration["DownstreamApi:TenantId"];
			var clientId = _configuration["DownstreamApi:ClientId"];
			var clientSecret = _configuration["DownstreamApi:ClientSecret"];
			var scope = _configuration["DownstreamApi:Scopes:0"];

			if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(clientId) ||
				string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(scope))
			{
				_logger.LogError("Missing required configuration for downstream API token acquisition");
				return null;
			}

			var tokenEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";

			using var tokenClient = new HttpClient();
			var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
			{
				Content = new FormUrlEncodedContent(new Dictionary<string, string>
				{
					["grant_type"] = "client_credentials",
					["client_id"] = clientId,
					["client_secret"] = clientSecret,
					["scope"] = scope
				})
			};

			var tokenResponse = await tokenClient.SendAsync(tokenRequest, cancellationToken);
			if (!tokenResponse.IsSuccessStatusCode)
			{
				var errorContent = await tokenResponse.Content.ReadAsStringAsync(cancellationToken);
				_logger.LogError("Token acquisition failed: {StatusCode} - {Error}",
					tokenResponse.StatusCode, errorContent);
				return null;
			}

			var tokenJson = await tokenResponse.Content.ReadAsStringAsync(cancellationToken);
			var tokenDoc = JsonDocument.Parse(tokenJson);

			_cachedToken = tokenDoc.RootElement.GetProperty("access_token").GetString();

			// Get expiration (typically 3600 seconds)
			if (tokenDoc.RootElement.TryGetProperty("expires_in", out var expiresIn))
			{
				_tokenExpiration = DateTime.UtcNow.AddSeconds(expiresIn.GetInt32());
			}

			_logger.LogInformation("Successfully acquired access token, expires at {Expiration}", _tokenExpiration);
			return _cachedToken;
		}
		finally
        {
            _lock.Release();
        }
    }
}