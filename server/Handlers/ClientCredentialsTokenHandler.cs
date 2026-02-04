using System.Net.Http.Headers;
using System.Text.Json;

namespace BffMicrosoftEntraID.Server.Handlers;

public class ClientCredentialsTokenHandler : DelegatingHandler
{
    private readonly ITokenCacheService _tokenCache;
    private readonly ILogger<ClientCredentialsTokenHandler> _logger;

    public ClientCredentialsTokenHandler(
        ITokenCacheService tokenCache,
        ILogger<ClientCredentialsTokenHandler> logger)
    {
        _tokenCache = tokenCache;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var token = await _tokenCache.GetOrRefreshTokenAsync(cancellationToken);
        
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}