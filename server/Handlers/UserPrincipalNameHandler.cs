namespace BffMicrosoftEntraID.Server.Handlers;

public class UserPrincipalNameHandler : DelegatingHandler
{
    private const string UpnHeaderName = "upn";
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<UserPrincipalNameHandler> _logger;

    public UserPrincipalNameHandler(
        IHttpContextAccessor httpContextAccessor,
        ILogger<UserPrincipalNameHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // Get the user's UPN from claims
        var upn = _httpContextAccessor.HttpContext?.User?.FindFirst("upn")?.Value;

        if (!string.IsNullOrEmpty(upn))
        {
            // Add UPN header to outgoing request if not already present
            if (!request.Headers.Contains(UpnHeaderName))
            {
                request.Headers.Add(UpnHeaderName, upn);
                _logger.LogDebug("Added UPN header: {Upn} to outgoing request to {RequestUri}", 
                    upn, request.RequestUri);
            }
        }
        else
        {
            _logger.LogWarning("UPN claim not found for user. Request to {RequestUri}", request.RequestUri);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}