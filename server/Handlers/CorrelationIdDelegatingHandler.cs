using BffMicrosoftEntraID.Server.Services;

namespace BffMicrosoftEntraID.Server.Handlers;

public class CorrelationIdDelegatingHandler : DelegatingHandler
{
    private const string CorrelationIdHeaderName = "X-Correlation-Id";
    private readonly ICorrelationIdService _correlationIdService;
    private readonly ILogger<CorrelationIdDelegatingHandler> _logger;

    public CorrelationIdDelegatingHandler(
        ICorrelationIdService correlationIdService,
        ILogger<CorrelationIdDelegatingHandler> logger)
    {
        _correlationIdService = correlationIdService;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        try
        {
            var correlationId = _correlationIdService.GetCorrelationId();

            // Add correlation ID to outgoing request if not already present
            if (!request.Headers.Contains(CorrelationIdHeaderName))
            {
                request.Headers.Add(CorrelationIdHeaderName, correlationId);
                _logger.LogDebug("Added correlation ID {CorrelationId} to outgoing request to {RequestUri}", 
                    correlationId, request.RequestUri);
            }
        }
        catch (InvalidOperationException)
        {
            // Correlation ID not set (shouldn't happen in normal flow)
            _logger.LogWarning("Correlation ID not available for outgoing request to {RequestUri}", request.RequestUri);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}