namespace BffMicrosoftEntraID.Server.Services
{
	public class DownstreamApiService
	{
		private readonly IHttpClientFactory _httpClientFactory;
		private readonly ILogger<DownstreamApiService> _logger;
		private readonly IHttpContextAccessor _httpContextAccessor;
		private readonly ICorrelationIdService _correlationIdService;

		public DownstreamApiService(
			IHttpClientFactory httpClientFactory,
			ILogger<DownstreamApiService> logger,
			IHttpContextAccessor httpContextAccessor,
			ICorrelationIdService correlationIdService)
		{
			_httpClientFactory = httpClientFactory;
			_logger = logger;
			_httpContextAccessor = httpContextAccessor;
			_correlationIdService = correlationIdService;
		}

		public async Task<WeatherForecastWithInfo> GetWeatherForecastAsync()
		{
			var httpClient = _httpClientFactory.CreateClient("DownstreamApi");
			var correlationId = _correlationIdService.GetCorrelationId();

			try
			{
				var response = await httpClient.GetAsync("weatherforecast");
				response.EnsureSuccessStatusCode();

				var forecasts = await response.Content.ReadFromJsonAsync<WeatherForecastWithInfo>();

				_logger.LogInformation("Successfully retrieved weather forecast. CorrelationId: {CorrelationId}", correlationId);

				return forecasts ?? new WeatherForecastWithInfo();
			}
			catch (HttpRequestException ex)
			{
				_logger.LogError(ex, "Failed to get weather forecast from downstream API. CorrelationId: {CorrelationId}", correlationId);
				throw;
			}
		}
	}

	public class WeatherForecast
	{
		public DateOnly Date { get; set; }
		public int TemperatureC { get; set; }
		public string? Summary { get; set; }
		public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
	}

	public class WeatherForecastWithInfo
	{
		public string? Upn { get; set; }
		public DateTime RequestTime { get; set; }
		public string? RequestCorrelationId { get; set; }
		public WeatherForecast[]? Forecasts { get; set; }
	}
}
