namespace BffMicrosoftEntraID.Server.Controllers;

[ValidateAntiForgeryToken]
[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
[ApiController]
[Route("api/[controller]")]
public class WeatherApiController : ControllerBase
{
    private readonly DownstreamApiService _apiService;
    private readonly ICorrelationIdService _correlationIdService;
    private readonly ILogger<WeatherApiController> _logger;

    public WeatherApiController(
		DownstreamApiService apiService, 
		ICorrelationIdService correlationIdService,
		ILogger<WeatherApiController> logger)
    {
        _apiService = apiService;
        _correlationIdService = correlationIdService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> Get()
    {
	    _correlationIdService.SetCorrelationId(Guid.NewGuid().ToString());

	    try
        {
            var weatherData = await _apiService.GetWeatherForecastAsync();

            return Ok(weatherData);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Failed to retrieve weather forecast from downstream API");
            return StatusCode(StatusCodes.Status502BadGateway, "Failed to retrieve data from downstream service");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred while getting weather forecast");
            return StatusCode(StatusCodes.Status500InternalServerError, "An unexpected error occurred");
        }
    }
}
