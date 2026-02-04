# How the Downstream API Is Called in This Application

This document explains how the BFF calls the downstream API: configuration, HttpClient pipeline, handlers, and request flow.

---

## Table of Contents

- [End-to-End Flow](#end-to-end-flow)
  - [Security boundaries in this flow](#security-boundaries-in-this-flow)
- [Configuration](#configuration)
- [HttpClient and Handler Chain](#httpclient-and-handler-chain)
- [Controller: Entry Point and Correlation ID](#controller-entry-point-and-correlation-id)
- [DownstreamApiService: Named Client and URL](#downstreamapiservice-named-client-and-url)
- [Handler 1: Correlation ID](#handler-1-correlation-id)
- [Handler 2: User Identity (UPN)](#handler-2-user-identity-upn)
- [Handler 3: Bearer Token (Client Credentials)](#handler-3-bearer-token-client-credentials)
- [Request Sent to the Downstream API](#request-sent-to-the-downstream-api)
- [Response and Error Handling](#response-and-error-handling)
- [Summary](#summary)

---

## End-to-End Flow

The browser only talks to the BFF. The BFF then calls the downstream API with a server-side HTTP client.

```mermaid
sequenceDiagram
    box "Security boundary: Client (untrusted)" #f9f9f9
    participant Browser
    end

    box "Security boundary: BFF (trusted)" #e8f5e9
    participant Controller as WeatherApiController
    participant Service as DownstreamApiService
    participant H1 as CorrelationIdHandler
    participant H2 as UserPrincipalNameHandler
    participant H3 as ClientCredentialsTokenHandler
    end

    box "Security boundary: Downstream API (trusted, separate)" #e3f2fd
    participant API as Downstream API
    end

    Browser->>Controller: GET /api/WeatherApi with cookie and XSRF
    Controller->>Controller: Set correlation ID
    Controller->>Service: GetWeatherForecastAsync

    Service->>Service: CreateClient DownstreamApi
    Service->>H1: GET weatherforecast

    H1->>H1: Add X-Correlation-Id header
    H1->>H2: Pass request
    H2->>H2: Add upn header from User
    H2->>H3: Pass request
    H3->>H3: Get or refresh client_credentials token
    H3->>H3: Add Authorization Bearer header
    H3->>API: GET BaseUrl/weatherforecast

    API->>H3: 200 JSON
    H3->>H2: Pass response
    H2->>H1: Pass response
    H1->>Service: Pass response
    Service->>Controller: WeatherForecastWithInfo
    Controller->>Browser: 200 OK with weather data
```

### Security boundaries in this flow

| Boundary | What’s inside | Trust | What crosses the boundary |
|----------|----------------|--------|----------------------------|
| **Client** | Browser (Angular SPA) | Untrusted | All input is validated. Requests must include valid auth cookie and XSRF token. |
| **BFF** | ASP.NET Core app (controllers, services, handlers) | Trusted | Auth and XSRF are enforced at the BFF edge. Outgoing calls add correlation ID, UPN, and client-credentials Bearer token. |
| **Downstream API** | External weather API | Trusted, separate | Only server-side BFF calls it. No browser access. Identity is BFF’s client credentials plus optional UPN header. |

The important division is **client vs. BFF**: the browser never sees tokens or talks to the downstream API; only the BFF does. The BFF is the single trust boundary the browser crosses; everything beyond the BFF is server-to-server.

---

## Configuration

**File:** `server/appsettings.json`

```json
"DownstreamApi": {
  "BaseUrl": "https://...azurewebsites.net/",
  "TenantId": "559c89ed-813e-45e4-bb8e-6fab398ac08b",
  "ClientId": "85f1bddc-1824-4c68-9f29-f7a44474ec86",
  "ClientSecret": "...",
  "Scopes": [ "api://87a6bdbc-9a70-4845-a222-12efa431dd09/.default" ]
}
```

| Setting | Purpose |
|--------|---------|
| **BaseUrl** | Root URL of the downstream API. Relative paths (e.g. weatherforecast) are appended to this. |
| **TenantId** | Azure AD tenant used for client_credentials token. |
| **ClientId** | App registration client ID for the BFF when calling the downstream API. |
| **ClientSecret** | Client secret for that app registration. |
| **Scopes** | OAuth2 scope for the downstream API (e.g. api://.../.default). |

---

## HttpClient and Handler Chain

**File:** `server/Program.cs`

```csharp
builder.Services.AddHttpClient("DownstreamApi", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["DownstreamApi:BaseUrl"]!);
})
.AddHttpMessageHandler<CorrelationIdDelegatingHandler>()   // 1
.AddHttpMessageHandler<UserPrincipalNameHandler>()         // 2
.AddHttpMessageHandler<ClientCredentialsTokenHandler>();   // 3
```

Outgoing request order:

1. **CorrelationIdDelegatingHandler** – adds **X-Correlation-Id** (from ICorrelationIdService).
2. **UserPrincipalNameHandler** – adds **upn** from HttpContext.User (auth cookie).
3. **ClientCredentialsTokenHandler** – gets or caches a token and adds **Authorization: Bearer**.

So every call to the downstream API gets: correlation id, user identity (UPN), and machine-to-machine auth (Bearer).

```mermaid
graph LR
    A[DownstreamApiService] --> B[CreateClient DownstreamApi]
    B --> C[CorrelationIdHandler]
    C --> D[UserPrincipalNameHandler]
    D --> E[ClientCredentialsTokenHandler]
    E --> F[HttpClient]
    F --> G[Downstream API]
```

---

## Controller: Entry Point and Correlation ID

**File:** `server/Controllers/WeatherApiController.cs`

```csharp
[ValidateAntiForgeryToken]
[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
[ApiController]
[Route("api/[controller]")]
public class WeatherApiController : ControllerBase
{
    private readonly DownstreamApiService _apiService;
    private readonly ICorrelationIdService _correlationIdService;

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
            return StatusCode(502, "Failed to retrieve data from downstream service");
        }
        // ...
    }
}
```

- Incoming request is already authenticated (cookie) and validated for XSRF.
- A new **correlation ID** is set for this request so the handler can add it to the downstream call.
- The controller delegates the actual HTTP call to **DownstreamApiService** and returns the result (or 502 on downstream failure).

---

## DownstreamApiService: Named Client and URL

**File:** `server/Services/DownstreamApiService.cs`

```csharp
public async Task<WeatherForecastWithInfo> GetWeatherForecastAsync()
{
    var httpClient = _httpClientFactory.CreateClient("DownstreamApi");
    var correlationId = _correlationIdService.GetCorrelationId();

    var response = await httpClient.GetAsync("weatherforecast");
    response.EnsureSuccessStatusCode();

    var forecasts = await response.Content.ReadFromJsonAsync<WeatherForecastWithInfo>();
    return forecasts ?? new WeatherForecastWithInfo();
}
```

- **CreateClient("DownstreamApi")** – uses the configured BaseUrl and the three handlers above.
- **GetAsync("weatherforecast")** – request goes to **{BaseUrl}weatherforecast**.
- Response is deserialized to **WeatherForecastWithInfo** (Upn, RequestTime, RequestCorrelationId, Forecasts).

---

## Handler 1: Correlation ID

**File:** `server/Handlers/CorrelationIdDelegatingHandler.cs`

```csharp
var correlationId = _correlationIdService.GetCorrelationId();
if (!request.Headers.Contains(CorrelationIdHeaderName))
{
    request.Headers.Add(CorrelationIdHeaderName, correlationId);  // X-Correlation-Id
}
return await base.SendAsync(request, cancellationToken);
```

- **ICorrelationIdService** is scoped; the value was set in **WeatherApiController.Get()**.
- The same correlation ID is sent to the downstream API so logs and traces can be tied together.

---

## Handler 2: User Identity (UPN)

**File:** `server/Handlers/UserPrincipalNameHandler.cs`

```csharp
var upn = _httpContextAccessor.HttpContext?.User?.FindFirst("upn")?.Value;
if (!string.IsNullOrEmpty(upn))
{
    if (!request.Headers.Contains(UpnHeaderName))
        request.Headers.Add(UpnHeaderName, upn);  // upn
}
return await base.SendAsync(request, cancellationToken);
```

- **User** comes from the auth cookie (already set by cookie middleware).
- The **upn** claim is sent as the **upn** header so the downstream API knows which user the BFF is acting for.

---

## Handler 3: Bearer Token (Client Credentials)

**File:** `server/Handlers/ClientCredentialsTokenHandler.cs`

- **SendAsync:** calls `GetAccessTokenAsync()`, then sets `request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token)` and forwards the request.
- **GetAccessTokenAsync:**
  - If a cached token exists and expires more than 5 minutes in the future, return it.
  - Otherwise **POST** to `https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token` with:
    - **grant_type** = client_credentials
    - **client_id**, **client_secret**, **scope** from **DownstreamApi** config
  - Parse **access_token** and **expires_in**, cache them, return the token.

So the downstream API is called with **Authorization: Bearer** obtained via OAuth2 client_credentials (machine-to-machine), not the user token.

```mermaid
sequenceDiagram
    participant Handler as ClientCredentialsTokenHandler
    participant Cache as Token cache
    participant AAD as Azure AD

    Handler->>Cache: Check cached token
    alt Token valid - more than 5 min remaining
        Cache->>Handler: Return cached token
    else Token expired or missing
        Handler->>AAD: POST token endpoint - client_credentials
        AAD->>Handler: access_token, expires_in
        Handler->>Cache: Store token
    end
    Handler->>Handler: Add Authorization Bearer header
```

---

## Request Sent to the Downstream API

After the three handlers run, the request looks like:

```http
GET {BaseUrl}weatherforecast HTTP/1.1
Host: nprod-rhino-innov-spa-bff-api-....azurewebsites.net
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
X-Correlation-Id: 7f3d2a1b-4c5e-6f7a-8b9c-0d1e2f3a4b5c
upn: user@example.com
```

| Header | Source | Purpose |
|--------|--------|---------|
| **Authorization** | ClientCredentialsTokenHandler | Machine-to-machine auth (client_credentials). |
| **X-Correlation-Id** | CorrelationIdDelegatingHandler | Set in WeatherApiController; used for tracing. |
| **upn** | UserPrincipalNameHandler | From auth cookie user; identifies the user to the downstream API. |

---

## Response and Error Handling

- **DownstreamApiService** calls `response.EnsureSuccessStatusCode()` and deserializes JSON to **WeatherForecastWithInfo**.
- On **HttpRequestException** (e.g. network or non-success), **WeatherApiController** catches and returns **502 Bad Gateway** with a generic message, so the browser does not see downstream details.

---

## Summary

| Step | Component | What happens |
|------|-----------|--------------|
| 1 | Browser | GET /api/WeatherApi (cookie and X-XSRF-TOKEN). |
| 2 | WeatherApiController | Validates auth and XSRF, sets correlation ID, calls DownstreamApiService. |
| 3 | DownstreamApiService | CreateClient("DownstreamApi"), GET "weatherforecast". |
| 4 | CorrelationIdDelegatingHandler | Adds **X-Correlation-Id** from CorrelationIdService. |
| 5 | UserPrincipalNameHandler | Adds **upn** from HttpContext.User (auth cookie). |
| 6 | ClientCredentialsTokenHandler | Gets or caches client_credentials token, adds **Authorization: Bearer**. |
| 7 | HttpClient | GET {BaseUrl}weatherforecast with those headers. |
| 8 | Downstream API | Returns JSON; BFF deserializes and returns Ok(weatherData) or 502. |

The downstream API is called only from the BFF, using a named **HttpClient** and a fixed pipeline (correlation id, UPN, Bearer token), with configuration and errors handled as above.

All diagrams use Mermaid syntax and should render in GitHub, GitLab, Azure DevOps, and other Markdown viewers that support Mermaid.
