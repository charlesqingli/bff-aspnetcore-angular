# SPA-BFF: Minimum vs Extra Features

This document distinguishes what is **strictly required** to convert a pure SPA to a SPA-BFF architecture from the **extra bells and whistles** present in this project.

---

## Table of Contents

- [Minimum SPA→BFF (What You Actually Need)](#minimum-spabff-what-you-actually-need)
- [Extra Bells and Whistles](#extra-bells-and-whistles)
- [Summary Table](#summary-table)
- [Stripped-Down Checklist](#stripped-down-checklist)

---

## Minimum SPA→BFF (What You Actually Need)

| Component | Purpose |
|-----------|---------|
| **Cookie auth** | Store tokens server-side in HttpOnly cookie (browser never sees access token) |
| **OIDC** | Login flow: redirect to IDP, code exchange, receive tokens |
| **Cookie + OIDC config** | `AddCookie` + `AddOpenIdConnect` with `SignInScheme`, `SaveTokens`, PKCE |
| **Antiforgery** | XSRF protection (cookie + header validation) |
| **AccountController** | Login (`Challenge`) and Logout (`SignOut`) endpoints |
| **UserController** | Return user info for SPA (e.g. `isAuthenticated`, claims) so UI can show login state |
| **Protected API** | At least one `[Authorize]` endpoint the SPA calls |
| **Serve SPA** | Fallback to index.html (or _Host) so the SPA loads |
| **XSRF on protected endpoints** | `[ValidateAntiForgeryToken]` and SPA sending `X-XSRF-TOKEN` header |

**Optional but highly recommended:**

- **Token refresh** – Keeps the session alive when the access token expires; otherwise the user is logged out unexpectedly.

---

## Extra Bells and Whistles

These features are **not** required for a minimal SPA-BFF conversion. They add security hardening, observability, or “BFF as gateway to another API” behavior.

### 1. Security Headers (NetEscapades)

| Aspect | Details |
|--------|---------|
| **What** | CSP, HSTS, X-Frame-Options, COOP, CORP, COEP, Referrer-Policy, etc. Plus a separate policy for `/api/*`. |
| **Files** | `SecurityHeadersDefinitions.cs`, `ApiSecurityHeadersDefinitions.cs`, `AddSecurityHeaderPolicies()` in Program.cs |
| **Verdict** | **Extra** – Hardening only. Minimum BFF does not require these. |

### 2. CSP Nonce Injection

| Aspect | Details |
|--------|---------|
| **What** | Per-request nonce injected into HTML and script/link tags so CSP can allow only those scripts/styles. |
| **Where** | `_Host.cshtml` (`HttpContext.GetNonce()`, replace placeholders), `index.html` placeholders, Angular `CSP_NONCE` provider |
| **Verdict** | **Extra** – Minimum can serve static `index.html` with no nonce. |

### 3. Downstream API + Client Credentials

| Aspect | Details |
|--------|---------|
| **What** | BFF calls another API using OAuth2 client_credentials; handlers add Bearer token, UPN, correlation ID. |
| **Files** | `ClientCredentialsTokenHandler`, `DownstreamApiService`, `WeatherApiController`, `UserPrincipalNameHandler`, config (`DownstreamApi:*`) |
| **Verdict** | **Extra** – Only needed if you have a backend API the BFF calls. Not required to “convert SPA to SPA-BFF.” |

### 4. Correlation ID

| Aspect | Details |
|--------|---------|
| **What** | Per-request ID in `AsyncLocal`, sent to downstream API for distributed tracing. |
| **Files** | `CorrelationIdService`, `CorrelationIdDelegatingHandler`, usage in `WeatherApiController` and `DownstreamApiService` |
| **Verdict** | **Extra** – Observability only. Not part of minimum SPA-BFF. |

### 5. UPN Header

| Aspect | Details |
|--------|---------|
| **What** | Forward user’s UPN (or similar) to downstream API. |
| **File** | `UserPrincipalNameHandler` |
| **Verdict** | **Extra** – Only needed if you have a downstream API that needs user identity. Not required for basic SPA-BFF. |

### 6. UserInfo Endpoint Enrichment

| Aspect | Details |
|--------|---------|
| **What** | After token validation, call OIDC UserInfo and merge claims into `ClaimsPrincipal`. |
| **Where** | `OnTokenValidated` in Program.cs |
| **Verdict** | **Extra** – Nice-to-have for richer claims. Minimum BFF can rely only on ID token claims. |

### 7. Open Redirect Protection

| Aspect | Details |
|--------|---------|
| **What** | Validate/sanitize `returnUrl` in `AccountController.Login` (`GetAuthProperties`). |
| **Verdict** | **Extra** – Good practice; not strictly required for “minimal” but recommended in production. |

### 8. Kestrel: No Server Header

| Aspect | Details |
|--------|---------|
| **What** | `AddServerHeader = false` so Kestrel doesn’t send a `Server` header. |
| **Verdict** | **Extra** – Minor hardening; not required for SPA-BFF. |

### 9. OpenAPI

| Aspect | Details |
|--------|---------|
| **What** | `AddOpenApi()`, `MapOpenApi()` in dev for API documentation. |
| **Verdict** | **Extra** – Documentation only; not part of minimum SPA-BFF. |

### 10. MapNotFound for `/api/*`

| Aspect | Details |
|--------|---------|
| **What** | Explicit 404 for unknown API routes (`MapNotFound("/api/{**segment}")`). |
| **Verdict** | **Extra** – Small UX improvement; not required. |

### 11. YARP Reverse Proxy (Dev)

| Aspect | Details |
|--------|---------|
| **What** | In dev, proxy UI requests to Angular CLI instead of serving from wwwroot. |
| **Verdict** | **Extra** – Dev experience only. Minimum could always build SPA into wwwroot and serve from there. |

### 12. CAE / Claims Challenge (Currently Unused)

| Aspect | Details |
|--------|---------|
| **What** | `CaeClaimsChallengeService`, `AuthContextId`, etc. (and commented-out registration). |
| **Verdict** | **Extra** – For scenarios like Conditional Access; not part of minimum SPA-BFF. |

### 13. Razor Dynamic Host vs Static HTML

| Aspect | Details |
|--------|---------|
| **What** | `_Host.cshtml` fetches/injects HTML, nonce, XSRF cookie. |
| **Verdict** | **Extra** – Dynamic host is for nonce + XSRF. Minimum could be: serve static `index.html` and set XSRF cookie on first request (e.g. from a simple endpoint or middleware) without Razor. |

### 14. RejectSessionCookieWhenAccountNotInCacheEvents

| Aspect | Details |
|--------|---------|
| **What** | Extra cookie validation (file exists; if used, it’s an extra safeguard). |
| **Verdict** | **Extra** – Optional hardening; not minimum SPA-BFF. |

---

## Summary Table

| Category | Minimum SPA-BFF? | In This Project |
|----------|------------------|-----------------|
| Cookie + OIDC auth | ✅ Yes | ✅ |
| XSRF (antiforgery + header) | ✅ Yes | ✅ |
| Login/Logout endpoints | ✅ Yes | ✅ |
| User endpoint (`/api/User`) | ✅ Yes | ✅ |
| At least one protected API | ✅ Yes | ✅ (e.g. WeatherApi) |
| Serve SPA (fallback) | ✅ Yes | ✅ |
| Token refresh | ⚠️ Recommended | ✅ |
| Security headers (CSP, HSTS, etc.) | ❌ No | ✅ |
| CSP nonce | ❌ No | ✅ |
| Downstream API + client credentials | ❌ No | ✅ |
| Correlation ID | ❌ No | ✅ |
| UPN header | ❌ No | ✅ |
| UserInfo enrichment | ❌ No | ✅ |
| Open redirect protection | ⚠️ Recommended | ✅ |
| OpenAPI, MapNotFound, no Server header | ❌ No | ✅ |
| YARP (dev proxy) | ❌ No | ✅ |
| CAE / claims challenge | ❌ No | Present (unused) |

---

## Stripped-Down Checklist

To build a **minimal** SPA-BFF from scratch (or strip this project down), you need:

**Backend (ASP.NET Core):**

- [ ] Cookie authentication (`AddCookie`) with HttpOnly, Secure, SameSite=Strict
- [ ] OpenID Connect (`AddOpenIdConnect`) with PKCE, `SaveTokens`, `SignInScheme` = cookie
- [ ] Antiforgery (`AddAntiforgery`) with cookie + header name (e.g. `X-XSRF-TOKEN`)
- [ ] AccountController: `GET Login` → `Challenge()`, `POST Logout` → `SignOut()` (with `[Authorize]`)
- [ ] UserController: `GET` returning user info (e.g. `isAuthenticated`, claims), optionally `[AllowAnonymous]`
- [ ] At least one protected API controller with `[Authorize]` and `[ValidateAntiForgeryToken]`
- [ ] Fallback route to serve SPA (e.g. `MapFallbackToPage("/_Host")` or `MapFallbackToFile("index.html")`)
- [ ] (Recommended) Token refresh via cookie events so session doesn’t die when access token expires

**Frontend (Angular):**

- [ ] All API requests go to same origin (BFF)
- [ ] Read XSRF token from cookie and send in `X-XSRF-TOKEN` header for API requests (interceptor)
- [ ] Login = navigation to `/api/Account/Login` (or similar)
- [ ] Logout = POST to `/api/Account/Logout` with XSRF token
- [ ] Call `/api/User` (or equivalent) to get login state and render UI (e.g. Log in vs user info + Logout)

Everything else in this repo (security headers, nonce, downstream API, correlation ID, UPN, UserInfo, OpenAPI, YARP, CAE, etc.) is **optional** relative to the minimum SPA-BFF pattern.
