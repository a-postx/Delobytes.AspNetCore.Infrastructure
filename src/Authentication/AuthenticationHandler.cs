using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Delobytes.AspNetCore.Infrastructure.Authentication.Dto;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Headers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

namespace Delobytes.AspNetCore.Infrastructure.Authentication;

/// <summary>
/// Обработчик аутентификации АПИ-запроса.
/// </summary>
public class AuthenticationHandler : IAuthenticationHandler
{
    /// <summary>
    /// Конструктор.
    /// </summary>
    /// <exception cref="ArgumentNullException">Отсутствует какой-либо компонент внешней зависимости.</exception>
    public AuthenticationHandler(ILogger<AuthenticationHandler> logger,
        IHttpContextAccessor httpContextAccessor,
        IConfigurationManager<OpenIdConnectConfiguration> configManager,
        IOptions<AuthenticationOptions> oauthOptions)
    {
        _log = logger ?? throw new ArgumentNullException(nameof(logger));
        _httpCtx = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));  
        _configManager = configManager ?? throw new ArgumentNullException(nameof(configManager));
        _oauthOptions = oauthOptions.Value;
    }

    private readonly ILogger<AuthenticationHandler> _log;
    private readonly IHttpContextAccessor _httpCtx;
    private readonly IConfigurationManager<OpenIdConnectConfiguration> _configManager;
    private readonly AuthenticationOptions _oauthOptions;
    private AuthenticationScheme _scheme;
    private RequestHeaders _headers;

    /// <inheritdoc/>
    public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
    {
        RequestHeaders headers = context.Request.GetTypedHeaders();

        if (scheme != null && headers != null)
        {
            _scheme = scheme;
            _headers = headers;
        }
        else
        {
            throw new InvalidOperationException();
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public async Task<AuthenticateResult> AuthenticateAsync()
    {
        string errorMessage = string.Empty;

        string clientId = string.Empty;
        string userId = string.Empty;
        string tenantId = string.Empty;
        string tenantAccessType = string.Empty;
        string email = string.Empty;
        string emailVerified = string.Empty;

        JwtSecurityToken validatedToken;

        if (JwtTokenFound(out string token))
        {
            using (CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(_oauthOptions.SecurityTokenValidationTimeoutMsec)))
            {
                validatedToken = await ValidateTokenAsync(token, cts.Token);
            }

            if (validatedToken != null)
            {
                clientId = validatedToken.Claims.FirstOrDefault(claim => claim.Type == ClaimNames.azp)?.Value;
                userId = validatedToken.Claims.FirstOrDefault(claim => claim.Type == ClaimNames.sub)?.Value;
                email = validatedToken.Claims.FirstOrDefault(claim => claim.Type == _oauthOptions.EmailClaimName)?.Value;
                emailVerified = validatedToken.Claims.FirstOrDefault(claim => claim.Type == _oauthOptions.EmailVerifiedClaimName)?.Value;

                string appMetadataValue = validatedToken.Claims
                    .FirstOrDefault(claim => claim.Type == _oauthOptions.AppMetadataClaimName)?.Value;

                if (!string.IsNullOrEmpty(appMetadataValue))
                {
                    AppMetadata appMetadata = JsonSerializer
                        .Deserialize<AppMetadata>(appMetadataValue, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    tenantId = appMetadata.Tid;
                    tenantAccessType = appMetadata.TenantAccessType;
                }

                if (string.IsNullOrEmpty(clientId))
                {
                    errorMessage = $"{ClaimNames.azp} claim cannot be found";
                }
                if (string.IsNullOrEmpty(userId))
                {
                    errorMessage = $"{ClaimNames.uid} claim cannot be found";
                }
            }
            else
            {
                errorMessage = "Security token validation has failed";
            }
        }
        else
        {
            return AuthenticateResult.NoResult();
        }

#pragma warning disable CA1508 // переменная может быть модифицирована в условиях
        if (string.IsNullOrEmpty(errorMessage))
#pragma warning restore CA1508 // Avoid dead conditional code
        {
            AuthenticationTicket ticket = CreateAuthenticationTicket(clientId, userId, tenantId, tenantAccessType,
                email, emailVerified, validatedToken);

            _log.LogInformation("User {UserId} is authenticated.", userId);

            return AuthenticateResult.Success(ticket);
        }
        else
        {
            return AuthenticateResult.Fail(errorMessage);
        }
    }

    private AuthenticationTicket CreateAuthenticationTicket(string clientId, string userId, string tenantId,
        string tenantAccessType, string email, string emailVerified, JwtSecurityToken validatedToken)
    {
        ClaimsIdentity userIdentity = new(_oauthOptions.AuthType, ClaimNames.name, ClaimNames.role);

        userIdentity.AddClaim(new Claim(ClaimNames.cid, clientId));
        userIdentity.AddClaim(new Claim(ClaimNames.uid, userId));

        if (email != null)
        {
            userIdentity.AddClaim(new Claim(ClaimNames.email, email));
        }

        if (emailVerified != null)
        {
            userIdentity.AddClaim(new Claim(ClaimNames.emailVerified, emailVerified));
        }

        if (!string.IsNullOrEmpty(tenantId) && Guid.TryParse(tenantId, out Guid tid))
        {
            userIdentity.AddClaim(new Claim(ClaimNames.tid, tenantId));
        }

        if (!string.IsNullOrEmpty(tenantAccessType))
        {
            userIdentity.AddClaim(new Claim(ClaimNames.tenantaccesstype, tenantAccessType));
        }

        GenericPrincipal userPricipal = new GenericPrincipal(userIdentity, null);
        ClaimsPrincipal principal = new ClaimsPrincipal(userPricipal);

        AuthenticationProperties props = new AuthenticationProperties
        {
            IssuedUtc = validatedToken.IssuedAt,
            ExpiresUtc = validatedToken.ValidTo,
            RedirectUri = _oauthOptions.LoginRedirectPath
        };

        return new AuthenticationTicket(principal, props, _scheme.Name);
    }

    /// <inheritdoc/>
    public Task ChallengeAsync(AuthenticationProperties properties)
    {
        HttpContext context = _httpCtx.HttpContext;

        if (context.Request.Host.Host == _oauthOptions.ApiGatewayHost
            && context.Request.Host.Port == _oauthOptions.ApiGatewayPort)
        {
            _log.LogInformation("Challenge: redirected.");
            context.Response.Redirect(_oauthOptions.LoginRedirectPath);
            return Task.CompletedTask;
        }
        else
        {
            _log.LogInformation("Challenge: unauthorized.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }
    }

    /// <inheritdoc/>
    public Task ForbidAsync(AuthenticationProperties properties)
    {
        HttpContext context = _httpCtx.HttpContext;
        _log.LogInformation("Forbid: forbidden.");
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }

    private bool JwtTokenFound(out string token)
    {
        bool tokenFound = false;
        token = null;

        if (_headers.Headers.TryGetValue(HeaderNames.Authorization, out StringValues authHeaders) && authHeaders.Any())
        {
            string tokenHeaderValue = authHeaders.ElementAt(0);
            token = tokenHeaderValue.StartsWith(_oauthOptions.AuthType + " ", StringComparison.OrdinalIgnoreCase)
                ? tokenHeaderValue.Substring(7) : tokenHeaderValue;
            tokenFound = true;
        }

        return tokenFound;
    }

    private async Task<JwtSecurityToken> ValidateTokenAsync(string token, CancellationToken cancellationToken)
    {
        JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();

        try
        {
            jwtHandler.ReadToken(token);
        }
        catch (ArgumentNullException)
        {
            _log.LogInformation("Security token is null.");
            return null;
        }
        catch (ArgumentException)
        {
            _log.LogInformation("Security token is not well formed.");
            return null;
        }

        TokenValidationParameters validationParameters = await GetValidationParametersAsync(cancellationToken);

        try
        {
            ClaimsPrincipal principal = jwtHandler.ValidateToken(token, validationParameters, out SecurityToken rawValidatedToken);

            JwtSecurityToken validatedToken = (JwtSecurityToken)rawValidatedToken;
            string expectedAlg = SecurityAlgorithms.RsaSha256;

            if (validatedToken.Header?.Alg == null || validatedToken.Header?.Alg != expectedAlg)
            {
                throw new SecurityTokenValidationException($"The security token alg must be {expectedAlg}.");
            }

            return validatedToken;
        }
        catch (SecurityTokenExpiredException)
        {
            _log.LogInformation("Security token expired.");
            return null;
        }
        catch (SecurityTokenValidationException ex)
        {
            _log.LogInformation("Security token validation failed: {ExceptionMessage}", ex.Message);
            return null;
        }
        catch (SecurityTokenException ex)
        {
            _log.LogWarning(ex, "Security token exception.");
            return null;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Security token validation failed with exception.");
            return null;
        }
    }

    private async Task<TokenValidationParameters> GetValidationParametersAsync(CancellationToken cancellationToken)
    {
        //значение кешировано большую часть времени, поэтому проблемы производительности быть не должно
        OpenIdConnectConfiguration discoveryDocument = await _configManager.GetConfigurationAsync(cancellationToken);
        ICollection<SecurityKey> signingKeys = discoveryDocument.SigningKeys;

        TokenValidationParameters validationParameters = new()
        {
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuer = _oauthOptions.Authority + "/",
            ValidateAudience = true,
            ValidAudience = _oauthOptions.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,
            ValidateLifetime = true,
            ClockSkew = _oauthOptions.TokenValidationClockSkew,
        };

        return validationParameters;
    }
}
