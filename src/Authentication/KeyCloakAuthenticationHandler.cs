using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
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
/// Обработчик аутентификации АПИ-запроса с помощью KeyCloak.
/// </summary>
public class KeyCloakAuthenticationHandler : IAuthenticationHandler
{
    /// <summary>
    /// Конструктор.
    /// </summary>
    /// <exception cref="ArgumentNullException">Отсутствует какой-либо компонент внешней зависимости.</exception>
    public KeyCloakAuthenticationHandler(ILogger<KeyCloakAuthenticationHandler> logger,
        IHttpContextAccessor httpContextAccessor,
        IConfigurationManager<OpenIdConnectConfiguration> configManager,
        IOptions<AuthenticationOptions> authOptions)
    {
        _log = logger ?? throw new ArgumentNullException(nameof(logger));
        _httpCtx = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _configManager = configManager ?? throw new ArgumentNullException(nameof(configManager));
        _authOptions = authOptions.Value;
    }

    private readonly ILogger<KeyCloakAuthenticationHandler> _log;
    private readonly IHttpContextAccessor _httpCtx;
    private readonly IConfigurationManager<OpenIdConnectConfiguration> _configManager;
    private readonly AuthenticationOptions _authOptions;
    private AuthenticationScheme _scheme = default!; //инициализируем в автоматическом вызове InitializeAsync
    private RequestHeaders _headers = default!;

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
            throw new InvalidOperationException("Authentication scheme or headers are not found");
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public async Task<AuthenticateResult> AuthenticateAsync()
    {
        string? token = GetJwtToken();

        if (token == null)
        {
            return AuthenticateResult.Fail("Security token is not found");
        }

        JwtSecurityToken? validatedToken;

        using (CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(_authOptions.TokenValidationTimeoutMsec)))
        {
            validatedToken = await ValidateTokenAsync(token, cts.Token);
        }

        if (validatedToken == null)
        {
            return AuthenticateResult.Fail("Security token validation has failed");
        }

        string? clientId = validatedToken.Claims.FirstOrDefault(claim => claim.Type == ClaimNames.azp)?.Value;
        string? userId = validatedToken.Claims.FirstOrDefault(claim => claim.Type == ClaimNames.sub)?.Value;

        if (string.IsNullOrEmpty(clientId))
        {
            return AuthenticateResult.Fail($"{ClaimNames.azp} claim cannot be found");
        }

        if (string.IsNullOrEmpty(userId))
        {
            return AuthenticateResult.Fail($"{ClaimNames.uid} claim cannot be found");
        }

        Dictionary<string, string> customClaims = new Dictionary<string, string>();

        foreach (string claimName in _authOptions.CustomClaims)
        {
            string? claimValue = validatedToken.Claims.FirstOrDefault(claim => claim.Type == claimName)?.Value;

            if (!string.IsNullOrEmpty(claimValue))
            {
                customClaims.Add(claimName, claimValue);
            }
        }

        AuthenticationTicket ticket = CreateAuthenticationTicket(clientId, userId, customClaims, validatedToken);

        _log.LogInformation("User {UserId} is authenticated.", userId);

        return AuthenticateResult.Success(ticket);
    }

    private AuthenticationTicket CreateAuthenticationTicket(string clientId, string userId,
        Dictionary<string, string> customClaims, JwtSecurityToken validatedToken)
    {
        ClaimsIdentity userIdentity = new ClaimsIdentity(_authOptions.AuthType, ClaimNames.name, ClaimNames.role);

        userIdentity.AddClaim(new Claim(ClaimNames.cid, clientId));
        userIdentity.AddClaim(new Claim(ClaimNames.uid, userId));

        foreach (KeyValuePair<string, string> claim in customClaims)
        {
            userIdentity.AddClaim(new Claim(claim.Key, claim.Value));
        }

        GenericPrincipal userPricipal = new GenericPrincipal(userIdentity, null);
        ClaimsPrincipal principal = new ClaimsPrincipal(userPricipal);

        AuthenticationProperties props = new AuthenticationProperties
        {
            IssuedUtc = validatedToken.IssuedAt,
            ExpiresUtc = validatedToken.ValidTo
        };

        if (!string.IsNullOrEmpty(_authOptions.LoginRedirectPath))
        {
            props.RedirectUri = _authOptions.LoginRedirectPath;
        }

        return new AuthenticationTicket(principal, props, _scheme.Name);
    }

    /// <inheritdoc/>
    public Task ChallengeAsync(AuthenticationProperties? properties)
    {
        if (_httpCtx.HttpContext == null)
        {
            throw new InvalidOperationException("Http context not found");
        }

        HttpContext context = _httpCtx.HttpContext;

        if (!string.IsNullOrEmpty(_authOptions.ApiGatewayHost)
            && context.Request.Host.Host == _authOptions.ApiGatewayHost
            && _authOptions.ApiGatewayPort != 0
            && context.Request.Host.Port == _authOptions.ApiGatewayPort
            && !string.IsNullOrEmpty(_authOptions.LoginRedirectPath))
        {
            _log.LogInformation("Challenge: redirected.");
            context.Response.Redirect(_authOptions.LoginRedirectPath);
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
    public Task ForbidAsync(AuthenticationProperties? properties)
    {
        if (_httpCtx.HttpContext == null)
        {
            throw new InvalidOperationException("Http context not found");
        }

        HttpContext context = _httpCtx.HttpContext;
        _log.LogInformation("Forbid: forbidden.");
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }

    private string? GetJwtToken()
    {
        if (_httpCtx.HttpContext == null)
        {
            throw new InvalidOperationException("Http context not found");
        }

        string? token = null;

        if (_headers.Headers.TryGetValue(HeaderNames.Authorization, out StringValues authHeaders) && authHeaders.Any())
        {
            string tokenHeaderValue = authHeaders.ElementAt(0);
            token = tokenHeaderValue.StartsWith(_authOptions.AuthType + " ", StringComparison.OrdinalIgnoreCase)
                ? tokenHeaderValue[7..] : tokenHeaderValue;
        }
        //проблема безопасности
        //запросы на загрузку файлов идут через window.open, поэтому ключ посылается в параметрах
        else if (_httpCtx.HttpContext.Request.Query.TryGetValue("at", out StringValues accessToken))
        {
            token = accessToken.ToString();
        }

        return token;
    }

    private async Task<JwtSecurityToken?> ValidateTokenAsync(string token, CancellationToken cancellationToken)
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

        JwtSecurityToken? validatedToken = null;

        try
        {
            ClaimsPrincipal principal = jwtHandler.ValidateToken(token, validationParameters, out SecurityToken rawValidatedToken);

            validatedToken = (JwtSecurityToken)rawValidatedToken;
            string expectedAlg = SecurityAlgorithms.RsaSha256;

            if (validatedToken.Header?.Alg == null || validatedToken.Header?.Alg != expectedAlg)
            {
                throw new SecurityTokenValidationException($"The security token alg must be {expectedAlg}.");
            }
        }
        catch (SecurityTokenDecryptionFailedException ex)
        {
            _log.LogInformation("Security token cannot be decrypted: {ExceptionMessage}", ex.Message);
        }
        catch (SecurityTokenExpiredException)
        {
            _log.LogInformation("Security token expired.");
        }
        catch (SecurityTokenValidationException ex)
        {
            _log.LogInformation("Security token validation failed: {ExceptionMessage}", ex.Message);
        }
        catch (SecurityTokenException ex)
        {
            _log.LogWarning(ex, "Security token exception.");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Security token validation failed with exception.");
        }

        return validatedToken;
    }

    private async Task<TokenValidationParameters> GetValidationParametersAsync(CancellationToken cancellationToken)
    {
        //конфигурация кеширована большую часть времени, поэтому нет проблемы производительности
        OpenIdConnectConfiguration discoveryDocument = await _configManager.GetConfigurationAsync(cancellationToken);
        ICollection<SecurityKey> signingKeys = discoveryDocument.SigningKeys;

        TokenValidationParameters validationParameters = new TokenValidationParameters
        {
            IssuerSigningKeys = signingKeys
        };

        if (_authOptions.TokenValidationParameters != null)
        {
            validationParameters.RequireExpirationTime = _authOptions.TokenValidationParameters.RequireExpirationTime;
            validationParameters.RequireSignedTokens = _authOptions.TokenValidationParameters.RequireSignedTokens;
            validationParameters.ValidateIssuerSigningKey = _authOptions.TokenValidationParameters.ValidateIssuerSigningKey;
            validationParameters.ValidateIssuer = _authOptions.TokenValidationParameters.ValidateIssuer;
            validationParameters.ValidIssuer = _authOptions.TokenValidationParameters.ValidIssuer;
            validationParameters.ValidateAudience = _authOptions.TokenValidationParameters.ValidateAudience;
            validationParameters.ValidAudience = _authOptions.TokenValidationParameters.ValidAudience;
            validationParameters.ValidateLifetime = _authOptions.TokenValidationParameters.ValidateLifetime;
            validationParameters.ClockSkew = _authOptions.TokenValidationParameters.ClockSkew;
        }
        else
        {
            validationParameters.ValidateIssuerSigningKey = true;
            validationParameters.ValidIssuer = _authOptions.Authority;
            validationParameters.ValidAudience = _authOptions.Audience;
        }

        return validationParameters;
    }
}
