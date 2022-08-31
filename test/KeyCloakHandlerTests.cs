using System.IO;
using System.IO.Pipelines;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading;
using Delobytes.AspNetCore.Infrastructure.Authentication;
using Delobytes.AspNetCore.Infrastructure.Tests.Dto;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Net.Http.Headers;
using AuthenticationOptions = Delobytes.AspNetCore.Infrastructure.Authentication.AuthenticationOptions;

namespace Delobytes.AspNetCore.Infrastructure.Tests;

public class KeyCloakHandlerTests
{
    private static readonly string RequestPath = "/json";
    private static readonly Dictionary<string, StringValues> RequestHeadersWoSecurity = new Dictionary<string, StringValues>
            {
                { "RequestHeader1", "RequestHeader1Value" },
            };
    private static readonly Dictionary<string, StringValues> RequestHeadersWMalformedSecurity = new Dictionary<string, StringValues>
            {
                { HeaderNames.Authorization, $"Bearer 123qwe" },
            };
    private static readonly Dictionary<string, StringValues> ResponseHeaders = new Dictionary<string, StringValues>
            {
                { "ResponseHeader1", "ResponseHeader1Value" }
            };

    private static readonly string AuthScheme = "TestScheme";
    private static readonly string ApiGatewayHost = "localhost";
    private static readonly int ApiGatewayPort = 7457;


    #region Infrastructure
    private AppSecrets? GetAppSecrets()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        IConfigurationRoot tempConfig = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();

        builder.Configuration.AddYandexCloudLockboxConfiguration(config =>
        {
            config.PrivateKey = Environment.GetEnvironmentVariable("YC_PRIVATE_KEY");
            config.ServiceAccountId = tempConfig.GetValue<string>("YC:ServiceAccountId");
            config.ServiceAccountAuthorizedKeyId = tempConfig.GetValue<string>("YC:ServiceAccountAuthorizedKeyId");
            config.SecretId = tempConfig.GetValue<string>("YC:ConfigurationSecretId");
            config.PathSeparator = '-';
            config.Optional = false;
            config.ReloadPeriod = TimeSpan.FromDays(7);
            config.LoadTimeout = TimeSpan.FromSeconds(20);
            config.OnLoadException += exceptionContext =>
            {
                //log
            };
        });

        builder.Services.AddSingleton<IValidateOptions<AppSecrets>, AppSecretsValidator>();
        builder.Services
            .Configure<AppSecrets>(builder.Configuration.GetSection(nameof(AppSecrets)), o => o.BindNonPublicProperties = false);
        AppSecrets? appSecrets = builder.Services.BuildServiceProvider().GetService<IOptions<AppSecrets>>()?.Value;

        return appSecrets;
    }

    private WebApplication CreateApplication()
    {
        AppSecrets? secrets = GetAppSecrets();

        if (secrets == null)
        {
            throw new InvalidOperationException($"Error getting app secrets");
        }

        WebApplicationBuilder builder = WebApplication.CreateBuilder();

        builder.Services.AddKeyCloakAuthentication(AuthScheme, true, options =>
        {
            options.Authority = secrets.RealmUrl;
            options.Audience = "account";
            options.OpenIdConfigurationEndpoint = secrets.RealmUrl + "/.well-known/openid-configuration";
            options.LoginRedirectPath = "/authentication/login";
            options.ApiGatewayHost = ApiGatewayHost;
            options.ApiGatewayPort = ApiGatewayPort;
            options.CustomClaims = new List<string> { ClaimNames.tid };
            options.TokenValidationParameters = new TokenValidationOptions
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,                
                ValidIssuer = secrets.RealmUrl,
                ValidateAudience = true,
                ValidAudience = "account",
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(2),
            };
        });

        WebApplication app = builder.Build();

        return app;
    }

    private KeyCloakAuthenticationHandler CreateHandler(HttpContext ctx)
    {
        WebApplication app = CreateApplication();

        ILogger<KeyCloakAuthenticationHandler> logger = Mock.Of<ILogger<KeyCloakAuthenticationHandler>>();

        IHttpContextAccessor httpCtx = Mock.Of<IHttpContextAccessor>();
        httpCtx.HttpContext = ctx;

        IConfigurationManager<OpenIdConnectConfiguration> configManager = app.Services
            .GetService(typeof(IConfigurationManager<OpenIdConnectConfiguration>))
            .As<IConfigurationManager<OpenIdConnectConfiguration>>();

        IOptions<AuthenticationOptions> options = app.Services
            .GetService(typeof(IOptions<AuthenticationOptions>))
            .As<IOptions<AuthenticationOptions>>();

        KeyCloakAuthenticationHandler handler = new KeyCloakAuthenticationHandler(logger, httpCtx, configManager, options);

        return handler;
    }

    private AuthenticationScheme CreateAuthenticationScheme()
    {
        AuthenticationSchemeBuilder schemeBuilder = new AuthenticationSchemeBuilder(AuthScheme);
        schemeBuilder.HandlerType = typeof(KeyCloakAuthenticationHandler);
        AuthenticationScheme scheme = schemeBuilder.Build();

        return scheme;
    }

    private HttpContext GetHttpContextWithRequest(Dictionary<string, StringValues> requestHeaders, HostString requestHostString, string requestBody = "{ \"request\": true }")
    {
        MockRepository mocks = new MockRepository(MockBehavior.Default);
        mocks.CallBase = true;

        FeatureCollection features = new FeatureCollection();

        Mock<IHttpRequestFeature> requestMock = new Mock<IHttpRequestFeature>();
        Mock<PipeReader> mockReqBodyReader = mocks.Create<PipeReader>();
        MemoryStream requestBodyMs = new MemoryStream();
        requestBodyMs.WriteAsync(Encoding.UTF8.GetBytes(requestBody));
        requestBodyMs.Seek(0, SeekOrigin.Begin);

        requestMock.Setup(h => h.Body).Returns(requestBodyMs);
        requestMock.Setup(h => h.Path).Returns(PathString.FromUriComponent(RequestPath));
        requestMock.Setup(h => h.RawTarget).Returns(PathString.FromUriComponent(RequestPath));
        requestMock.Setup(h => h.Protocol).Returns("HTTP/1.1");
        requestMock.Setup(h => h.Scheme).Returns("http");
        requestMock.Setup(h => h.Method).Returns("POST");
        requestMock.Setup(p => p.Headers).Returns(new HeaderDictionary(requestHeaders));
        requestMock.Setup(h => h.QueryString).Returns("?pageSize=5");
        features.Set(requestMock.Object);

        DefaultHttpContext context = new DefaultHttpContext(features);
        context.Request.Host = requestHostString;
        context.Request.ContentLength = requestBodyMs.Length;

        return context;
    }

    private HttpContext GetHttpContextWithRequestAndResponse(Dictionary<string, StringValues> requestHeaders,
        HostString requestHostString, Dictionary<string, StringValues> responseHeaders, string requestBody = "{ \"request\": true }",
        string responseBody = "{ \"response\": true }")
    {
        MockRepository mocks = new MockRepository(MockBehavior.Default);
        mocks.CallBase = true;

        FeatureCollection features = new FeatureCollection();

        Mock<IHttpRequestFeature> requestMock = new Mock<IHttpRequestFeature>();
        Mock<PipeReader> mockReqBodyReader = mocks.Create<PipeReader>();
        MemoryStream requestBodyMs = new MemoryStream();
        requestBodyMs.WriteAsync(Encoding.UTF8.GetBytes(requestBody));
        requestBodyMs.Seek(0, SeekOrigin.Begin);

        requestMock.Setup(h => h.Body).Returns(requestBodyMs);
        requestMock.Setup(h => h.Path).Returns(PathString.FromUriComponent(RequestPath));
        requestMock.Setup(h => h.RawTarget).Returns(PathString.FromUriComponent(RequestPath));
        requestMock.Setup(h => h.Protocol).Returns("HTTP/1.1");
        requestMock.Setup(h => h.Scheme).Returns("http");
        requestMock.Setup(h => h.Method).Returns("POST");
        requestMock.Setup(p => p.Headers).Returns(new HeaderDictionary(requestHeaders));
        requestMock.Setup(h => h.QueryString).Returns("?pageSize=5");
        features.Set(requestMock.Object);

        Mock<IHttpResponseFeature> responseMock = new Mock<IHttpResponseFeature>();
        responseMock.SetupProperty(x => x.StatusCode);
        responseMock.Setup(p => p.Headers).Returns(new HeaderDictionary(responseHeaders));
        features.Set(responseMock.Object);

        Mock<IHttpResponseBodyFeature> responseBodyMock = new Mock<IHttpResponseBodyFeature>();
        MemoryStream responseBodyMs = new MemoryStream();
        responseBodyMs.WriteAsync(Encoding.UTF8.GetBytes(responseBody));
        responseBodyMs.Seek(0, SeekOrigin.Begin);
        responseBodyMock.Setup(o => o.Stream).Returns(responseBodyMs);
        features.Set(responseBodyMock.Object);

        DefaultHttpContext context = new DefaultHttpContext(features);
        context.Request.Host = requestHostString;
        context.Request.ContentLength = requestBodyMs.Length;

        return context;
    }

    private async Task<string?> GetAccessToken()
    {
        //Direct Access Grants (Resource Owner Password Credentials Grant) должен быть включён на клиенте
        string? result = null;

        AppSecrets? secrets = GetAppSecrets();

        if (secrets == null)
        {
            throw new InvalidOperationException($"Error getting app secrets");
        }

        string realmUrl = secrets.RealmUrl!;
        string username = secrets.Username!;
        string password = secrets.Password!;
        string client_id = secrets.ClientId!;

        string tokenEndpoint = $"{realmUrl}/protocol/openid-connect/token";

        JsonSerializerOptions opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

        using (CancellationTokenSource cts = new CancellationTokenSource())
        using (HttpClient client = new HttpClient())
        {
            cts.CancelAfter(30000);

            client.Timeout = TimeSpan.FromSeconds(60);
            string formContent = $"username={username}&password={password}&grant_type=password&client_id={client_id}";
            StringContent content = new StringContent(formContent, Encoding.UTF8, "application/x-www-form-urlencoded");
            HttpResponseMessage response = await client.PostAsync(tokenEndpoint, content, cts.Token);
            string res = await response.Content.ReadAsStringAsync(cts.Token);

            AccessTokenResponse? tokenResponse = JsonSerializer.Deserialize<AccessTokenResponse>(res, opts);

            if (tokenResponse != null && !string.IsNullOrEmpty(tokenResponse.Access_token))
            {
                result = tokenResponse.Access_token;
            }
            else
            {
                string? errorMsg = null;

                KeyCloakErrorResponse? errorResponse = JsonSerializer.Deserialize<KeyCloakErrorResponse>(res, opts);

                if (errorResponse != null && !string.IsNullOrEmpty(errorResponse.Error))
                {
                    errorMsg = $"{errorResponse.Error}: {errorResponse.Error_description}";
                }
                else
                {
                    errorMsg = "unknown error";
                }

                throw new InvalidOperationException($"Error getting access token: {errorMsg}");
            }
        }

        return result;
    }

    private async Task<KeyCloakAuthenticationHandler> GetInitializedHandler(HttpContext httpContext)
    {
        KeyCloakAuthenticationHandler handler = CreateHandler(httpContext);
        AuthenticationScheme scheme = CreateAuthenticationScheme();

        await handler.InitializeAsync(scheme, httpContext);

        return handler;
    }
    #endregion


    [Fact]
    public void KeyCloakHandler_HasOpenIdConfigurationManager()
    {
        WebApplication app = CreateApplication();

        IConfigurationManager<OpenIdConnectConfiguration> configManager = app.Services
            .GetService(typeof(IConfigurationManager<OpenIdConnectConfiguration>))
            .As<IConfigurationManager<OpenIdConnectConfiguration>>();

        configManager.Should().NotBeNull();
        configManager.Should().BeOfType<ConfigurationManager<OpenIdConnectConfiguration>>();

        ConfigurationManager<OpenIdConnectConfiguration> typedCm = configManager
            .As<ConfigurationManager<OpenIdConnectConfiguration>>();

        typedCm.Should().NotBeNull();
        typedCm.MetadataAddress.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task KeyCloakHandler_ConfigurationManager_GotConfiguration()
    {
        WebApplication app = CreateApplication();

        IConfigurationManager<OpenIdConnectConfiguration> configManager = app.Services
            .GetService(typeof(IConfigurationManager<OpenIdConnectConfiguration>))
            .As<IConfigurationManager<OpenIdConnectConfiguration>>();

        CancellationTokenSource cts = new CancellationTokenSource();
        cts.CancelAfter(3000);
        
        Func<Task> retrieveConfiguration = () => configManager.GetConfigurationAsync(cts.Token);
        Exception ex = await Record.ExceptionAsync(retrieveConfiguration);

        ex.Should().BeNull();
    }

    [Fact]
    public async Task KeyCloakHandler_InitializedSuccessfully()
    {
        HttpContext ctx = GetHttpContextWithRequest(RequestHeadersWoSecurity, HostString.FromUriComponent("app.ru"));
        KeyCloakAuthenticationHandler handler = CreateHandler(ctx);
        AuthenticationScheme scheme = CreateAuthenticationScheme();

        Func<Task> retrieveConfiguration = () => handler.InitializeAsync(scheme, ctx);
        Exception ex = await Record.ExceptionAsync(retrieveConfiguration);

        ex.Should().BeNull();
    }

    [Fact]
    public async Task KeyCloakHandler_AuthenticationFails_WithoutSecurityHeader()
    {
        HttpContext ctx = GetHttpContextWithRequest(RequestHeadersWoSecurity, HostString.FromUriComponent("app.ru"));
        KeyCloakAuthenticationHandler handler = await GetInitializedHandler(ctx);

        AuthenticateResult authResult = await handler.AuthenticateAsync();

        authResult.Should().NotBeNull();
        authResult.Succeeded.Should().BeFalse();
        authResult.Failure.Should().NotBeNull();
        authResult.Ticket.Should().BeNull();
    }

    [Fact]
    public async Task KeyCloakHandler_AuthenticationFails_WithMalformedSecurityHeader()
    {
        HttpContext ctx = GetHttpContextWithRequest(RequestHeadersWMalformedSecurity, HostString.FromUriComponent("app.ru"));
        KeyCloakAuthenticationHandler handler = await GetInitializedHandler(ctx);

        AuthenticateResult authResult = await handler.AuthenticateAsync();

        authResult.Should().NotBeNull();
        authResult.Succeeded.Should().BeFalse();
        authResult.Failure.Should().NotBeNull();
        authResult.Ticket.Should().BeNull();
    }

    [Fact]
    public async Task KeyCloakHandler_UserAccessToken_CanBeReceived()
    {
        string? accessToken = await GetAccessToken();

        accessToken.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task KeyCloakHandler_AuthenticationSucceed_WithSecurityHeader()
    {
        string? accessToken = await GetAccessToken();

        Dictionary<string, StringValues> requestHeadersWithSecurity = new Dictionary<string, StringValues>
            {
                { HeaderNames.Authorization, $"Bearer {accessToken}" }
            };

        HttpContext ctx = GetHttpContextWithRequest(requestHeadersWithSecurity, HostString.FromUriComponent("app.ru"));
        KeyCloakAuthenticationHandler handler = await GetInitializedHandler(ctx);

        AuthenticateResult authResult = await handler.AuthenticateAsync();
        
        authResult.Should().NotBeNull();
        authResult.Succeeded.Should().BeTrue();
        authResult.Failure.Should().BeNull();
        authResult.Ticket.Should().NotBeNull();
        authResult.Ticket!.Principal.Should().NotBeNull();
    }

    [Fact]
    public async Task KeyCloakHandler_CustomClaimIsAddedToPrincipal()
    {
        string? accessToken = await GetAccessToken();

        Dictionary<string, StringValues> requestHeadersWithSecurity = new Dictionary<string, StringValues>
            {
                { HeaderNames.Authorization, $"Bearer {accessToken}" }
            };

        HttpContext ctx = GetHttpContextWithRequest(requestHeadersWithSecurity, HostString.FromUriComponent("app.ru"));
        KeyCloakAuthenticationHandler handler = await GetInitializedHandler(ctx);

        AuthenticateResult authResult = await handler.AuthenticateAsync();

        authResult.Should().NotBeNull();
        authResult.Ticket.Should().NotBeNull();
        authResult.Ticket!.Principal.Should().NotBeNull();

        Claim? tenantIdClaim = authResult.Ticket.Principal.Claims.FirstOrDefault(e => e.Type == ClaimNames.tid);

        tenantIdClaim.Should().NotBeNull();
        tenantIdClaim!.Value.Should().NotBeNull();
    }

    [Fact]
    public async Task KeyCloakHandler_ChallengeWithoutRedirect_Returns401()
    {
        HttpContext ctx = GetHttpContextWithRequestAndResponse(RequestHeadersWoSecurity, HostString.FromUriComponent("yandex.ru:8080"), ResponseHeaders);
        KeyCloakAuthenticationHandler handler = await GetInitializedHandler(ctx);

        await handler.ChallengeAsync(null);

        ctx.Response.Should().NotBeNull();
        ctx.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task KeyCloakHandler_ChallengeWithRedirect_Returns302()
    {
        HttpContext ctx = GetHttpContextWithRequestAndResponse(RequestHeadersWoSecurity, HostString.FromUriComponent($"{ApiGatewayHost}:{ApiGatewayPort}"), ResponseHeaders);
        KeyCloakAuthenticationHandler handler = await GetInitializedHandler(ctx);

        await handler.ChallengeAsync(null);

        ctx.Response.Should().NotBeNull();
        ctx.Response.StatusCode.Should().Be(StatusCodes.Status302Found);
    }

    [Fact]
    public async Task KeyCloakHandler_ForbiddenResultReturns403()
    {
        HttpContext ctx = GetHttpContextWithRequestAndResponse(RequestHeadersWoSecurity, HostString.FromUriComponent("yandex.ru:8080"), ResponseHeaders);
        KeyCloakAuthenticationHandler handler = await GetInitializedHandler(ctx);

        await handler.ForbidAsync(null);

        ctx.Response.Should().NotBeNull();
        ctx.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
    }
}
