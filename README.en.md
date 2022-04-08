# Delobytes.AspNetCore.Infrastructure
Infrastructure layer components for web-API applications.

[RU](README.md), [EN](README.en.md)

## Installation

The fastest way to add package to your app is via [NuGet](https://www.nuget.org/packages/Delobytes.AspNetCore.Infrastructure):

    dotnet add package Delobytes.AspNetCore.Infrastructure

## Usage

## KeyCloak Authentication
Add JWT-authentication based on KeyCloak with specific integration settings.

1. Add authentication handler:  

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddKeyCloakAuthentication("SchemeName", true, options =>
        {
            options.Authority = oauthOptions.Authority;
            options.Audience = oauthOptions.Audience;
            options.LoginRedirectPath = "/authentication/login";
            options.ApiGatewayHost = oauthOptions.ApiGatewayHost;
            options.ApiGatewayPort = oauthOptions.ApiGatewayPort;
            options.EmailClaimName = "email";
            options.EmailVerifiedClaimName = "email_verified";
            options.TenantIdClaimName = "tid";
            options.TenantAccessTypeClaimName = "tenantaccesstype";
            options.OpenIdConfigurationEndpoint = oauthOptions.OidcIssuer + "/.well-known/openid-configuration";
            options.TokenValidationParameters = new TokenValidationOptions
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = oauthOptions.Authority,
                ValidateAudience = true,
                ValidAudience = oauthOptions.Audience,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(2),
            };
        });
}

public void Configure(IApplicationBuilder application)
{
    application
        .UseAuthentication();     
}
```

2. Set attribute Authorize to a method or controller:

```
[Route("[controller]")]
[ApiController]
[Authorize]
public class HomeController : ControllerBase
{
    [HttpPost]
    public Task<IActionResult> PostInfoAsync(
        [FromServices] IPostClientInfoAh handler,
        [FromBody] InfoSm infoSm,
        CancellationToken cancellationToken)
    {
        return handler.ExecuteAsync(infoSm, cancellationToken);
    }
}
```

## Auth0 Authentication
Add JWT-authentication based on Auth0 with specific integration settings.

1. Add authentication handler:  

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuth0Authentication(secrets.OidcProviderIssuer, "SchemeName", options =>
        {
            options.Authority = oauthOptions.Authority;
            options.Audience = oauthOptions.Audience;
            options.LoginRedirectPath = "/authentication/login";
            options.ApiGatewayHost = secrets.ApiGatewayHost;
            options.ApiGatewayPort = secrets.ApiGatewayPort;
            options.EmailClaimName = "email_claim_name";
            options.EmailVerifiedClaimName = "email_verified_claim_name";
            options.AppMetadataClaimName = "app_metadata_claim_name";
        });
}

public void Configure(IApplicationBuilder application)
{
    application
        .UseAuthentication();     
}
```

2. Set attribute Authorize to a method or controller:

```
[Route("[controller]")]
[ApiController]
[Authorize]
public class HomeController : ControllerBase
{
    [HttpPost]
    public Task<IActionResult> PostInfoAsync(
        [FromServices] IPostClientInfoAh handler,
        [FromBody] InfoSm infoSm,
        CancellationToken cancellationToken)
    {
        return handler.ExecuteAsync(infoSm, cancellationToken);
    }
}
```

## License
[MIT](https://github.com/a-postx/Delobytes.AspNetCore.Infrastructure/blob/master/LICENSE)