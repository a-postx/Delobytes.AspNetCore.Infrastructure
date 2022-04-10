# Delobytes.AspNetCore.Infrastructure
Infrastructure layer components for .Net Core web-API applications.

[RU](README.md), [EN](README.en.md)

## Installation

The fastest way to add package to your app is via [NuGet](https://www.nuget.org/packages/Delobytes.AspNetCore.Infrastructure):

    dotnet add package Delobytes.AspNetCore.Infrastructure

## Usage

## KeyCloak Authentication
Add JWT-authentication based on KeyCloak. You can add claim names that should be taken from JWT-token and added to the user identity if needed.

1. Set up KeyCloak, create realm and open its endpoint configuration page (/.well-known/openid-configuration).

2. Add KeyCloak authentication handler to your application:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddKeyCloakAuthentication("SchemeName", true, options =>
        {
            options.Authority = "https://mykeycloakinstallation.com/auth/realms/myrealm"; //"issuer" endpoint
            options.Audience = "account";
			options.OpenIdConfigurationEndpoint = "https://mykeycloakinstallation.com/auth/realms/myrealm/.well-known/openid-configuration";
            options.TokenValidationParameters = new TokenValidationOptions
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = "https://mykeycloakinstallation.com/auth/realms/myrealm",
                ValidateAudience = true,
                ValidAudience = "account",
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

3. Set attribute Authorize to a method or controller:

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
Add JWT-authentication based on Auth0. You can add claim names that should be taken from JWT-token and added to the user identity if needed.

1. Register on Auth0, create application and open its endpoint configuration page (/.well-known/openid-configuration).

2. Add authentication handler:  

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuth0Authentication("SchemeName", true, options =>
        {
            options.Authority = "https://dev-xxxxxxxx.eu.auth0.com";
            options.Audience = "https://myapp-audience.com";
			options.OpenIdConfigurationEndpoint = "https://dev-xxxxxxxx.eu.auth0.com/.well-known/openid-configuration";
			options.TokenValidationParameters = new TokenValidationOptions
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = "https://dev-xxxxxxxx.eu.auth0.com/",
                ValidateAudience = true,
                ValidAudience = "account",
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

3. Set attribute Authorize to a method or controller:

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