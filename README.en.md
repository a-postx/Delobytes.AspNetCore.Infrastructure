# Delobytes.AspNetCore.Idempotency
Infrastructure layer components for web-API applications.

[RU](README.md), [EN](README.en.md)

## Authentication
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
        .UseAuth0Authentication();     
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