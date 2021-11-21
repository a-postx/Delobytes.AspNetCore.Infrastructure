# Delobytes.AspNetCore.Infrastructure
Компоненты инфраструктурного слоя для веб-АПИ приложений.

[RU](README.md), [EN](README.en.md)

## Authentication
Добавляет JWT-аутентификацию на базе сервиса Auth0 со специфическими настройками интеграции.

1. Добавьте обработчик аутентификации:  

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

2. Поместите атрибут Authorize к методу или ко всему контроллеру:

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

## Лицензия
[МИТ](https://github.com/a-postx/Delobytes.AspNetCore.Infrastructure/blob/master/LICENSE)