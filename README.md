# Delobytes.AspNetCore.Infrastructure
Компоненты инфраструктурного слоя для веб-АПИ приложений.

[RU](README.md), [EN](README.en.md)

## Установка

Для добавления пакета в ваше приложение вы можете использовать [NuGet](https://www.nuget.org/packages/Delobytes.AspNetCore.Infrastructure):

    dotnet add package Delobytes.AspNetCore.Infrastructure

## Использование

### Аутентификация на базе KeyCloak
Добавляет JWT-аутентификацию на базе KeyCloak со специфическими настройками интеграции.

1. Установите KeyCloak и откройте страницу описания конечных точек инсталляции (/.well-known/openid-configuration).

2. Добавьте обработчик Кейклоук аутентификации в ваше .Net Core приложение:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddKeyCloakAuthentication("SchemeName", true, options =>
        {
            options.Authority = "https://mykeycloakinstallation.com/auth/realms/myrealm"; //"issuer" endpoint
            options.Audience = "account";
			options.OpenIdConfigurationEndpoint = "https://mykeycloakinstallation.com/auth/realms/myrealm/.well-known/openid-configuration";
            options.LoginRedirectPath = "/authentication/login";
            options.EmailClaimName = "email";
            options.EmailVerifiedClaimName = "email_verified";
            options.TenantIdClaimName = "tid";
            options.TenantAccessTypeClaimName = "tenantaccesstype";
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

3. Поместите атрибут Authorize к методу или ко всему контроллеру, чтобы доступ могли получить только аутентифицированные пользователи:

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

### Аутентификация на базе Auth0
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

2. Поместите атрибут Authorize к методу или ко всему контроллеру, чтобы доступ могли получить только аутентифицированные пользователи:

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