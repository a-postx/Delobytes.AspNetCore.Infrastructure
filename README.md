# Delobytes.AspNetCore.Infrastructure
Компоненты инфраструктурного слоя для веб-АПИ приложений.

[RU](README.md), [EN](README.en.md)

## Установка

Для добавления пакета в ваше приложение вы можете использовать [NuGet](https://www.nuget.org/packages/Delobytes.AspNetCore.Infrastructure):

    dotnet add package Delobytes.AspNetCore.Infrastructure

## Использование

### Аутентификация с помощью KeyCloak
Добавляет JWT-аутентификацию на базе KeyCloak. Если необходимо, вы можете добавить названия удостоверений, которые будут взяты из токена и добавлены аутентифицированному пользователю.

1. Установите KeyCloak, создайте рилм и откройте его страницу описания конечных точек (/.well-known/openid-configuration).

2. Добавьте обработчик Кейклоук аутентификации в ваше .Net Core приложение:

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
Добавляет JWT-аутентификацию на базе сервиса Auth0. Если необходимо, вы можете добавить названия удостоверений, которые будут взяты из токена и добавлены аутентифицированному пользователю.

1. Зарегистрируйтесь в Auth0, создайте приложение и откройте его страницу описания конечных точек (/.well-known/openid-configuration).

2. Добавьте обработчик аутентификации:

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

## Лицензия
[МИТ](https://github.com/a-postx/Delobytes.AspNetCore.Infrastructure/blob/master/LICENSE)