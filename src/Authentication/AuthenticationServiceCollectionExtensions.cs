using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Delobytes.AspNetCore.Infrastructure.Authentication;

/// <summary>
/// Расширения <see cref="IServiceCollection"/> для регистрации сервисов.
/// </summary>
public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Добавляет в <see cref="IServiceCollection"/> всё необходимое для аутентификации на базе Auth0 (OAuth2, OpenID Connect и JWT-токены).
    /// </summary>
    /// <param name="services"><see cref="IServiceCollection"/> в которую нужно добавить аутентификацию.</param>
    /// <param name="oidcProviderIssuer">Адрес OpenID-совместимого (OIDC) OAuth2-провайдера, откуда следует забирать обновляемые ключи шифрования JWT-токенов.</param>
    /// <param name="authSchemeName">Название схемы аутентификации.</param>
    /// <param name="configure"><see cref="Action{AuthenticationOptions}"/> для настройки <see cref="AuthenticationOptions"/>.</param>
    /// <returns>Ссылка на этот экземпляр после завершения операции.</returns>
    public static IServiceCollection AddAuth0Authentication(this IServiceCollection services, string oidcProviderIssuer, string authSchemeName, Action<AuthenticationOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        if (string.IsNullOrEmpty(oidcProviderIssuer))
        {
            throw new InvalidOperationException("Parameter value is required: " + nameof(oidcProviderIssuer));
        }

        if (string.IsNullOrEmpty(authSchemeName))
        {
            throw new InvalidOperationException("Parameter value is required: " + nameof(authSchemeName));
        }
        
        services
            .AddOptions()
            .AddHttpContextAccessor()
            .AddLogging();

        services.AddSingleton(options => new AuthenticationOptions());
        services.Configure(configure);

        //забираем регулярно обновляемые ключи шифрования токенов с сервера провайдера
        services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(provider =>
            new ConfigurationManager<OpenIdConnectConfiguration>(
                oidcProviderIssuer + ".well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = true })
            );

        services.AddAuthenticationCore(o =>
        {
            o.DefaultScheme = authSchemeName;
            o.AddScheme<AuthenticationHandler>(authSchemeName, "Authentication scheme that use claims extracted from JWT token.");
        });

        return services;
    }
}
