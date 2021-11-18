using System;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
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
    /// Добавляет в <see cref="IServiceCollection"/> и конвейер всё необходимое для аутентификации
    /// веб-АПИ приложения на базе OAuth2 (OpenID Connect) и JWT-токенов.
    /// Включает кастомный обработчик <see cref="IAuthenticationHandler"/> и обновление ключей шифрования токенов.
    /// </summary>
    /// <param name="services"><see cref="IServiceCollection"/> в которую нужно добавить аутентификацию.</param>
    /// <param name="oidcProviderIssuer">Адрес OpenID-совместимого (OIDC) OAuth2-провайдера, откуда следует забирать обновляемые ключи шифрования JWT-токенов.</param>
    /// <param name="configure"><see cref="Action{AuthenticationOptions}"/> для настройки <see cref="AuthenticationOptions"/>.</param>
    /// <returns>Ссылка на этот экземпляр после завершения операции.</returns>
    public static IServiceCollection AddOidcAuthentication(this IServiceCollection services, string oidcProviderIssuer, Action<AuthenticationOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        if (string.IsNullOrEmpty(oidcProviderIssuer))
        {
            throw new InvalidOperationException("Option value is required: " + nameof(oidcProviderIssuer));
        }

        services
            .AddOptions()
            .AddHttpContextAccessor()
            .AddLogging();

        services.Configure(configure);

        if (!services.Any(x => x.ServiceType == typeof(AuthenticationOptions)))
        {
            throw new InvalidOperationException("AuthenticationOptions must be registered for OIDC authentication.");
        }

        //забираем регулярно обновляемые ключи шифрования токенов с сервера провайдера
        services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(provider =>
            new ConfigurationManager<OpenIdConnectConfiguration>(
                oidcProviderIssuer + ".well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = true })
            );

        services.AddAuthenticationCore(o =>
        {
            o.DefaultScheme = "YaScheme";
            o.AddScheme<AuthenticationHandler>("YaScheme", "Authentication scheme that use claims extracted from JWT token.");
        });

        return services;
    }
}
