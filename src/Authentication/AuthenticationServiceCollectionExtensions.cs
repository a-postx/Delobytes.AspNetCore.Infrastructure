using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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
    /// <param name="authSchemeName">Название схемы аутентификации.</param>
    /// <param name="defaultScheme">Признак использования схемы по-умолчанию.</param>
    /// <param name="configureOptions"><see cref="Action{AuthenticationOptions}"/> для настройки <see cref="AuthenticationOptions"/>.</param>
    /// <returns>Ссылка на этот экземпляр после завершения операции.</returns>
    public static IServiceCollection AddAuth0Authentication(this IServiceCollection services, string authSchemeName, bool defaultScheme, Action<AuthenticationOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        if (string.IsNullOrEmpty(authSchemeName))
        {
            throw new InvalidOperationException("Parameter value is required: " + nameof(authSchemeName));
        }

        services
            .AddOptions()
            .AddHttpContextAccessor()
            .AddLogging();

        services.AddSingleton<IValidateOptions<AuthenticationOptions>, AuthenticationOptionsValidator>();

        services.AddSingleton(options => new AuthenticationOptions());
        services.Configure(configureOptions);

        services.AddSigningKeysRenewal();

        services.AddAuthenticationCore(o =>
        {
            o.AddScheme<Auth0AuthenticationHandler>(authSchemeName, "Auth0 authentication scheme.");

            if (defaultScheme)
            {
                o.DefaultScheme = authSchemeName;
            }
        });

        return services;
    }

    /// <summary>
    /// Добавляет в <see cref="IServiceCollection"/> всё необходимое для аутентификации на базе KeyCloak (OAuth2, OpenID Connect и JWT-токены).
    /// </summary>
    /// <param name="services"><see cref="IServiceCollection"/> в которую нужно добавить аутентификацию.</param>
    /// <param name="authSchemeName">Название схемы аутентификации.</param>
    /// <param name="defaultScheme">Признак использования схемы по-умолчанию.</param>
    /// <param name="configureOptions"><see cref="Action{AuthenticationOptions}"/> для настройки <see cref="AuthenticationOptions"/>.</param>
    /// <returns>Ссылка на этот экземпляр после завершения операции.</returns>
    public static IServiceCollection AddKeyCloakAuthentication(this IServiceCollection services, string authSchemeName, bool defaultScheme, Action<AuthenticationOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        if (string.IsNullOrEmpty(authSchemeName))
        {
            throw new InvalidOperationException("Parameter value is required: " + nameof(authSchemeName));
        }

        services
            .AddOptions()
            .AddHttpContextAccessor()
            .AddLogging();

        services.AddSingleton<IValidateOptions<AuthenticationOptions>, AuthenticationOptionsValidator>();

        services.AddSingleton(options => new AuthenticationOptions());
        services.Configure(configureOptions);

        services.AddSigningKeysRenewal();

        services.AddAuthenticationCore(o =>
        {
            o.AddScheme<KeyCloakAuthenticationHandler>(authSchemeName, "KeyCloak authentication scheme.");

            if (defaultScheme)
            {
                o.DefaultScheme = authSchemeName;
            }
        });

        return services;
    }

    /// <summary>
    /// Добавляет в <see cref="IServiceCollection"/> источник автоматического обновления ключей шифрования JWT-токенов.
    /// </summary>
    /// <param name="services"><see cref="IServiceCollection"/> в которую нужно добавить автоматическое обновление ключей подписи.</param>
    /// <returns>Ссылка на этот экземпляр после завершения операции.</returns>
    private static IServiceCollection AddSigningKeysRenewal(this IServiceCollection services)
    {
        services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(provider =>
        {
            AuthenticationOptions authOptions = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

            return new ConfigurationManager<OpenIdConnectConfiguration>(
                authOptions.OpenIdConfigurationEndpoint,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = true });
        });

        return services;
    }
}
