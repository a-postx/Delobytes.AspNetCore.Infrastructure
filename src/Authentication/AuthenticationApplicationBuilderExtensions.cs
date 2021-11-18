using System;
using Microsoft.AspNetCore.Builder;

namespace Delobytes.AspNetCore.Infrastructure.Authentication;

/// <summary>
/// Методы расширения.
/// </summary>
public static class AuthenticationApplicationBuilderExtensions
{
    /// <summary>
    /// Добавляет аутентификацию веб-АПИ приложения на базе Auth0 (OAuth2, OpenID Connect и JWT-токены).
    /// </summary>
    /// <param name="app"></param>
    /// <returns></returns>
    public static IApplicationBuilder UseAuth0Authentication(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseAuthentication();
    }
}

