namespace Delobytes.AspNetCore.Infrastructure.Authentication;

/// <summary>
/// Настройки аутентификации.
/// </summary>
public class AuthenticationOptions
{
    /// <summary>
    /// <para>
    /// Тип аутентификации.
    /// </para>
    /// <para>Default: Bearer</para>
    /// </summary>
    public string AuthType { get; set; } = "Bearer";

    /// <summary>
    /// <para>
    /// Поставщик безопасности, который выписал токен. Используется при проверке ValidIssuer в токене.
    /// </para>
    /// </summary>
    public string? Authority { get; set; }

    /// <summary>
    /// <para>
    /// Аудитория, для которой выписан токен. Используется при проверке ValidAudience в токене.
    /// </para>
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// <para>
    /// Адрес конфигурации OpenID.
    /// </para>
    /// </summary>
    public string? OpenIdConfigurationEndpoint { get; set; }

    /// <summary>
    /// <para>
    /// Адрес публичного АПИ-шлюза (если используется), на который должно происходить перенаправление
    /// при необходимости повторной аутентификации.
    /// </para>
    /// </summary>
    public string? ApiGatewayHost { get; set; }

    /// <summary>
    /// <para>
    /// Порт публичного АПИ-шлюза (если используется), на который должно происходить перенаправление
    /// при необходимости повторной аутентификации.
    /// </para>
    /// </summary>
    public int? ApiGatewayPort { get; set; }

    /// <summary>
    /// <para>
    /// Путь (относительный) на который нужно перенаправлять клиента при необходимости повторной аутентификации.
    /// </para>
    /// </summary>
    public string? LoginRedirectPath { get; set; }

    /// <summary>
    /// <para>
    /// Список дополнительных удостоверений, которые пользователь должен получить из токена.
    /// </para>
    /// </summary>
    public IEnumerable<string> CustomClaims { get; set; } = new List<string>();

    /// <summary>
    /// <para>
    /// Имя удостоверения, которое даёт метаданные пользователя.
    /// </para>
    /// </summary>
    public string? AppMetadataClaimName { get; set; }

    /// <summary>
    /// <para>
    /// Таймаут валидации JWT-токена.
    /// </para>
    /// <para>Default: 10000</para>
    /// </summary>
    public int TokenValidationTimeoutMsec { get; set; } = 10000;

    /// <summary>
    /// <para>
    /// Параметры валидации JWT-токена.
    /// </para>
    /// </summary>
    public TokenValidationOptions? TokenValidationParameters { get; set; }
}
