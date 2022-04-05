namespace Delobytes.AspNetCore.Infrastructure.Authentication;

/// <summary>
/// Параметры валидации jwt-токена.
/// </summary>
public class TokenValidationOptions
{
    /// <summary>
    /// <para>
    /// Требовать наличие подписи.
    /// </para>
    /// <para>Default: true</para>
    /// </summary>
    public bool RequireSignedTokens { get; set; } = true;

    /// <summary>
    /// <para>
    /// Проверять ключи центра валидации.
    /// </para>
    /// <para>Default: true</para>
    /// </summary>
    public bool ValidateIssuerSigningKey { get; set; }

    /// <summary>
    /// <para>
    /// Проверять центр валидации.
    /// </para>
    /// <para>Default: true</para>
    /// </summary>
    public bool ValidateIssuer { get; set; } = true;

    /// <summary>
    /// <para>
    /// Авторизованный центр валидации.
    /// </para>
    /// <para>Default: true</para>
    /// </summary>
    public string ValidIssuer { get; set; }

    /// <summary>
    /// <para>
    /// Проверять целевую аудиторию.
    /// </para>
    /// <para>Default: true</para>
    /// </summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>
    /// <para>
    /// Авторизованная целевая аудитория.
    /// </para>
    /// <para>Default: true</para>
    /// </summary>
    public string ValidAudience { get; set; }

    /// <summary>
    /// <para>
    /// Требовать наличие времени жизни.
    /// </para>
    /// <para>Default: true</para>
    /// </summary>
    public bool RequireExpirationTime { get; set; } = true;

    /// <summary>
    /// <para>
    /// Проверять время жизни.
    /// </para>
    /// <para>Default: true</para>
    /// </summary>
    public bool ValidateLifetime { get; set; } = true;

    /// <summary>
    /// <para>
    /// Временной лаг, который будет допустимым при валидации времени жизни JWT-токена.
    /// </para>
    /// <para>Default: 5 минут</para>
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(300);
}
