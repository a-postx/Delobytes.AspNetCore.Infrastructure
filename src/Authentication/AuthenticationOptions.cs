using System;

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
    /// Таймаут валидации JWT-токена.
    /// </para>
    /// <para>Default: 10000</para>
    /// </summary>
    public int SecurityTokenValidationTimeoutMsec { get; set; } = 10000;

    /// <summary>
    /// <para>
    /// Поставщик безопасности, который выписал токен. Используется при проверке ValidIssuer в токене.
    /// </para>
    /// </summary>
    public string Authority { get; set; }

    /// <summary>
    /// <para>
    /// Аудитория, для которой выписан токен. Используется при проверке ValidAudience в токене.
    /// </para>
    /// </summary>
    public string Audience { get; set; }

    /// <summary>
    /// <para>
    /// Адрес публичного АПИ-шлюза (если используется), на который должно происходить перенаправление
    /// при необходимости повторной аутентификации.
    /// </para>
    /// </summary>
    public string ApiGatewayHost { get; set; }

    /// <summary>
    /// <para>
    /// Порт публичного АПИ-шлюза (если используется), на который должно происходить перенаправление
    /// при необходимости повторной аутентификации.
    /// </para>
    /// </summary>
    public int ApiGatewayPort { get; set; }

    /// <summary>
    /// <para>
    /// Путь (относительный) на который нужно перенаправлять клиента при необходимости повторной аутентификации.
    /// </para>
    /// </summary>
    public string LoginRedirectPath { get; set; }

    /// <summary>
    /// <para>
    /// Имя удостоверения, которое даёт электропочту пользователя.
    /// </para>
    /// </summary>
    public string EmailClaimName { get; set; }

    /// <summary>
    /// <para>
    /// Имя удостоверения, которое даёт признак подтверждения электропочты пользователя.
    /// </para>
    /// </summary>
    public string EmailVerifiedClaimName { get; set; }

    /// <summary>
    /// <para>
    /// Имя удостоверения, которое даёт метаданные пользователя.
    /// </para>
    /// </summary>
    public string AppMetadataClaimName { get; set; }

    /// <summary>
    /// <para>
    /// Временной лаг, который будет допустимым при валидации JWT-токена.
    /// </para>
    /// <para>Default: 2 минуты</para>
    /// </summary>
    public TimeSpan TokenValidationClockSkew { get; set; } = TimeSpan.FromMinutes(2);
}
