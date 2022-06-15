namespace Delobytes.AspNetCore.Infrastructure.Authentication;

/// <summary>
/// Имена удостоверений пользователя.
/// </summary>
public static class ClaimNames
{
#pragma warning disable IDE1006 // JWT-стандарт использует нижний регистр
    /// <summary>
    /// Идентификатор клиентского приложения.
    /// </summary>
    public const string cid = nameof(cid);
    /// <summary>
    /// Идентификатор пользователя.
    /// </summary>
    public const string uid = nameof(uid);
    /// <summary>
    /// Идентификатор пользователя в рамках провайдера.
    /// </summary>
    public const string sub = nameof(sub);
    /// <summary>
    /// Идентификатор арендатора.
    /// </summary>
    public const string tid = nameof(tid);
    /// <summary>
    /// Электропочта.
    /// </summary>
    public const string email = nameof(email);
    /// <summary>
    /// Признак проверенной электропочты.
    /// </summary>
    public const string email_verified = nameof(email_verified);
    /// <summary>
    /// Имя пользователя.
    /// </summary>
    public const string name = nameof(name);
    /// <summary>
    /// Роль пользователя.
    /// </summary>
    public const string role = nameof(role);
    /// <summary>
    /// Идентификатор клиентского приложения в рамках провайдера.
    /// </summary>
    public const string azp = nameof(azp);
    /// <summary>
    /// Тип доступа к арендатору.
    /// </summary>
    public const string tenantaccesstype = nameof(tenantaccesstype);
#pragma warning restore IDE1006 // Naming Styles
}
