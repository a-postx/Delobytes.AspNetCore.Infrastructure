namespace Delobytes.AspNetCore.Infrastructure.Authentication.Dto;

/// <summary>
/// Метаданные пользователя, которые получаются при использовании провайдера Auth0
/// </summary>
public class AppMetadata
{
    /// <summary>
    /// Идентификатор арендатора.
    /// </summary>
    public string Tid { get; set; }
    /// <summary>
    /// Тип доступа пользователя к арендатору.
    /// </summary>
    public string TenantAccessType { get; set; }
}
