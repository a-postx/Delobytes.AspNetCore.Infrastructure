namespace Delobytes.AspNetCore.Infrastructure.Authentication;

internal class UserInfo
{
    internal UserInfo(string clientId, string userId, string tenantId = null,
        string tenantAccessType = null, string email = null, string emailVerified = null)
    {
        ClientId = clientId;
        UserId = userId;
        TenantId = tenantId;
        TenantAccessType = tenantAccessType;
        Email = email;
        EmailVerified = emailVerified;
    }

    internal string ClientId { get; set; }
    internal string UserId { get; set; }
    internal string TenantId { get; set; }
    internal string TenantAccessType { get; set; }
    internal string Email { get; set; }
    internal string EmailVerified { get; set; }
}
