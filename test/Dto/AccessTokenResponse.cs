namespace Delobytes.AspNetCore.Infrastructure.Tests.Dto;

public record AccessTokenResponse
{
    public string? Access_token { get; init; }
    public int? Expires_in { get; init; }
    public string? Scope { get; init; }
    public string? Token_type { get; init; }
}
