namespace Delobytes.AspNetCore.Infrastructure.Tests.Dto;

public record KeyCloakErrorResponse
{
    public string? Error { get; init; }
    public string? Error_description { get; init; }
}
