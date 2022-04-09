using System.Collections.Generic;
using Microsoft.Extensions.Options;

namespace Delobytes.AspNetCore.Infrastructure.Authentication;

/// <summary>
/// Валидатор настроек аутентификации.
/// </summary>
public class AuthenticationOptionsValidator : IValidateOptions<AuthenticationOptions>
{
    /// <summary>
    /// Проверяет настройки аутентификации.
    /// </summary>
    /// <param name="name">Имя.</param>
    /// <param name="options">Настройки.</param>
    /// <returns></returns>
    public ValidateOptionsResult Validate(string name, AuthenticationOptions options)
    {
        List<string> failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Authority))
        {
            failures.Add($"{nameof(options.Authority)} option is not found.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            failures.Add($"{nameof(options.Audience)} option is not found.");
        }

        if (string.IsNullOrWhiteSpace(options.OpenIdConfigurationEndpoint))
        {
            failures.Add($"{nameof(options.OpenIdConfigurationEndpoint)} option is not found.");
        }

        if (options.TokenValidationParameters == null)
        {
            failures.Add($"{nameof(options.TokenValidationParameters)} option is not found.");
        }

        if (failures.Count > 0)
        {
            return ValidateOptionsResult.Fail(failures);
        }
        else
        {
            return ValidateOptionsResult.Success;
        }
    }
}
