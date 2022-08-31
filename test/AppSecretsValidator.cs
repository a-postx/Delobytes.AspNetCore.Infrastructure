namespace Delobytes.AspNetCore.Infrastructure.Tests;

public class AppSecretsValidator : IValidateOptions<AppSecrets>
{
    public ValidateOptionsResult Validate(string name, AppSecrets options)
    {
        List<string> failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.RealmUrl))
        {
            failures.Add($"{nameof(options.RealmUrl)} secret is not found.");
        }

        if (string.IsNullOrWhiteSpace(options.Username))
        {
            failures.Add($"{nameof(options.Username)} secret is not found.");
        }

        if (string.IsNullOrWhiteSpace(options.Password))
        {
            failures.Add($"{nameof(options.Password)} secret is not found.");
        }

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            failures.Add($"{nameof(options.ClientId)} secret is not found.");
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

