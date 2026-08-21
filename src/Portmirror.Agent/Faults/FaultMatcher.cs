namespace Portmirror.Agent.Faults;

/// <summary>
/// Chooses the first enabled rule that matches a request. Pure and allocation-light so it can run
/// on every request in the IIS pipeline without adding meaningful latency.
/// </summary>
public static class FaultMatcher
{
    public static FaultDecision? Match(IReadOnlyList<FaultRule>? rules, string? method, string? path)
    {
        if (rules is null || rules.Count == 0)
        {
            return null;
        }

        method ??= string.Empty;
        path ??= string.Empty;

        foreach (var rule in rules)
        {
            if (!rule.Enabled)
            {
                continue;
            }

            if (!string.IsNullOrEmpty(rule.Method)
                && !string.Equals(rule.Method, method, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrEmpty(rule.PathContains)
                && path.IndexOf(rule.PathContains, StringComparison.OrdinalIgnoreCase) < 0)
            {
                continue;
            }

            return new FaultDecision
            {
                Status = rule.Status,
                Body = rule.Body,
                ContentType = rule.ContentType,
                DelayMs = rule.DelayMs < 0 ? 0 : rule.DelayMs
            };
        }

        return null;
    }
}
