using Portmirror.Agent.Faults;
using Xunit;

namespace Portmirror.Tests;

public class FaultMatcherTests
{
    private static List<FaultRule> Rules(params FaultRule[] r) => new(r);

    [Fact]
    public void No_rules_matches_nothing()
    {
        Assert.Null(FaultMatcher.Match(null, "GET", "/x"));
        Assert.Null(FaultMatcher.Match(Rules(), "GET", "/x"));
    }

    [Fact]
    public void Matches_by_path_substring_and_returns_the_action()
    {
        var d = FaultMatcher.Match(Rules(new FaultRule { PathContains = "/pay", Status = 503 }), "POST", "/api/pay");

        Assert.NotNull(d);
        Assert.Equal(503, d!.Status);
    }

    [Fact]
    public void Method_filter_is_honoured_and_case_insensitive()
    {
        var rules = Rules(new FaultRule { Method = "post", PathContains = "/pay", Status = 500 });

        Assert.NotNull(FaultMatcher.Match(rules, "POST", "/pay"));
        Assert.Null(FaultMatcher.Match(rules, "GET", "/pay"));
    }

    [Fact]
    public void A_rule_with_no_method_or_path_matches_everything()
    {
        var d = FaultMatcher.Match(Rules(new FaultRule { Status = 418 }), "GET", "/anything");
        Assert.Equal(418, d!.Status);
    }

    [Fact]
    public void Disabled_rules_are_skipped()
    {
        var rules = Rules(
            new FaultRule { Enabled = false, PathContains = "/pay", Status = 500 },
            new FaultRule { PathContains = "/pay", Status = 503 });

        Assert.Equal(503, FaultMatcher.Match(rules, "POST", "/pay")!.Status);
    }

    [Fact]
    public void The_first_matching_rule_wins()
    {
        var rules = Rules(
            new FaultRule { PathContains = "/api", Status = 500 },
            new FaultRule { PathContains = "/api/pay", Status = 503 });

        Assert.Equal(500, FaultMatcher.Match(rules, "GET", "/api/pay")!.Status);
    }

    [Fact]
    public void A_delay_only_rule_is_flagged_as_such()
    {
        var d = FaultMatcher.Match(Rules(new FaultRule { PathContains = "/slow", Status = 0, DelayMs = 2000 }), "GET", "/slow");

        Assert.NotNull(d);
        Assert.True(d!.DelayOnly);
        Assert.Equal(2000, d.DelayMs);
    }

    [Fact]
    public void A_negative_delay_is_clamped_to_zero()
    {
        var d = FaultMatcher.Match(Rules(new FaultRule { PathContains = "/x", DelayMs = -5 }), "GET", "/x");
        Assert.Equal(0, d!.DelayMs);
    }
}
