// Zero-dependency test runner for NonceTracker (avoids needing NuGet
// restore access to run six simple assertions).
// Run: dotnet run

using System;
using KeePassHttp2.Protocol;

int passed = 0, failed = 0;

void Check(string name, bool condition)
{
    if (condition)
    {
        Console.WriteLine($"PASS: {name}");
        passed++;
    }
    else
    {
        Console.WriteLine($"FAIL: {name}");
        failed++;
    }
}

// 1. Fresh nonce is not a replay.
{
    var tracker = new NonceTracker();
    Check("FreshNonce_IsNotReplay", !tracker.IsReplay("client-a", "nonce-1"));
}

// 2. Registered nonce is a replay on second sighting.
{
    var tracker = new NonceTracker();
    tracker.Register("client-a", "nonce-1");
    Check("RegisteredNonce_IsReplayOnSecondSighting", tracker.IsReplay("client-a", "nonce-1"));
}

// 3. Different clients do not share nonce history.
{
    var tracker = new NonceTracker();
    tracker.Register("client-a", "nonce-1");
    Check("DifferentClients_DoNotShareNonceHistory", !tracker.IsReplay("client-b", "nonce-1"));
}

// 4. Registering the same nonce repeatedly must not break eviction.
{
    var tracker = new NonceTracker();
    for (int i = 0; i < 10; i++)
        tracker.Register("client-a", "nonce-1");
    tracker.Register("client-a", "nonce-2");

    Check("RegisteringSameNonceTwice_nonce1_stillTracked", tracker.IsReplay("client-a", "nonce-1"));
    Check("RegisteringSameNonceTwice_nonce2_tracked", tracker.IsReplay("client-a", "nonce-2"));
}

// 5. Oldest nonce is evicted after the cap is exceeded.
{
    var tracker = new NonceTracker();
    const int cap = 4096; // must match NonceTracker.MaxNoncesPerClient

    for (int i = 0; i < cap; i++)
        tracker.Register("client-a", $"nonce-{i}");

    Check("BeforeOverflow_nonce0_stillTracked", tracker.IsReplay("client-a", "nonce-0"));

    tracker.Register("client-a", "nonce-overflow");

    Check("AfterOverflow_nonce0_evicted", !tracker.IsReplay("client-a", "nonce-0"));
    Check("AfterOverflow_nonce1_stillTracked", tracker.IsReplay("client-a", "nonce-1"));
    Check("AfterOverflow_overflowNonce_tracked", tracker.IsReplay("client-a", "nonce-overflow"));
}

// 6. Forget clears client history.
{
    var tracker = new NonceTracker();
    tracker.Register("client-a", "nonce-1");
    tracker.Forget("client-a");
    Check("Forget_ClearsClientHistory", !tracker.IsReplay("client-a", "nonce-1"));
}

Console.WriteLine();
Console.WriteLine($"Passed: {passed}, Failed: {failed}");
Environment.Exit(failed == 0 ? 0 : 1);
