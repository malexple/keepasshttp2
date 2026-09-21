using KeePassHttp2.Protocol;
using Xunit;

namespace KeePassHttp2.Tests;

public class NonceTrackerTests
{
    [Fact]
    public void FreshNonce_IsNotReplay()
    {
        var tracker = new NonceTracker();
        Assert.False(tracker.IsReplay("client1", "nonceA"));
    }

    [Fact]
    public void RegisteredNonce_IsReplay_ForSameClient()
    {
        var tracker = new NonceTracker();
        tracker.Register("client1", "nonceA");
        Assert.True(tracker.IsReplay("client1", "nonceA"));
    }

    [Fact]
    public void RegisteredNonce_IsNotReplay_ForDifferentClient()
    {
        var tracker = new NonceTracker();
        tracker.Register("client1", "nonceA");
        Assert.False(tracker.IsReplay("client2", "nonceA"));
    }

    [Fact]
    public void DifferentNonce_SameClient_IsNotReplay()
    {
        var tracker = new NonceTracker();
        tracker.Register("client1", "nonceA");
        Assert.False(tracker.IsReplay("client1", "nonceB"));
    }

    [Fact]
    public void Forget_ClearsHistoryForThatClient()
    {
        var tracker = new NonceTracker();
        tracker.Register("client1", "nonceA");
        tracker.Forget("client1");
        Assert.False(tracker.IsReplay("client1", "nonceA"));
    }

    [Fact]
    public void Forget_DoesNotAffectOtherClients()
    {
        var tracker = new NonceTracker();
        tracker.Register("client1", "nonceA");
        tracker.Register("client2", "nonceB");
        tracker.Forget("client1");
        Assert.True(tracker.IsReplay("client2", "nonceB"));
    }

    [Fact]
    public void HistoryIsBounded_OldestNoncesAreForgotten()
    {
        var tracker = new NonceTracker();
        const int overCapacity = 4096 + 10;

        for (int i = 0; i < overCapacity; i++)
            tracker.Register("client1", $"nonce{i}");

        // The very first nonce should have been evicted once the
        // per-client history exceeded its cap.
        Assert.False(tracker.IsReplay("client1", "nonce0"));

        // A recent nonce must still be tracked.
        Assert.True(tracker.IsReplay("client1", $"nonce{overCapacity - 1}"));
    }
}