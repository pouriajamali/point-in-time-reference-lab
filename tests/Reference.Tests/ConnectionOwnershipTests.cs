using System.Net;
using System.Net.Sockets;
using Npgsql;
using Xunit;
using ReferenceLab;

public sealed class ConnectionOwnershipTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(8);

    private sealed class Resource : IAsyncDisposable
    {
        public int Disposals { get; private set; }
        public Func<ValueTask> Cleanup { get; init; } = () => ValueTask.CompletedTask;

        public ValueTask DisposeAsync()
        {
            Disposals++;
            return Cleanup();
        }
    }

    [Fact]
    public async Task SuccessfulOpenTransfersOwnershipWithoutDisposal()
    {
        var resource = new Resource();
        using var cancellation = new CancellationTokenSource();
        var opened = await Store.OpenOwned(resource, (value, token) =>
        {
            Assert.Same(resource, value);
            Assert.Equal(cancellation.Token, token);
            return Task.CompletedTask;
        }, cancellation.Token);
        Assert.Same(resource, opened);
        Assert.Equal(0, resource.Disposals);
        await opened.DisposeAsync();
        Assert.Equal(1, resource.Disposals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedOpenDisposesExactlyOnceAndPreservesOriginalException(bool asynchronous)
    {
        var resource = new Resource();
        var original = new InvalidOperationException("synthetic-open-failure");
        Task Open(Resource _, CancellationToken __)
        {
            if (asynchronous) return Task.FromException(original);
            throw original;
        }
        var actual = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Store.OpenOwned(resource, Open, CancellationToken.None));
        Assert.Same(original, actual);
        Assert.Equal(1, resource.Disposals);
    }

    [Fact]
    public async Task CancellationDisposesAndPreservesOriginalTokenAndException()
    {
        var resource = new Resource();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var original = new OperationCanceledException(cancellation.Token);
        var actual = await Assert.ThrowsAsync<OperationCanceledException>(() =>
            Store.OpenOwned(resource, (_, _) => Task.FromException(original), cancellation.Token));
        Assert.Same(original, actual);
        Assert.Equal(cancellation.Token, actual.CancellationToken);
        Assert.Equal(1, resource.Disposals);
    }

    [Fact]
    public async Task FailedOpenWaitsForAsynchronousCleanupBeforeRethrowing()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resource = new Resource { Cleanup = async () =>
        {
            entered.SetResult();
            await finish.Task;
        }};
        var original = new InvalidOperationException("synthetic-open-failure");
        var open = Store.OpenOwned(resource, (_, _) => Task.FromException(original), CancellationToken.None);
        try
        {
            await Task.WhenAny(entered.Task, open).WaitAsync(Bound, TestContext.Current.CancellationToken);
            Assert.True(entered.Task.IsCompletedSuccessfully, "Cleanup must start on failed open.");
            Assert.False(open.IsCompleted);
        }
        finally
        {
            finish.TrySetResult();
            var actual = await Assert.ThrowsAsync<InvalidOperationException>(() => open.WaitAsync(Bound, TestContext.Current.CancellationToken));
            Assert.Same(original, actual);
        }
        Assert.Equal(1, resource.Disposals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CleanupFailureDoesNotReplaceOriginalOpenException(bool asynchronous)
    {
        var cleanupFailure = new ApplicationException("synthetic-cleanup-failure");
        var resource = new Resource { Cleanup = () =>
        {
            if (asynchronous) return ValueTask.FromException(cleanupFailure);
            throw cleanupFailure;
        }};
        var original = new InvalidOperationException("synthetic-open-failure");
        var actual = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Store.OpenOwned(resource, (_, _) => Task.FromException(original), CancellationToken.None));
        Assert.Same(original, actual);
        Assert.Equal(1, resource.Disposals);
    }

    private static NpgsqlConnection Connection(int port) => new(new NpgsqlConnectionStringBuilder
    {
        Host = "127.0.0.1", Port = port, Database = "synthetic", Username = "synthetic",
        Password = "synthetic", Pooling = false, Timeout = 3, CommandTimeout = 3,
        SslMode = SslMode.Disable
    }.ConnectionString);

    [Fact]
    public async Task RealNpgsqlConnectionIsDisposedAfterRefusedOpen()
    {
        using var reserved = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        reserved.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = Assert.IsType<IPEndPoint>(reserved.LocalEndPoint);
        await using var connection = Connection(endpoint.Port);
        using var bound = new CancellationTokenSource(Bound);
        var failure = await Assert.ThrowsAsync<NpgsqlException>(() =>
            Store.OpenOwned(connection, (db, token) => db.OpenAsync(token), bound.Token));
        Assert.Equal(SocketError.ConnectionRefused, Assert.IsType<SocketException>(failure.InnerException).SocketErrorCode);
        // Closed state also occurs without disposal. Reuse must instead prove object disposal.
        await Assert.ThrowsAsync<ObjectDisposedException>(() => connection.OpenAsync(bound.Token));
    }

    [Fact]
    public async Task RealNpgsqlConnectionIsDisposedAfterCancellationDuringHandshake()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(1);
        var endpoint = Assert.IsType<IPEndPoint>(listener.LocalEndpoint);
        await using var connection = Connection(endpoint.Port);
        using var bound = new CancellationTokenSource(Bound);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(bound.Token);
        OperationCanceledException? driverCancellation = null;
        async Task Open(NpgsqlConnection db, CancellationToken token)
        {
            try { await db.OpenAsync(token); }
            catch (OperationCanceledException error)
            {
                driverCancellation = error;
                throw;
            }
        }
        var open = Store.OpenOwned(connection, Open, cancellation.Token);
        using var accepted = await listener.AcceptTcpClientAsync(bound.Token);
        // This owned socket sends no PostgreSQL handshake response; no external database is used.
        cancellation.Cancel();
        var actual = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => open.WaitAsync(Bound, TestContext.Current.CancellationToken));
        Assert.True(cancellation.IsCancellationRequested);
        // The driver may use its own linked token. Preserve the exact driver exception/token.
        Assert.NotNull(driverCancellation);
        Assert.Same(driverCancellation, actual);
        Assert.Equal(driverCancellation.CancellationToken, actual.CancellationToken);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => connection.OpenAsync(bound.Token));
    }
}
