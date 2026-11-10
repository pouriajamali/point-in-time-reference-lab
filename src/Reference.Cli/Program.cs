using System.Globalization;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using ReferenceLab;

const int FrameCap = 16384;
try
{
    if (args.Length == 1 && args[0] is "--help" or "--version")
    {
        Console.WriteLine(JsonSerializer.Serialize(new { version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion, usage = "Synthetic literal-loopback point-in-time reference: init | serve PORT | head URL | ingest URL JSONFILE | query URL EFFECTIVE_AT KNOWN_REVISION | history URL AFTER_REVISION. Explicit committed revision, never wall-clock known-at." }));
        return 0;
    }

    if (args.SequenceEqual(new[] { "init" }))
    {
        using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await new Store().Init(bound.Token);
        Console.WriteLine("{\"status\":\"INITIALIZED_FRESH\"}");
        return 0;
    }

    if (args.Length == 2 && args[0] == "serve")
    {
        if (!int.TryParse(args[1], out var port) || port is < 1024 or > 65535)
            throw new ArgumentException("PORT");
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = Array.Empty<string>(), ContentRootPath = AppContext.BaseDirectory, EnvironmentName = Environments.Production });
        builder.Configuration.Sources.Clear();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton<Store>();
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Limits.MaxRequestBodySize = FrameCap;
            k.Limits.MaxRequestHeadersTotalSize = 8192;
            k.Limits.MaxRequestLineSize = 4096;
            k.Limits.MaxConcurrentConnections = 16;
            k.Listen(IPAddress.Loopback, port, l => l.Protocols = HttpProtocols.Http1);
        });
        var app = builder.Build();
        using var slots = new SemaphoreSlim(8, 8);
        app.MapPost("/v1/instruments/SYNTH/corrections", async (HttpRequest request, Store store) =>
        {
            using var bound = CancellationTokenSource.CreateLinkedTokenSource(request.HttpContext.RequestAborted);
            bound.CancelAfter(TimeSpan.FromSeconds(6));
            if (!await slots.WaitAsync(0, bound.Token))
                return Json(new { status = "BUSY" }, 503);
            string? id = null;
            try
            {
                if (request.Query.Count != 0 || (request.ContentLength is long length && length > FrameCap))
                    throw new ArgumentException("REQUEST_FRAME");
                var bytes = await ReadBounded(request.Body, bound.Token);
                var input = JsonSerializer.Deserialize<CorrectionInput>(bytes, Wire.Options) ?? throw new ArgumentException("REQUEST_BODY");
                var correction = Contract.Validate(input);
                id = correction.OperationId;
                var outcome = await store.Apply(correction, bound.Token);
                return Json(outcome, outcome.Status is "IDENTITY_CONFLICT" or "CAPACITY_REJECTED" ? 409 : 200);
            }
            catch (Exception error)when (error is ArgumentException or JsonException or FormatException or OverflowException)
            {
                return Json(new { status = "DENIED", operationId = id, error = error.GetType().Name }, 400);
            }
            catch (Exception error)when (error is Npgsql.NpgsqlException or OperationCanceledException or IOException or InvalidOperationException)
            {
                return Json(new { status = "UNKNOWN", operationId = id, detail = "Resolve only with the SAME identity and canonical correction." }, 503);
            }
            finally
            {
                slots.Release();
            }
        });
        app.MapGet("/v1/instruments/SYNTH/head", async (HttpRequest request, Store store) => await ReadEndpoint(request, slots, async token =>
        {
            if (request.Query.Count != 0)
                throw new ArgumentException("QUERY");
            return await store.Head(token);
        }));
        app.MapGet("/v1/instruments/SYNTH/value", async (HttpRequest request, Store store) => await ReadEndpoint(request, slots, async token =>
        {
            RequireQuery(request, "effectiveAt", "knownThroughRevision");
            return await store.Query(Instant.Parse(request.Query["effectiveAt"].ToString()), Revision(request.Query["knownThroughRevision"].ToString(), false), token);
        }));
        app.MapGet("/v1/instruments/SYNTH/history", async (HttpRequest request, Store store) => await ReadEndpoint(request, slots, async token =>
        {
            RequireQuery(request, "afterRevision");
            return await store.History(Revision(request.Query["afterRevision"].ToString(), true), token);
        }));
        await app.RunAsync();
        return 0;
    }

    if (args.Length >= 2 && args[0] is "head" or "ingest" or "query" or "history")
    {
        var root = Endpoint(args[1]);
        string path;
        HttpMethod method = HttpMethod.Get;
        byte[]? body = null;
        string? operationId = null;
        Correction? expectedCorrection = null;
        DateTime? expectedAt = null;
        long expectedRevision = 0;
        if (args[0] == "head" && args.Length == 2)
            path = "head";
        else if (args[0] == "ingest" && args.Length == 3)
        {
            using var file = File.OpenRead(args[2]);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var bytes = await ReadBounded(file, deadline.Token);
            var input = JsonSerializer.Deserialize<CorrectionInput>(bytes, Wire.Options) ?? throw new ArgumentException("INPUT");
            var normalized = Contract.Validate(input);
            expectedCorrection = normalized;
            operationId = normalized.OperationId;
            body = JsonSerializer.SerializeToUtf8Bytes(input, Wire.Options);
            method = HttpMethod.Post;
            path = "corrections";
        }
        else if (args[0] == "query" && args.Length == 4)
        {
            expectedAt = Instant.Parse(args[2]);
            expectedRevision = Revision(args[3], false);
            path = "value?effectiveAt=" + Uri.EscapeDataString(Instant.Format(expectedAt.Value)) + "&knownThroughRevision=" + expectedRevision.ToString(CultureInfo.InvariantCulture);
        }
        else if (args[0] == "history" && args.Length == 3)
        {
            expectedRevision = Revision(args[2], true);
            path = "history?afterRevision=" + expectedRevision.ToString(CultureInfo.InvariantCulture);
        }
        else
            throw new ArgumentException("USAGE");
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(2)
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(8)
        };
        using var request = new HttpRequestMessage(method, new Uri(root, "v1/instruments/SYNTH/" + path));
        if (body is not null)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new("application/json");
        }

        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            if (response.Content.Headers.ContentLength is long length && length > FrameCap)
                throw new IOException("RESPONSE_CAP");
            using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            await using var stream = await response.Content.ReadAsStreamAsync(bound.Token);
            var bytes = await ReadBounded(stream, bound.Token);
            using var parsed = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8, AllowDuplicateProperties = false });
            if (response.IsSuccessStatusCode)
            {
                if (args[0] == "ingest")
                    ResponseContract.Correction(JsonSerializer.Deserialize<CorrectionOutcome>(bytes, Wire.Options) ?? throw new JsonException(), expectedCorrection!);
                else if (args[0] == "query")
                    ResponseContract.Point(JsonSerializer.Deserialize<PointOutcome>(bytes, Wire.Options) ?? throw new JsonException(), expectedAt!.Value, expectedRevision);
                else if (args[0] == "history")
                    ResponseContract.History(JsonSerializer.Deserialize<HistoryPage>(bytes, Wire.Options) ?? throw new JsonException(), expectedRevision);
                else
                    ResponseContract.Head(JsonSerializer.Deserialize<KnowledgeHead>(bytes, Wire.Options) ?? throw new JsonException());
            }

            Console.WriteLine(parsed.RootElement.GetRawText());
            return response.IsSuccessStatusCode ? 0 : (int)response.StatusCode is 400 or 409 ? 3 : 4;
        }
        catch (Exception error)when (error is HttpRequestException or IOException or OperationCanceledException or JsonException or ArgumentException)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { status = method == HttpMethod.Post ? "UNKNOWN" : "UNAVAILABLE", operationId, detail = "No invented revision or retry identity." }, Wire.Options));
            return 4;
        }
    }

    throw new ArgumentException("USAGE");
}
catch (Exception error)when (error is ArgumentException or IOException or FormatException or OverflowException or JsonException or Npgsql.NpgsqlException or OperationCanceledException)
{
    Console.WriteLine(JsonSerializer.Serialize(new { status = "FAILED_CLOSED", error = error.GetType().Name }));
    return 2;
}

static IResult Json(object value, int status = 200) => Results.Json(value, Wire.Options, statusCode: status);
static async Task<byte[]> ReadBounded(Stream stream, CancellationToken token)
{
    var bytes = new byte[FrameCap + 1];
    var size = 0;
    while (size < bytes.Length)
    {
        var read = await stream.ReadAsync(bytes.AsMemory(size), token);
        if (read == 0)
            break;
        size += read;
    }

    if (size > FrameCap)
        throw new ArgumentException("FRAME_CAP");
    return bytes[..size];
}

static Uri Endpoint(string value)
{
    if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "http" || uri.Host != "127.0.0.1" || uri.Port < 1024 || uri.AbsolutePath != "/" || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "")
        throw new ArgumentException("LITERAL_LOOPBACK_REQUIRED");
    return uri;
}

static long Revision(string value, bool zero)
{
    if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number < (zero ? 0 : 1) || number.ToString(CultureInfo.InvariantCulture) != value)
        throw new ArgumentException("CANONICAL_REVISION_REQUIRED");
    return number;
}

static void RequireQuery(HttpRequest request, params string[] names)
{
    if (request.Query.Count != names.Length || names.Any(name => !request.Query.TryGetValue(name, out var value) || value.Count != 1))
        throw new ArgumentException("EXPLICIT_QUERY_FIELDS_REQUIRED");
}

static async Task<IResult> ReadEndpoint(HttpRequest request, SemaphoreSlim slots, Func<CancellationToken, Task<object>> read)
{
    using var bound = CancellationTokenSource.CreateLinkedTokenSource(request.HttpContext.RequestAborted);
    bound.CancelAfter(TimeSpan.FromSeconds(6));
    if (!await slots.WaitAsync(0, bound.Token))
        return Json(new { status = "BUSY" }, 503);
    try
    {
        return Json(await read(bound.Token));
    }
    catch (Exception error)when (error is ArgumentException or FormatException or OverflowException)
    {
        return Json(new { status = "DENIED", error = error.GetType().Name }, 400);
    }
    catch (Exception error)when (error is Npgsql.NpgsqlException or OperationCanceledException or IOException or InvalidOperationException)
    {
        return Json(new { status = "UNAVAILABLE" }, 503);
    }
    finally
    {
        slots.Release();
    }
}
