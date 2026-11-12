using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ReferenceLab;
public static class Wire
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        AllowDuplicateProperties = false,
        MaxDepth = 8,
        NumberHandling = JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString
    };
}

public sealed record CorrectionInput(string OperationId, string EffectiveFrom, string EffectiveTo, long TickSizeMicros, long ContractMultiplierMicros, string ObservedAt, string SourceLabel);
public sealed record Correction(string OperationId, DateTime From, DateTime To, long TickSizeMicros, long ContractMultiplierMicros, DateTime ObservedAt, string SourceLabel, string Digest)
{
    public StoredReceipt Receipt(long revision) => new(OperationId, revision, "SYNTH", Instant.Format(From), Instant.Format(To), TickSizeMicros, ContractMultiplierMicros, Instant.Format(ObservedAt), SourceLabel);
}

public sealed record StoredReceipt(string OperationId, long KnowledgeRevision, string Instrument, string EffectiveFrom, string EffectiveTo, long TickSizeMicros, long ContractMultiplierMicros, string ObservedAt, string SourceLabel);
public sealed record CorrectionOutcome(string Status, string OperationId, StoredReceipt? Receipt = null);
public sealed record PointValue(long TickSizeMicros, long ContractMultiplierMicros, string ValueOperationId, long OriginKnowledgeRevision, string SourceLabel, string OriginObservedAt);
public sealed record PointOutcome(string Status, string Instrument, string EffectiveAt, long KnownThroughRevision, PointValue? Value = null);
public sealed record KnowledgeHead(string Instrument, long HeadRevision, string KnowledgeConvention);
public sealed record HistoryPage(long HeadRevision, IReadOnlyList<StoredReceipt> Entries);
public sealed record Segment(long RowId, DateTime From, DateTime To, long TickSizeMicros, long ContractMultiplierMicros, string ValueOperationId, string AssertionOperationId);
public sealed record NewSegment(DateTime From, DateTime To, long TickSizeMicros, long ContractMultiplierMicros, string ValueOperationId, string AssertionOperationId);
public sealed record SplitPlan(IReadOnlyList<Segment> Close, IReadOnlyList<NewSegment> Insert, int ActiveAfter, int HistoryAfter);
public static class Instant
{
    public static readonly DateTime Minimum = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    public static readonly DateTime Maximum = new(2100, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    public static DateTime Parse(string value, bool allowUpper = false)
    {
        if (value is null || value.Length is not (20 or 27) || !DateTime.TryParseExact(value, new[] { "yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'" }, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var time) || time.Kind != DateTimeKind.Utc || time.Ticks % 10 != 0 || time < Minimum || (allowUpper ? time > Maximum : time >= Maximum))
            throw new ArgumentException("CANONICAL_UTC_MICROSECOND_TIME_REQUIRED");
        return time;
    }

    public static string Format(DateTime value) => value.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}

public static partial class Contract
{
    public const int MaximumCorrections = 4096, MaximumActiveSegments = 4096, MaximumHistoryRows = 50000;
    [GeneratedRegex(@"\A[a-z0-9][a-z0-9-]{0,63}\z", RegexOptions.CultureInvariant)]
    private static partial Regex IdentityPattern();
    public static string Identity(string value)
    {
        if (value is null || !IdentityPattern().IsMatch(value))
            throw new ArgumentException("ASCII_IDENTITY_REQUIRED");
        return value;
    }

    public static Correction Validate(CorrectionInput input)
    {
        var id = Identity(input.OperationId);
        var source = Identity(input.SourceLabel);
        var from = Instant.Parse(input.EffectiveFrom);
        var to = Instant.Parse(input.EffectiveTo, true);
        var observed = Instant.Parse(input.ObservedAt);
        if (from >= to || input.TickSizeMicros is < 1 or > 1000000000 || input.ContractMultiplierMicros is < 1 or > 1000000000)
            throw new ArgumentException("HALF_OPEN_INTERVAL_AND_POSITIVE_SCALED_UNITS_REQUIRED");
        var canonical = string.Create(CultureInfo.InvariantCulture, $"reference-v1\n{id}\nSYNTH\n{Instant.Format(from)}\n{Instant.Format(to)}\n{input.TickSizeMicros}\n{input.ContractMultiplierMicros}\n{Instant.Format(observed)}\n{source}\n");
        return new(id, from, to, input.TickSizeMicros, input.ContractMultiplierMicros, observed, source, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))));
    }

    public static long NextRevision(long committedHead)
    {
        if (committedHead is < 0 or >= MaximumCorrections)
            throw new ArgumentException("CORRECTION_CAPACITY");
        return checked(committedHead + 1);
    }

    public static SplitPlan Plan(Correction correction, IReadOnlyList<Segment> overlap, int active, int history)
    {
        var insert = new List<NewSegment>();
        foreach (var old in overlap)
        {
            if (old.From >= correction.To || old.To <= correction.From)
                throw new ArgumentException("PLANNER_NON_OVERLAP_INPUT");
            if (old.From < correction.From)
                insert.Add(new(old.From, correction.From, old.TickSizeMicros, old.ContractMultiplierMicros, old.ValueOperationId, correction.OperationId));
            if (old.To > correction.To)
                insert.Add(new(correction.To, old.To, old.TickSizeMicros, old.ContractMultiplierMicros, old.ValueOperationId, correction.OperationId));
        }

        insert.Add(new(correction.From, correction.To, correction.TickSizeMicros, correction.ContractMultiplierMicros, correction.OperationId, correction.OperationId));
        var activeAfter = checked(active - overlap.Count + insert.Count);
        var historyAfter = checked(history + insert.Count);
        if (activeAfter is < 0 or > MaximumActiveSegments || historyAfter > MaximumHistoryRows)
            throw new ArgumentException("HISTORY_CAPACITY");
        return new(overlap, insert, activeAfter, historyAfter);
    }
}

public static class ResponseContract
{
    public static void Receipt(StoredReceipt receipt, Correction? expected = null)
    {
        if (receipt.Instrument != "SYNTH" || receipt.KnowledgeRevision is < 1 or > Contract.MaximumCorrections)
            throw new ArgumentException("INVALID_RECEIPT_REVISION");
        var normalized = Contract.Validate(new(receipt.OperationId, receipt.EffectiveFrom, receipt.EffectiveTo, receipt.TickSizeMicros, receipt.ContractMultiplierMicros, receipt.ObservedAt, receipt.SourceLabel));
        if (expected is not null && normalized.Digest != expected.Digest)
            throw new ArgumentException("RECEIPT_INTENT_MISMATCH");
    }

    public static void Correction(CorrectionOutcome outcome, Correction expected)
    {
        if (outcome.Status is not ("CORRECTION_COMMITTED" or "REPLAY") || outcome.OperationId != expected.OperationId || outcome.Receipt is null)
            throw new ArgumentException("INVALID_CORRECTION_RESPONSE");
        Receipt(outcome.Receipt, expected);
    }

    public static void Point(PointOutcome outcome, DateTime effectiveAt, long known)
    {
        if (known is < 1 or > Contract.MaximumCorrections || outcome.Instrument != "SYNTH" || outcome.EffectiveAt != Instant.Format(effectiveAt) || outcome.KnownThroughRevision != known || outcome.Status is not ("KNOWN" or "NOT_KNOWN"))
            throw new ArgumentException("POINT_CUTOFF_MISMATCH");
        if (outcome.Status == "NOT_KNOWN")
        {
            if (outcome.Value is not null)
                throw new ArgumentException("INVENTED_VALUE");
            return;
        }

        var value = outcome.Value ?? throw new ArgumentException("MISSING_KNOWN_VALUE");
        if (value.TickSizeMicros is < 1 or > 1000000000 || value.ContractMultiplierMicros is < 1 or > 1000000000 || value.OriginKnowledgeRevision < 1 || value.OriginKnowledgeRevision > known)
            throw new ArgumentException("INVALID_VALUE_OR_KNOWLEDGE");
        Contract.Identity(value.ValueOperationId);
        Contract.Identity(value.SourceLabel);
        Instant.Parse(value.OriginObservedAt);
    }

    public static void Head(KnowledgeHead head)
    {
        if (head.Instrument != "SYNTH" || head.HeadRevision is < 0 or > Contract.MaximumCorrections || string.IsNullOrWhiteSpace(head.KnowledgeConvention) || head.KnowledgeConvention.Length > 256)
            throw new ArgumentException("INVALID_HEAD");
    }

    public static void History(HistoryPage page, long after)
    {
        if (after < 0 || page.HeadRevision < after || page.HeadRevision > Contract.MaximumCorrections || page.Entries.Count != Math.Min(16, page.HeadRevision - after))
            throw new ArgumentException("INVALID_HISTORY_PAGE");
        var previous = after;
        foreach (var receipt in page.Entries)
        {
            Receipt(receipt);
            if (receipt.KnowledgeRevision != previous + 1 || receipt.KnowledgeRevision > page.HeadRevision)
                throw new ArgumentException("HISTORY_REVISION_ORDER");
            previous = receipt.KnowledgeRevision;
        }
    }
}
