using System.Globalization;
using ReferenceLab;
using Xunit;

public class HistoryPageContractTests
{
    // Five omission/truncation counterexamples, five positive pages, two guards.
    // Receipt records below are literal fixture data, not producer-built results.
    [Theory]
    [InlineData(16L, 17L, "", false)]
    [InlineData(0L, 17L, "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15", false)]
    [InlineData(0L, 17L, "2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17", false)]
    [InlineData(0L, 17L, "1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17", false)]
    [InlineData(15L, 17L, "17", false)]
    [InlineData(0L, 0L, "", true)]
    [InlineData(0L, 16L, "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16", true)]
    [InlineData(0L, 17L, "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16", true)]
    [InlineData(16L, 17L, "17", true)]
    [InlineData(17L, 17L, "", true)]
    [InlineData(18L, 17L, "", false)]
    [InlineData(4096L, 4097L, "", false)]
    public void PageMustContainExactlyTheNextCommittedReceipts(
        long after, long head, string revisions, bool accepted)
    {
        var entries = revisions.Length == 0
            ? Array.Empty<StoredReceipt>()
            : revisions.Split(',').Select(s => Receipt(long.Parse(s, CultureInfo.InvariantCulture))).ToArray();
        var page = new HistoryPage(head, entries);
        if (accepted)
            ResponseContract.History(page, after);
        else
            Assert.Throws<ArgumentException>(() => ResponseContract.History(page, after));
    }

    private static StoredReceipt Receipt(long revision)
    {
        if (revision == 1)
            return new("w2-seed", 1, "SYNTH", "2024-01-01T00:00:00Z", "2024-02-01T00:00:00Z",
                10000, 1000000, "2024-03-01T12:00:00Z", "synthetic-seed");
        if (revision == 17)
            return new("w2-late", 17, "SYNTH", "2024-01-10T00:00:00Z", "2024-01-20T00:00:00Z",
                5000, 2000000, "2023-12-01T00:00:00Z", "synthetic-late");
        return new(string.Create(CultureInfo.InvariantCulture, $"w2-fill-{revision:00}"), revision, "SYNTH",
            string.Create(CultureInfo.InvariantCulture, $"2025-01-{revision:00}T00:00:00Z"),
            string.Create(CultureInfo.InvariantCulture, $"2025-01-{revision + 1:00}T00:00:00Z"),
            20000 + revision, 1000000, "2024-03-01T12:00:00Z", "synthetic-fill");
    }
}
