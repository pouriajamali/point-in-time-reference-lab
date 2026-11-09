using System.Globalization;
using System.Numerics;
using System.Text.Json;
using ReferenceLab;
using Xunit;

public class DomainTests
{
    private static CorrectionInput Input(string id="x")=>new(id,"2024-01-01T00:00:00Z","2024-02-01T00:00:00Z",10000,1000000,"2024-03-01T12:00:00Z","synthetic");
    [Fact]
    public void WholeAndMicrosecondUtcFormsHaveOneCanonicalBusinessIdentity()
    {
        var a=Contract.Validate(Input());var b=Contract.Validate(Input() with{EffectiveFrom="2024-01-01T00:00:00.000000Z",ObservedAt="2024-03-01T12:00:00.000000Z"});
        Assert.Equal(a.Digest,b.Digest);Assert.Equal(DateTimeKind.Utc,a.From.Kind);Assert.Equal("2024-01-01T00:00:00.000000Z",Instant.Format(a.From));
    }
    [Theory]
    [InlineData("2024-01-01T00:00:00+00:00")] [InlineData("2024-01-01T00:00:00.0000001Z")] [InlineData("2024-01-01")] [InlineData("1999-12-31T23:59:59Z")] [InlineData("2100-01-01T00:00:00Z")] [InlineData("2024-01-01T00:00:00Z\n")]
    public void UnsupportedPrecisionZoneBoundsAndFramingDeny(string value)=>Assert.Throws<ArgumentException>(()=>Instant.Parse(value));
    [Fact] public void UpperExclusiveDomainBoundaryIsValid()=>Assert.Equal(Instant.Maximum,Instant.Parse("2100-01-01T00:00:00Z",true));
    [Theory] [InlineData(0)] [InlineData(-1)] [InlineData(1000000001)] [InlineData(long.MaxValue)]
    public void ExactScaledUnitsHaveBounds(long value)=>Assert.Throws<ArgumentException>(()=>Contract.Validate(Input() with{TickSizeMicros=value}));
    [Fact] public void EmptyEffectiveIntervalDenies()=>Assert.Throws<ArgumentException>(()=>Contract.Validate(Input() with{EffectiveTo="2024-01-01T00:00:00Z"}));
    [Fact] public void ReversedEffectiveIntervalDenies()=>Assert.Throws<ArgumentException>(()=>Contract.Validate(Input() with{EffectiveTo="2023-01-01T00:00:00Z"}));
    [Theory] [InlineData("")] [InlineData("x\n")] [InlineData("Capital")] [InlineData("../x")]
    public void IdentitiesAreAsciiFramed(string value)=>Assert.Throws<ArgumentException>(()=>Contract.Validate(Input(value)));
    [Theory] [InlineData(-1)] [InlineData(4096)] [InlineData(long.MaxValue)]
    public void ExhaustionNeverWrapsOrInventsRevision(long current)=>Assert.Throws<ArgumentException>(()=>Contract.NextRevision(current));
    [Fact] public void PositiveKnowledgeSuccessorMatchesBigInteger()=>Assert.Equal(new BigInteger(4096),new BigInteger(Contract.NextRevision(4095)));
    [Fact]
    public void InteriorCorrectionCarriesBothSidesWithoutChangingOrigin()
    {
        var old=Contract.Validate(Input("old"));var incoming=Contract.Validate(Input("new") with{EffectiveFrom="2024-01-10T00:00:00Z",EffectiveTo="2024-01-20T00:00:00Z",TickSizeMicros=5000});
        var before=new Segment(1,old.From,old.To,old.TickSizeMicros,old.ContractMultiplierMicros,"old","old");var plan=Contract.Plan(incoming,[before],1,1);
        Assert.Single(plan.Close);Assert.Equal(3,plan.Insert.Count);Assert.Equal(3,plan.ActiveAfter);Assert.Equal(4,plan.HistoryAfter);
        var oldParts=plan.Insert.Where(s=>s.ValueOperationId=="old").OrderBy(s=>s.From).ToArray();
        Assert.Equal((old.From,incoming.From),(oldParts[0].From,oldParts[0].To));Assert.Equal((incoming.To,old.To),(oldParts[1].From,oldParts[1].To));Assert.All(oldParts,s=>Assert.Equal("new",s.AssertionOperationId));
        // Independent interval-length conservation in UTC ticks.
        Assert.Equal(new BigInteger(old.To.Ticks-old.From.Ticks),plan.Insert.Aggregate(BigInteger.Zero,(sum,s)=>sum+s.To.Ticks-s.From.Ticks));
    }
    [Fact]
    public void SourceAndObservedMetadataArePartOfTheDurableIntent()
    {
        var normal=Contract.Validate(Input());Assert.NotEqual(normal.Digest,Contract.Validate(Input() with{SourceLabel="other"}).Digest);Assert.NotEqual(normal.Digest,Contract.Validate(Input() with{ObservedAt="2024-03-01T12:00:01Z"}).Digest);
    }
    [Fact]
    public void InvalidJsonShapeDoesNotSilentlySupplyDefaultsOrLastWins()
    {
        var valid=JsonSerializer.Serialize(Input(),Wire.Options);
        Assert.Throws<JsonException>(()=>JsonSerializer.Deserialize<CorrectionInput>(valid.Replace("\"operationId\":\"x\"","\"operationId\":\"x\",\"operationId\":\"y\"",StringComparison.Ordinal),Wire.Options));
        Assert.Throws<JsonException>(()=>JsonSerializer.Deserialize<CorrectionInput>(valid.Replace("\"operationId\":\"x\"","\"operationId\":null",StringComparison.Ordinal),Wire.Options));
        Assert.Throws<JsonException>(()=>JsonSerializer.Deserialize<CorrectionInput>("{}",Wire.Options));
        Assert.Throws<JsonException>(()=>JsonSerializer.Deserialize<CorrectionInput>(valid[..^1]+",\"knownAt\":\"ambiguous\"}",Wire.Options));
    }
    [Fact]
    public void CanonicalDigestDoesNotDependOnCurrentCulture()
    {
        var before=CultureInfo.CurrentCulture;var expected=Contract.Validate(Input()).Digest;
        try{CultureInfo.CurrentCulture=CultureInfo.GetCultureInfo("fa-IR");Assert.Equal(expected,Contract.Validate(Input()).Digest);}
        finally{CultureInfo.CurrentCulture=before;}
    }
    [Fact]
    public void ClientRejectsAParsedReceiptForAnotherIntent()
    {
        var requested=Contract.Validate(Input());var wrong=Contract.Validate(Input() with{TickSizeMicros=123});
        Assert.Throws<ArgumentException>(()=>ResponseContract.Correction(new("CORRECTION_COMMITTED","x",wrong.Receipt(1)),requested));
    }
    [Fact]
    public void ClientRejectsAParsedValueAtTheWrongKnowledgeCutoff()
    {
        var at=Instant.Parse("2024-01-04T00:00:00Z");var reply=new PointOutcome("NOT_KNOWN","SYNTH",Instant.Format(at),2);
        Assert.Throws<ArgumentException>(()=>ResponseContract.Point(reply,at,1));
    }
    [Fact]
    public void ClientRejectsFutureProvenanceInAKnownValue()
    {
        var at=Instant.Parse("2024-01-04T00:00:00Z");var value=new PointValue(10000,1000000,"x",2,"synthetic","2024-02-01T00:00:00.000000Z");
        Assert.Throws<ArgumentException>(()=>ResponseContract.Point(new("KNOWN","SYNTH",Instant.Format(at),1,value),at,1));
    }
    [Fact]
    public void ClientRejectsDuplicateOrUnorderedHistoryRevisions()
    {
        var receipt=Contract.Validate(Input()).Receipt(1);
        Assert.Throws<ArgumentException>(()=>ResponseContract.History(new(2,new[]{receipt,receipt}),0));
    }
}
