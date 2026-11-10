using System.Globalization;
using System.Text.Json;
using Npgsql;
namespace ReferenceLab;

public sealed class Store
{
    private readonly string connection;
    public Store()
    {
        var raw=Environment.GetEnvironmentVariable("REFERENCE_LAB_DB")??throw new ArgumentException("LAB_DATABASE_REQUIRED");
        var builder=new NpgsqlConnectionStringBuilder(raw);
        if(builder.Host!="127.0.0.1" || builder.Database!="reference_lab" || builder.Username!="reference_lab" || builder.Port<1024 || string.IsNullOrWhiteSpace(builder.Password))throw new ArgumentException("DEDICATED_LOOPBACK_DATABASE_REQUIRED");
        builder.Timeout=3;builder.CommandTimeout=3;builder.Pooling=false;builder.IncludeErrorDetail=false;connection=builder.ConnectionString;
    }
    private Task<NpgsqlConnection> Open(CancellationToken token) =>
        OpenOwned(new NpgsqlConnection(connection), static (db, cancellation) => db.OpenAsync(cancellation), token);

    internal static async Task<T> OpenOwned<T>(T resource, Func<T, CancellationToken, Task> open, CancellationToken token)
        where T : class, IAsyncDisposable
    {
        try
        {
            await open(resource, token);
            return resource;
        }
        catch
        {
            try
            {
                await resource.DisposeAsync();
            }
            catch
            {
                // Cleanup must not replace the original open failure or cancellation.
            }
            throw;
        }
    }

    private static async Task<object?> Scalar(NpgsqlConnection db,NpgsqlTransaction? tx,string sql,CancellationToken token,params (string,object)[] values)
    {
        await using var cmd=new NpgsqlCommand(sql,db,tx);
        foreach(var (key,value) in values)cmd.Parameters.AddWithValue(key,value);
        return await cmd.ExecuteScalarAsync(token);
    }
    public async Task Init(CancellationToken token)
    {
        await using var db=await Open(token);await using var tx=await db.BeginTransactionAsync(token);
        await Scalar(db,tx,"CREATE SCHEMA reference_v1",token);
        await Scalar(db,tx,"CREATE TABLE reference_v1.state (id boolean PRIMARY KEY CHECK(id), head_revision bigint NOT NULL CHECK(head_revision BETWEEN 0 AND 4096), active_segments integer NOT NULL CHECK(active_segments BETWEEN 0 AND 4096), history_rows integer NOT NULL CHECK(history_rows BETWEEN 0 AND 50000))",token);
        await Scalar(db,tx,"INSERT INTO reference_v1.state VALUES(true,0,0,0)",token);
        await Scalar(db,tx,"CREATE TABLE reference_v1.receipts (operation_id text PRIMARY KEY CHECK(operation_id SIMILAR TO '[a-z0-9][a-z0-9-]{0,63}'), knowledge_revision bigint NOT NULL UNIQUE CHECK(knowledge_revision BETWEEN 1 AND 4096), request_hash text NOT NULL CHECK(length(request_hash)=64), observed_at timestamptz NOT NULL, source_label text NOT NULL, payload jsonb NOT NULL)",token);
        await Scalar(db,tx,"CREATE TABLE reference_v1.segments (row_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, effective tstzrange NOT NULL, knowledge int8range NOT NULL, tick_size_micros bigint NOT NULL CHECK(tick_size_micros BETWEEN 1 AND 1000000000), contract_multiplier_micros bigint NOT NULL CHECK(contract_multiplier_micros BETWEEN 1 AND 1000000000), value_operation_id text NOT NULL REFERENCES reference_v1.receipts(operation_id), assertion_operation_id text NOT NULL REFERENCES reference_v1.receipts(operation_id), CHECK(NOT isempty(effective) AND NOT lower_inf(effective) AND NOT upper_inf(effective) AND lower_inc(effective) AND NOT upper_inc(effective) AND lower(effective)>='2000-01-01T00:00:00Z'::timestamptz AND upper(effective)<='2100-01-01T00:00:00Z'::timestamptz), CHECK(NOT isempty(knowledge) AND NOT lower_inf(knowledge) AND lower(knowledge)>=1 AND lower_inc(knowledge) AND NOT upper_inc(knowledge)), CONSTRAINT segment_effective_knowledge_no_overlap EXCLUDE USING gist(effective WITH &&, knowledge WITH &&))",token);
        await tx.CommitAsync(token);
    }
    private static async Task<(long Head,int Active,int History)> State(NpgsqlConnection db,NpgsqlTransaction tx,bool write,CancellationToken token)
    {
        await using var cmd=new NpgsqlCommand("SELECT head_revision,active_segments,history_rows FROM reference_v1.state WHERE id FOR "+(write?"UPDATE":"SHARE"),db,tx);
        await using var reader=await cmd.ExecuteReaderAsync(token);
        if(!await reader.ReadAsync(token))throw new InvalidOperationException("STATE_MISSING");
        return(reader.GetInt64(0),reader.GetInt32(1),reader.GetInt32(2));
    }
    public async Task<CorrectionOutcome> Apply(Correction correction,CancellationToken token)
    {
        await using var db=await Open(token);await using var tx=await db.BeginTransactionAsync(token);var state=await State(db,tx,true,token);
        await using(var cmd=new NpgsqlCommand("SELECT request_hash,payload::text FROM reference_v1.receipts WHERE operation_id=@id",db,tx))
        {
            cmd.Parameters.AddWithValue("id",correction.OperationId);await using var reader=await cmd.ExecuteReaderAsync(token);
            if(await reader.ReadAsync(token))
                return reader.GetString(0)==correction.Digest?new("REPLAY",correction.OperationId,JsonSerializer.Deserialize<StoredReceipt>(reader.GetString(1),Wire.Options)):new("IDENTITY_CONFLICT",correction.OperationId);
        }
        if(state.Head>=Contract.MaximumCorrections)return new("CAPACITY_REJECTED",correction.OperationId);
        var next=Contract.NextRevision(state.Head);var overlap=new List<Segment>();
        await using(var cmd=new NpgsqlCommand("SELECT row_id,lower(effective),upper(effective),tick_size_micros,contract_multiplier_micros,value_operation_id,assertion_operation_id FROM reference_v1.segments WHERE upper_inf(knowledge) AND effective && tstzrange(@from,@to,'[)') ORDER BY lower(effective) FOR UPDATE",db,tx))
        {
            cmd.Parameters.AddWithValue("from",correction.From);cmd.Parameters.AddWithValue("to",correction.To);await using var reader=await cmd.ExecuteReaderAsync(token);
            while(await reader.ReadAsync(token))overlap.Add(new(reader.GetInt64(0),reader.GetDateTime(1),reader.GetDateTime(2),reader.GetInt64(3),reader.GetInt64(4),reader.GetString(5),reader.GetString(6)));
        }
        SplitPlan plan;
        try{plan=Contract.Plan(correction,overlap,state.Active,state.History);}
        catch(ArgumentException){return new("CAPACITY_REJECTED",correction.OperationId);}
        var receipt=correction.Receipt(next);
        await Scalar(db,tx,"INSERT INTO reference_v1.receipts(operation_id,knowledge_revision,request_hash,observed_at,source_label,payload) VALUES(@id,@revision,@hash,@observed,@source,@payload::jsonb)",token,("id",correction.OperationId),("revision",next),("hash",correction.Digest),("observed",correction.ObservedAt),("source",correction.SourceLabel),("payload",JsonSerializer.Serialize(receipt,Wire.Options)));
        foreach(var old in plan.Close)
            await Scalar(db,tx,"UPDATE reference_v1.segments SET knowledge=int8range(lower(knowledge),@revision,'[)') WHERE row_id=@row AND upper_inf(knowledge)",token,("revision",next),("row",old.RowId));
        foreach(var row in plan.Insert)
            await Scalar(db,tx,"INSERT INTO reference_v1.segments(effective,knowledge,tick_size_micros,contract_multiplier_micros,value_operation_id,assertion_operation_id) VALUES(tstzrange(@from,@to,'[)'),int8range(@revision,NULL,'[)'),@tick,@multiplier,@origin,@assertion)",token,("from",row.From),("to",row.To),("revision",next),("tick",row.TickSizeMicros),("multiplier",row.ContractMultiplierMicros),("origin",row.ValueOperationId),("assertion",row.AssertionOperationId));
        await Scalar(db,tx,"UPDATE reference_v1.state SET head_revision=@revision,active_segments=@active,history_rows=@history WHERE id",token,("revision",next),("active",plan.ActiveAfter),("history",plan.HistoryAfter));
        await Pause("before-commit",token);await tx.CommitAsync(token);await Pause("after-commit",token);
        return new("CORRECTION_COMMITTED",correction.OperationId,receipt);
    }
    public async Task<PointOutcome> Query(DateTime effectiveAt,long knownThrough,CancellationToken token)
    {
        if(knownThrough<1)throw new ArgumentException("POSITIVE_COMMITTED_KNOWLEDGE_REVISION_REQUIRED");
        await using var db=await Open(token);await using var tx=await db.BeginTransactionAsync(token);var state=await State(db,tx,false,token);
        if(knownThrough>state.Head)throw new ArgumentException("FUTURE_KNOWLEDGE_CUTOFF");
        PointValue? value=null;
        await using(var cmd=new NpgsqlCommand("SELECT s.tick_size_micros,s.contract_multiplier_micros,s.value_operation_id,r.knowledge_revision,r.source_label,r.observed_at FROM reference_v1.segments s JOIN reference_v1.receipts r ON r.operation_id=s.value_operation_id WHERE s.effective @> @at AND s.knowledge @> @known",db,tx))
        {
            cmd.Parameters.AddWithValue("at",effectiveAt);cmd.Parameters.AddWithValue("known",knownThrough);await using var reader=await cmd.ExecuteReaderAsync(token);
            if(await reader.ReadAsync(token))value=new(reader.GetInt64(0),reader.GetInt64(1),reader.GetString(2),reader.GetInt64(3),reader.GetString(4),Instant.Format(reader.GetDateTime(5)));
            if(await reader.ReadAsync(token))throw new InvalidOperationException("OVERLAPPING_AUTHORITATIVE_VALUES");
        }
        await tx.CommitAsync(token);return new(value is null?"NOT_KNOWN":"KNOWN","SYNTH",Instant.Format(effectiveAt),knownThrough,value);
    }
    public async Task<object> Head(CancellationToken token)
    {
        await using var db=await Open(token);await using var tx=await db.BeginTransactionAsync(token);var state=await State(db,tx,false,token);await tx.CommitAsync(token);
        return new KnowledgeHead("SYNTH",state.Head,"Committed local revision; observedAt is receipt metadata, never external publication/commit time.");
    }
    public async Task<object> History(long after,CancellationToken token)
    {
        if(after<0)throw new ArgumentException("HISTORY_CUTOFF");
        await using var db=await Open(token);await using var tx=await db.BeginTransactionAsync(token);var state=await State(db,tx,false,token);
        if(after>state.Head)throw new ArgumentException("FUTURE_HISTORY_CUTOFF");
        var entries=new List<StoredReceipt>();
        await using(var cmd=new NpgsqlCommand("SELECT payload::text FROM reference_v1.receipts WHERE knowledge_revision>@after ORDER BY knowledge_revision LIMIT 16",db,tx))
        {
            cmd.Parameters.AddWithValue("after",after);await using var reader=await cmd.ExecuteReaderAsync(token);
            while(await reader.ReadAsync(token))entries.Add(JsonSerializer.Deserialize<StoredReceipt>(reader.GetString(0),Wire.Options)??throw new InvalidOperationException("RECEIPT"));
        }
        await tx.CommitAsync(token);return new HistoryPage(state.Head,entries);
    }
    private static async Task Pause(string stage,CancellationToken token)
    {
        if(Environment.GetEnvironmentVariable("REFERENCE_LAB_PAUSE")!=stage)return;
        var directory=Environment.GetEnvironmentVariable("REFERENCE_LAB_HOOK_DIR")??throw new ArgumentException("HOOK_DIR");
        Directory.CreateDirectory(directory);await File.WriteAllTextAsync(Path.Combine(directory,"ready"),stage,token);
        using var bound=CancellationTokenSource.CreateLinkedTokenSource(token);bound.CancelAfter(TimeSpan.FromSeconds(20));
        while(!File.Exists(Path.Combine(directory,"resume")))await Task.Delay(20,bound.Token);
    }
}
