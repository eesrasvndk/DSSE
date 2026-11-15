using System.Text.Json;
using System.Text.Json.Serialization;
using CipherSearch.Contracts;
using CipherSearch.Server;
using CipherSearch.Server.Storage;
using Minio;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
LocalSettings.Load(builder.Configuration, builder.Environment.ContentRootPath);
builder.WebHost.UseUrls("http://127.0.0.1:5180");
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 16 * 1024 * 1024);
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase)));
builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(
    builder.Configuration.GetConnectionString("Postgres") ?? throw new InvalidOperationException("Postgres configuration missing."))
    { SearchPath = "dsse" }.ConnectionString));
builder.Services.AddSingleton<RuntimeDatabase>();
builder.Services.AddSingleton(_ => new MinioDocumentStore(new MinioClient()
    .WithEndpoint(builder.Configuration["Minio:Endpoint"])
    .WithCredentials(builder.Configuration["Minio:AccessKey"], builder.Configuration["Minio:SecretKey"])
    .Build(), builder.Configuration["Minio:Bucket"] ?? "dsse-documents"));
builder.Services.AddSingleton<SearchEngine>();
builder.Services.AddSingleton<PrivateIndexEngine>();
builder.Services.AddSingleton<IEncryptedDocumentStore>(services => services.GetRequiredService<MinioDocumentStore>());
builder.Services.AddSingleton<LeakageLog>();
var app = builder.Build();
await app.Services.GetRequiredService<RuntimeDatabase>().Initialize();
await app.Services.GetRequiredService<MinioDocumentStore>().Initialize();
app.Use(async (context, next) =>
{
    if (context.Connection.RemoteIpAddress is not { } ip || !System.Net.IPAddress.IsLoopback(ip))
    { context.Response.StatusCode = 403; return; }
    // A padded Kamara setup is larger than ordinary mutations. Keep their 16 MiB
    // limit unchanged; allow a configurable larger body only for index creation.
    if (context.Request.Method == "POST" && context.Request.Path == "/api/v1/indexes")
    {
        var limit = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();
        if (limit is { IsReadOnly: false })
            limit.MaxRequestBodySize = builder.Configuration.GetValue<long>("Kamara:MaxSetupRequestBytes", 64L * 1024 * 1024);
    }
    try { await next(context); }
    catch (Exception ex) when (!context.Response.HasStarted)
    {
        var status = ex switch
        {
            CipherSearch.SearchSchemes.Kamara.KamaraCapacityException => 422,
            ArgumentException or JsonException or BadHttpRequestException => 400,
            KeyNotFoundException => 404,
            InvalidOperationException => 409,
            _ => 503
        };
        context.Response.StatusCode = status;
        await context.Response.WriteAsJsonAsync(new ApiError(status.ToString(),
            status == 422 ? ex.Message : status == 503 ? "Storage operation unavailable; retry with the same operation ID." :
            status == 409 ? "State conflict." : "Invalid or unavailable resource.", Guid.NewGuid()));
    }
});
app.MapGet("/health", () => Results.Ok(new { status = "ready" }));
if (app.Environment.IsDevelopment())
    app.MapGet("/api/v1/diagnostics/searches/{generationId:guid}/{searchId:guid}",
        (Guid generationId, Guid searchId, LeakageLog log) =>
            log.FindSearch(generationId, searchId) is { } observation ? Results.Ok(observation) : Results.NotFound());
app.MapPost("/api/v1/private-index-writes", (PrivateIndexWrite r, PrivateIndexEngine engine, CancellationToken ct) => engine.Write(r, ct));
app.MapPost("/api/v1/opaque-blobs", (OpaqueBlobWrite r, PrivateIndexEngine engine, CancellationToken ct) => engine.Put(r, ct));
app.MapPost("/api/v1/opaque-blobs/read", (OpaqueBlobRead r, PrivateIndexEngine engine, CancellationToken ct) => engine.Read(r, ct));
app.MapPost("/api/v1/indexes", (InitializeRequest r, RuntimeDatabase db, IEncryptedDocumentStore objects,
    CancellationToken ct) => db.Create(r, ct, objects));
app.MapPost("/api/v1/indexes/status", (IndexScope r, SearchEngine engine, CancellationToken ct) => engine.Status(r, ct));
app.MapPost("/api/v1/indexes/epoch", (IndexScope r, SearchEngine engine, CancellationToken ct) => engine.Epoch(r, ct));
app.MapPost("/api/v1/indexes/cleanup", async (IndexScope r, SearchEngine engine, CancellationToken ct) =>
{ await engine.Cleanup(r, ct); return Results.NoContent(); });
app.MapPost("/api/v1/documents", (MutationRequest r, SearchEngine engine, CancellationToken ct) =>
{
    if (r.Kind != MutationKind.Add) throw new ArgumentException("Expected add.");
    return engine.Mutate(r, ct);
});
app.MapPut("/api/v1/documents/{id:guid}", (Guid id, MutationRequest r, SearchEngine engine, CancellationToken ct) =>
{
    if (r.DocumentId != id || r.Kind != MutationKind.Update) throw new ArgumentException("Expected update.");
    return engine.Mutate(r, ct);
});
app.MapPost("/api/v1/documents/{id:guid}/delete", (Guid id, MutationRequest r, SearchEngine engine, CancellationToken ct) =>
{
    if (r.DocumentId != id || r.Kind != MutationKind.Delete) throw new ArgumentException("Expected delete.");
    return engine.Mutate(r, ct);
});
app.MapPost("/api/v1/documents/read", (GetEncryptedDocumentRequest r, SearchEngine engine, CancellationToken ct) => engine.Read(r, ct));
app.MapPost("/api/v1/searches", (SearchRequest r, SearchEngine engine, CancellationToken ct) => engine.Search(r, ct));
app.MapPost("/api/v1/imports", async (ImportRequest r, SearchEngine engine, CancellationToken ct) =>
{
    if (r.Version != 1 || r.OperationId == Guid.Empty || r.Documents.Count > 1000)
        throw new ArgumentException("Invalid import.");
    var items = new List<ImportItemResponse>();
    foreach (var document in r.Documents)
    {
        if (document.Scope != r.Scope || document.Kind != MutationKind.Add)
            throw new ArgumentException("Import scope or kind mismatch.");
    }
    foreach (var document in r.Documents)
    {
        try { items.Add(new(document.OperationId, await engine.Mutate(document, ct), null)); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        { items.Add(new(document.OperationId, null, new("conflict", "Import item rejected.", Guid.NewGuid()))); }
    }
    return new ImportResponse(r.OperationId, items);
});
app.Run();

public partial class Program;
