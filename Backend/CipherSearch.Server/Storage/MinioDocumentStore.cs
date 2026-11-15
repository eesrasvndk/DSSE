using CipherSearch.Contracts;
using Minio;
using Minio.DataModel.Args;

namespace CipherSearch.Server.Storage;

public sealed class MinioDocumentStore(IMinioClient client, string bucket) : IEncryptedDocumentStore
{
    public async Task Initialize(CancellationToken ct = default)
    {
        if (!await client.BucketExistsAsync(new BucketExistsArgs().WithBucket(bucket), ct))
            await client.MakeBucketAsync(new MakeBucketArgs().WithBucket(bucket), ct);
    }

    private static string Key(GetEncryptedDocumentRequest r) =>
        $"{r.Scope.DatasetId:N}/{r.Scope.SchemeId}/{r.Scope.GenerationId:N}/{r.DocumentId:N}/{r.Revision}.json";

    public async ValueTask PutAsync(IndexScope scope, EncryptedDocument document, CancellationToken cancellationToken = default)
    {
        using var stream = new MemoryStream(Wire.Encode(document));
        await client.PutObjectAsync(new PutObjectArgs().WithBucket(bucket)
            .WithObject(Key(new(scope, document.DocumentId, document.Revision)))
            .WithStreamData(stream).WithObjectSize(stream.Length).WithContentType("application/json"), cancellationToken);
    }

    public async ValueTask<EncryptedDocument> GetAsync(GetEncryptedDocumentRequest request, CancellationToken cancellationToken = default)
    {
        using var output = new MemoryStream();
        await client.GetObjectAsync(new GetObjectArgs().WithBucket(bucket).WithObject(Key(request))
            .WithCallbackStream(stream => stream.CopyTo(output)), cancellationToken);
        return Wire.Decode<EncryptedDocument>(output.ToArray());
    }

    public async ValueTask DeleteAsync(GetEncryptedDocumentRequest request, CancellationToken cancellationToken = default) =>
        await client.RemoveObjectAsync(new RemoveObjectArgs().WithBucket(bucket).WithObject(Key(request)), cancellationToken);
}
