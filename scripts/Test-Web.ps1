param([string]$BaseUrl = 'http://127.0.0.1:5190', [switch]$ExpectObservations)
$ErrorActionPreference = 'Stop'
$headers = @{ 'X-CipherSearch' = 'local-client' }
function Call-Web($scheme, $path, $method = 'GET', $body = $null) {
    $args = @{ Uri = "$BaseUrl/api/$scheme/$path"; Method = $method; Headers = $headers }
    if ($null -ne $body) { $args.ContentType = 'application/json'; $args.Body = ConvertTo-Json $body -Depth 8 -Compress }
    Invoke-RestMethod @args
}
function Expect-Status($action, $expected) {
    try { & $action | Out-Null; throw "Expected HTTP $expected" }
    catch { if ([int]$_.Exception.Response.StatusCode -ne $expected) { throw } }
}
function Expect-Search($scheme, $keyword, $ids, $serverEntries) {
    $result = Call-Web $scheme 'search' 'POST' @{ keyword=$keyword; verify=$true; inspect=[bool]$ExpectObservations }
    $actual = @($result.documents | ForEach-Object { $_.documentId })
    if (-not $result.oracle.passed -or $actual.Count -ne $ids.Count -or
        ($ids.Count -gt 0 -and $actual[0] -ne $ids[0])) { throw "$scheme client result mismatch for $keyword" }
    if ($ExpectObservations) {
        $observed = $result.observation
        if ($null -eq $observed -or $observed.searchId -ne $result.searchId -or
            $observed.schemeId -ne $scheme -or $observed.returnedEntryCount -ne $serverEntries) {
            throw "$scheme server observation mismatch for $keyword"
        }
        $observedIds = @($observed.documentIdSamples)
        if ($scheme -eq 'kamara-2012-v1') {
            if ($observedIds.Count -ne $ids.Count -or ($ids.Count -gt 0 -and $observedIds[0] -ne $ids[0])) {
                throw 'Kamara observed document IDs mismatch'
            }
        } elseif ($observedIds.Count -ne 0) { throw "$scheme search observation exposed document IDs" }
    }
    return $result
}
Expect-Status { Invoke-RestMethod "$BaseUrl/api/naive-hmac-v2/documents" } 403
Expect-Status { Invoke-RestMethod "$BaseUrl/api/naive-hmac-v2/documents" -Headers @{ 'X-CipherSearch'='local-client'; Origin='https://example.com' } } 403
Expect-Status { Call-Web 'basic-dynamic-v1' 'documents' } 400
$passed = @()
foreach ($scheme in @('naive-hmac-v2','kamara-2012-v1','mitra-v2')) {
    $id = [guid]::NewGuid().ToString()
    $keyword = 'web' + (-join ((97..122) | Get-Random -Count 15 | ForEach-Object { [char]$_ }))
    $updatedKeyword = $keyword + 'revised'
    $removedEntries = if ($scheme -eq 'mitra-v2') { 2 } else { 0 }
    $created = $false
    try {
        $inputDoc = @{ documentId=$id; revision=0; name='Web verification document'; text="$keyword meeting project" }
        $added = Call-Web $scheme 'documents' 'POST' $inputDoc
        $created = $true
        if ($added.revision -ne 1) { throw 'Add revision mismatch' }
        $found = Expect-Search $scheme $keyword @($id) 1
        if ($ExpectObservations -and $scheme -eq 'naive-hmac-v2') {
            $repeat = Expect-Search $scheme $keyword @($id) 1
            if ($repeat.observation.tokenSamples[0] -ne $found.observation.tokenSamples[0]) { throw 'HMAC token changed for repeated query' }
        }
        $unverified = Call-Web $scheme 'search' 'POST' @{ keyword=$keyword; verify=$false }
        if ($null -ne $unverified.oracle -or $unverified.documents[0].documentId -ne $id) { throw 'Search without verification mismatch' }
        $read = Call-Web $scheme "documents/$id"
        if ($read.text -ne $inputDoc.text) { throw 'Decryption mismatch' }
        $other = if ($scheme -eq 'naive-hmac-v2') { 'mitra-v2' } else { 'naive-hmac-v2' }
        $isolated = Call-Web $other 'search' 'POST' @{keyword=$keyword}
        if (@($isolated.documents).Count -ne 0) { throw 'Scheme isolation failed' }
        $inputDoc.revision = 1; $inputDoc.text = "$updatedKeyword energy contract"
        Call-Web $scheme "documents/$id" 'PUT' $inputDoc | Out-Null
        Expect-Status { Call-Web $scheme "documents/$id" 'PUT' $inputDoc } 409
        Expect-Search $scheme $keyword @() $removedEntries | Out-Null
        Expect-Search $scheme $updatedKeyword @($id) 1 | Out-Null
        $read = Call-Web $scheme "documents/$id"
        if ($read.text -ne $inputDoc.text -or $read.document.revision -ne 2) { throw 'Update mismatch' }
        Call-Web $scheme "documents/$id" 'DELETE' @{revision=2} | Out-Null
        $created = $false
        Expect-Status { Call-Web $scheme "documents/$id" } 404
        Expect-Search $scheme $updatedKeyword @() $removedEntries | Out-Null
        $listing = Call-Web $scheme 'documents'
        if ($listing.documents.documentId -contains $id) { throw 'Deleted document listed' }
        $passed += $scheme
    } finally {
        if ($created) {
            $current = Call-Web $scheme "documents/$id"
            Call-Web $scheme "documents/$id" 'DELETE' @{revision=$current.document.revision} | Out-Null
        }
    }
}
[pscustomobject]@{ Passed=$passed; Observations=[bool]$ExpectObservations; Checks='Origin/header guard, add/search, decrypt, isolation, update/old and new keywords, stale revision, delete/search' } | ConvertTo-Json
