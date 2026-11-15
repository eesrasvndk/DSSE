# DSSE doğrulama ve benchmark uygulama planı

## Son uygulama durumu

### 15 Kasım 2026 — kod karşılaştırması ve benchmark hazırlığı

Bu belge önce kaynak kodla karşılaştırılarak, ardından ilk RQ1 benchmark'ına hazırlık için yapılan kod değişiklikleri işlenerek güncellendi. Bu kopya macOS üzerinde; benchmark CLI'ı DPAPI nedeniyle yalnız Windows'ta çalışır ve hiçbir benchmark çalıştırılmadı. Bu kopya bir Git deposudur (son commit `7610c27`; aşağıdaki değişiklikler commit edilmedi).

Yapılan hazırlık değişiklikleri (hepsi küçük ve mevcut runner üzerinde; yeni framework eklenmedi):

- **Sızıntı günlüğü anahtarı:** Sunucu `Leakage__Enabled=false` ile dosyaya yazmayı bırakır; `scripts/Start-Server.ps1 -NoLeakageLog` bunu ayarlar. Benchmark'ta kullanılmalıdır (aşağıda açık iş 4).
- **`plan` komutu (her platformda):** Veri, sorgu sınıfları, iş yükü ve Kamara boyutlandırmasını servis çağırmadan hesaplar, özet yazar ve `plan.json` üretir. Windows'ta uzun koşudan önce kapasite ve kurulum boyutu tahminini görmek için kullanılır.
- **Sorgu örneklemesi:** `--queries-per-class` (varsayılan 20): seyrek, orta ve sık sınıflarından sınıf başına en fazla 20 kelime, ayrıca en fazla 5 olmayan kelime.
- **İş yükü:** `--mutations` (varsayılan 300 = 100 add + 100 update + 100 delete; smoke'ta 45). Mutasyon metinleri artık rastgele Enron belgelerinden geliyor (eski 3 kelimelik yapay metin yalnız `smoke`'ta kaldı). Sıra tohum 2026 ile belirlenir ve tüm yöntemlerde aynıdır.
- **Kamara serbest hücreleri:** `mutationCount × 3` yerine iş yükü önceden planlanıp tepe ihtiyaç hesaplanıyor (silmeler hücre geri verdiği için toplam ekleme değil, en yüksek canlı eşleşme sayısı belirleyici) + 64 hücre payı.
- **Ölçüm alanları (sonuç şeması 3):** `Query` (kelime) ve `QueryClass` (sınıf) ayrıldı; mutasyonlar için `ItemCount`/`PreviousItemCount` (belgedeki kelime sayısı); özetlerde mutasyonlardan sonraki indeks ve istemci durumu boyutları, algoritma durum dosyası boyutu; ortam için işlemci kimliği, mimari ve RAM; `--note` serbest metin alanı.
- **`analyze` komutu (her platformda):** `results.json`'dan `summary.md` ve `summary.csv` üretir: yöntem, işlem ve sorgu sınıfı bazında n, medyan, p95, min, maks, koşu medyanı aralığı, trafik; Mitra / Naive ve Mitra / Kamara oranları ve ek maliyet yüzdesi; boyut tabloları.
- **Mutasyon sonrası doğrulama:** Benchmark'ta her mutasyondan sonra sınıf başına bir kelime + değişen belgenin kelimeleri (en fazla 4 + 4) ölçüm dışında doğrulanır; koşu sonunda tüm sorgular doğrulanır. Tam doğruluk kanıtı oracle testlerindedir.

Doğrulama (bu makinede): 30 yeni test (iş yükü planlayıcı, analiz, sızıntı günlüğü anahtarı, sorgu sınıfları, kapasite hesabı, `plan` komutu) geçti. Mevcut `Category!=Integration` testlerinden 89 geçti, 1 atlandı (Enron oracle: ortam değişkeni verilmedi), 11 başarısız oldu; 11'inin hepsi `LocalVault` içinde `PlatformNotSupportedException` (DPAPI yok) ile düşüyor ve bu değişikliklerle ilgisi yok. Bu 11 testin Windows'ta geçtiği burada doğrulanamadı. `benchmark`, `smoke` ve `verify` komutlarının gerçek servislerle davranışı (yeni sorgu/iş yükü yolu dahil) çalıştırılmadı; ilk koşu pilot olarak yapılmalıdır. `analyze` ve `plan` sahte verilerle denendi, gerçek Enron verisi bu kopyada yok.

Önceki sürümde açık görünen şu maddeler kodda kapanmış durumda: oracle taramasının arama süresinden ayrılması, Kamara'nın Enron oracle testine eklenmesi, kapasite seçimi, `setup`/`ingest`/`build` ayrımı. Kurulum isteği gövde sınırı ayarlanabilir hale gelmiş ama 5k ve 10k için hâlâ yetmiyor. Eksik veya yanlış yazılmış olanlar "Ön koşulların koddaki durumu" ve "Benchmark öncesi açık işler" bölümlerinde düzeltildi.

### 10 Kasım 2026 — önceki durum

Kullanıcının istediği iki düzeltme uygulandı. Benchmark CLI, Kamara kapasitesini başlangıç eşleşmeleri + işlem sayısı × 3 rezerv üzerinden 16.384'lük bloklara yuvarlayarak seçiyordu (1k Enron: 65.536); bu yöntem 15 Kasım'da iş yükünden hesaplanan rezerve çevrildi. Protokolün 1.000.000 sınırı aşılırsa servis çağrısından önce açık hata verilir. Bu, makaledeki toplu Enc kurulumunun (|c|/8+z) yerine geçtiği veya ek gizlilik garantisi verdiği anlamına gelmez.

`setup` ve `ingest` ayrı ölçülür; `build` artık her ikisini kapsayan uçtan uca toplamdır (küçük ölçüm kayıt gideri dahil). Trafik sayaçları da aynı sınırları kullanır. Sonuç şeması 2 oldu (15 Kasım'da 3'e yükseltildi); eski şema 1 `build` değerleri yalnız yükleme ölçtüğünden doğrudan karşılaştırılmamalıdır. Toplam hesaplanırken `build` ile alt kalemleri yeniden toplanmamalıdır. Seçilen kapasite sonuç JSON'una (`kamaraCapacity`) yazılır.

Yalnız `POST /api/v1/indexes` için gövde sınırı varsayılan 64 MiB oldu ve sunucu ortamında `Kamara__MaxSetupRequestBytes` ile ayarlanabilir (15 Kasım'dan itibaren `Start-Server.ps1 -MaxSetupRequestBytes` ile de). Diğer isteklerin 16 MiB sınırı korunur.

Doğrulama (10 Kasım): Release derleme başarılı; mevcut Kamara testlerinden 14 geçti, gerçek depolama gerektiren 1 test atlandı. Tam Enron benchmarkı çalıştırılmadı.

Test yürütme durumu (10 Kasım): O oturumda başarılı yeni test sonucu alınamadı. Sandbox içindeki `dotnet test` çıktısız exit 1 verdi; `dotnet --info` Windows Service Control Manager erişim engeli bildirdi. Yükseltilmiş izinle test denemesi araç tarafından `user-aborted` olarak sonlandı. Eski TRX dosyaları o oturumun doğrulama kanıtı sayılmadı. `MIMARI_VE_KAMARA.txt` 1 Kasım 2026 için 75 başarılı test bildiriyor; bu plan o sonucu yeniden doğrulamış değildir.

Bu belge deney planıdır; tamamlanmış benchmark veya RQ1 sonucu değildir. İlk sürüm 10 Kasım 2026'da, kullanıcının isteği üzerine koordinatör, algoritma doğrulama agent'ı ve benchmark agent'ının paralel incelemesiyle hazırlanmıştır.

## İş bölümü

| Sorumlu | İş | Teslim |
|---|---|---|
| Koordinatör | Belge–kod uyumu, deney kapsamı, bağımlılıklar ve sonuç kontrolü | Bu plan ve RQ1 değerlendirmesi |
| Algoritma doğrulama agent'ı | Naive HMAC, Kamara ve Mitra; mevcut testler, oracle, yaşam döngüsü ve depolama | Test kanıtları ve açıklar |
| Benchmark agent'ı | Mevcut CLI, veri kümeleri, ölçüm sınırları ve kapasite | Çalıştırma protokolü ve gerekli en küçük düzeltmeler |

Kod incelemesi ve hazırlık paraleldir. Performans koşuları aynı bilgisayarda sırayla yürütülür; test, build ve başka benchmark yüküyle çakıştırılmaz. Arayüz değişikliği bu iş paketinde yoktur.

## Ön koşulların koddaki durumu

| # | Konu | Durum | Koddaki gerçek durum |
|---|---|---|---|
| 1 | Oracle taraması ölçülen süreye giriyor mu | **Çözüldü** | `MeasureSearch` kronometreyi yalnız `client.Search` (ve `search-and-decrypt` için `client.Read`) çevresinde tutuyor. Küme karşılaştırması ve açık metin eşitliği süre dışında; uyuşmazlıkta `InvalidOperationException` ile koşu duruyor, yani yanlış sonuçlu koşu kayda geçmiyor. Her sorgu için ölçümden önce bir `Verify` araması yapılıyor; bu fiilî bir ısınmadır ve raporda belirtilmelidir. |
| 2 | Varsayılan yöntem listesi | **Açık** | `--schemes` varsayılanı yalnız `naive-hmac-v2,mitra-v2`. Her komutta üç yöntem açıkça verilmeli. |
| 3 | Kamara kapasitesi | **Çözüldü (CLI)** | Kapasite otomatik hesaplanıyor; `--capacity` benzeri seçenek yok. Hesap aşağıda. |
| 4 | İstek gövdesi sınırı | **Kısmen** | Sunucu `POST /api/v1/indexes` için varsayılan 64 MiB; `Kamara__MaxSetupRequestBytes` veya `Start-Server.ps1 -MaxSetupRequestBytes` ile ayarlanabilir; diğer istekler 16 MiB. 1k sığıyor; 5k ve 10k sığmıyor (aşağıdaki tablo). 50k protokol sınırını aşıyor. |
| 5 | `Initialize()` ve veri yükleme ayrı ölçülüyor mu | **Çözüldü, ama eşdeğer değil** | `build` = `setup` + `ingest`. Kamara'da `setup` toplu kurulumun tamamı (belge şifreleme + Enc + tek istek) ve `ingest` satırı yok. Naive ve Mitra'da `setup` yalnız `Initialize()` (≈ 0), `ingest` N adet sıralı `Add`. Yöntemler arasında yalnız `build` karşılaştırılabilir; `setup` ve `ingest` satırları birebir kıyaslanamaz. |
| 6 | Şifreleme / indeks / doğrulama süreleri ayrı mı | **Açık** | Ölçüm kalemleri: `build`, `setup`, `ingest`, `search`, `search-and-decrypt`, `add`, `update`, `delete`. Belge şifreleme, indeks hazırlama, HTTP ve durum yazımı tek `Mutate` süresinin içinde. Kriptografik sonuç doğrulaması (MAC) uygulanmadığı için ölçülecek bir "doğrulama" kalemi yok (`MIMARI_VE_KAMARA.txt`: W9 kapsamı). Oracle doğruluğu ayrı bir metriktir. |
| 7 | Enron oracle testi Kamara'yı kapsıyor mu | **Çözüldü** | `EnronOracleTests` üç yöntemi de içeriyor (satır 51). Ayrıntı aşağıda. |

### Kamara kapasitesi ve kurulum boyutu

CLI, iş yükünü (add/update/delete dizisi) önceden planlıyor ve canlı kelime–belge eşleşmesinin başlangıca göre tepe artışını hesaplıyor (`PeakExtraPairs`). Silmeler hücreleri serbest listeye geri verdiği için bu, tüm eklemelerin toplamı değil, dizi boyunca en yüksek canlı eşleşme sayısıdır. Serbest hücre sayısı `PeakExtraPairs + 64`; gerekli kapasite `başlangıç eşleşmeleri + serbest hücre`; kapasite bunun 16.384'lük bloklara yukarı yuvarlanmış hâli. Yuvarlanmış kapasite `PrepareSetupAsync`'in açık kapasite aşırı yüklemesine veriliyor; makaledeki `|c|/8+z` hesabı (şifreli belge uzunluğundan) benchmark'ta kullanılmıyor. Serbest liste yalnız bu hücrelerle başlıyor; blok yuvarlamasından artan hücreler rastgele dolgu olarak kalıyor ve kullanılamıyor. Kapasite dolarsa `KamaraCapacityException` fırlatılır. Kesin değerler `plan` komutunun çıktısında ve `results.json`'daki `kamaraCapacity` / `kamaraFreeSlots` alanlarında görülür.

Aşağıdaki kapasiteler, tepe artışın küçük olduğu varsayımıyla bloklara yuvarlanmış tipik değerlerdir (eşleşme sayıları önceki plandan alındı; veri kümesi bu kopyada olmadığından yeniden doğrulanmadı): 10k'da yuvarlama payı yalnız 3.310 hücre olduğundan tepe artış + 64 bunu aşarsa kapasite bir blok (917.504) büyür. Kurulum mesajı boyutu tahmindir: kapasite hücresi başına `As` girdisi (≈ 106 bayt JSON) + `Ad` girdisi (≈ 154 bayt JSON) = ≈ 260 bayt; `kamara.setup` yükü `ProtocolMessage.Payload` (`byte[]`) içinde olduğundan ikinci kez base64 olur (×4/3) → hücre çifti başına ≈ 347 bayt (`BenchmarkPlanner.EstimatedSetupBytesPerCell`). `Ts`/`Td` kayıtları ve şifreli belgeler ayrıca eklenir.

| Enron belge sayısı | Başlangıç kelime–belge çifti | Tipik CLI kapasitesi | Tahmini kurulum isteği | Varsayılan 64 MiB yeter mi |
|---:|---:|---:|---:|---|
| 1.000 | 61.840 | 65.536 | ≈ 23 MB | Evet |
| 5.000 | 383.636 | 393.216 | ≈ 136 MB | Hayır |
| 10.000 | 897.810 | 901.120 (veya 917.504) | ≈ 313 MB | Hayır |
| 50.000 | 4.848.082 | CLI hata verir (> 1.000.000) | — | — |

Bu tahminler 5k ve 10k için `Kamara__MaxSetupRequestBytes` değerinin yükseltilmesi gerektiğini, ayrıca istemci ve sunucu belleğinin kontrol edilmesi gerektiğini gösteriyor. Sunucu tarafında `PostgresIndexSession.Flush` her girdi için ayrı bir `INSERT … ON CONFLICT` komutunu tek bir `NpgsqlBatch` içinde gönderiyor (10k için yaklaşık 1,8 milyon komut); bunun süre ve bellek etkisi pilotla ölçülmeli. `HttpClient` zaman aşımı 5 dakika. 50k yalnız kapsam sınırı olarak raporlanır.

### Enron oracle testi (`EnronOracleTests`)

Test üç yöntemi (Naive, Kamara, Mitra) aynı Enron 1.000 belgelik iş dizisiyle çalıştırır: 3 seed (1, 17, 42), 128 sıklığa göre katmanlanmış sabit sorgu + olmayan bir kelime, 60 mutasyon. Mutasyonlar altı senaryoluk döngüdür: yeni belge ekleme, içerik değiştirme, silme, silinmiş belgeyi yeniden ekleme, boş belgeye güncelleme, aynı içerikle güncelleme. Her adımdan sonra her yöntemin sonucu açık metin referansıyla `(DocumentId, Revision)` çiftleri düzeyinde karşılaştırılır. Kamara toplu kurulumla başlar (başlangıç `Add`'leri atlanır) ve tüm kalan hücreler serbest listeye alınır.

Dikkat edilecekler:

- Test bellek içi `TestIndex` üzerinde şema katmanını sınar. HTTP, PostgreSQL, MinIO ve `DocumentClient` yolu bu testte yoktur; o yol `smoke`/`verify` ve entegrasyon testlerinde sınanır.
- `CIPHERSEARCH_ORACLE_ROOT` verilmezse test **atlanır (Skipped)**; geçti sayılmaz. `CIPHERSEARCH_ORACLE_OUT` yoksa test hata verir.
- `workload-{seed}.json` ve `oracle-{seed}.json` yalnız tüm doğrulamalar geçtikten sonra yazılır; dosyaların oluşumu kontrol edilmelidir.

## Benchmark öncesi açık işler

Önceki sürümdeki on madde yeniden değerlendirildi. Kodda çözülenler işaretlendi; kalanlar benchmark'tan önce kararlaştırılmalı veya raporda belirtilmelidir.

| # | Konu | Durum | Not |
|---|---|---|---|
| 1 | Sorgu örneklemesi | **Çözüldü (kodda)** | Sınıf başına `--queries-per-class` (varsayılan 20) kelime, sınıfın içinde sıklık sırasına göre eşit aralıklı; ayrıca en fazla 5 olmayan kelime. Sınıflar belge sıklığına göre: seyrek 1–5, orta 6–50, sık ≥ 51 (`BenchmarkPlanner` sabitleri, `results.json`'daki `queryClassThresholds`). Eşikler bir protokol kararıdır; danışmanla teyit edilmeli. Bir sınıfta yeterli kelime yoksa mevcut olanların hepsi alınır (1k Enron'da sık sınıfının kaç kelime verdiği `plan` çıktısında görülür). Ölçüm kaydında `Query` kelimeyi, `QueryClass` sınıfı tutar. Her sorgu 5 `search` + 1 `search-and-decrypt` ölçümü verir. |
| 2 | Mutasyon sayısı ve iş yükü | **Çözüldü (kodda)** | Varsayılan 300 mutasyon (tür başına 100); 5 koşuda yöntem başına tür başına 500 örnek. Metinler Enron belgelerinden. Mitra'nın geçmiş maliyetini ölçmek için tasarlanmış ayrı bir senaryo **hâlâ yok**; geçmiş uzunluğu doğal olarak sık kelimelerin mutasyonlardan aldığı eklemelere bağlıdır. |
| 3 | Özet istatistik | **Çözüldü** | `analyze` komutu (medyan, p95, oranlar, boyutlar). p95 = en yakın sıra, ceil(0,95·n). |
| 4 | Sunucu sızıntı günlüğü ölçümün içinde | **Çözüldü (anahtar), kullanılmalı** | Günlük dosya yazımı istek içinde yapılıyor ve istemci süresine giriyor; Mitra aramasında kayıt, geçmiş uzunluğuyla büyüyor. `Start-Server.ps1 -NoLeakageLog` (`Leakage__Enabled=false`) bunu kapatır. `LocalSettings` bu anahtarı ayarlamadığı için ortam değişkeni geçerlidir. Benchmark'ta mutlaka kullanılmalı ve `--note` ile kaydedilmelidir. Kapatmanın etkisi ayrıca ölçülmedi. |
| 5 | İstemci durum dosyası G/Ç maliyeti | **Açık (raporda belirtilecek)** | Her `Search` durum dosyasını DPAPI ile çözüp ayrıştırıyor ve her eşleşen belge için `doc-*.state` yüklüyor. Her mutasyon dört kez DPAPI'li, `Flush(true)` ile diske zorlanan atomik durum yazımı yapıyor. Maliyet durum boyutuna bağlı ve yöntemler arasında çok farklı (Naive durumu tüm posting list'leri, Mitra kelime sayaçlarını, Kamara belge revizyonlarını tutar). Naive'in sıralı `ingest` süresinin indeks büyüdükçe (kabaca N²) artması beklenir; 5k/10k için pilotla ölçülmeli (öngörü, ölçülmemiştir). Artık `AlgorithmStateBytes` kaydedildiğinden durum boyutu ile gecikme ilişkisi incelenebilir. |
| 6 | Kamara toplu kurulum ile diğerlerinin sıralı ekleme farkı | **Açık (karar)** | Kamara `ingest` satırı üretmiyor. Karşılaştırmayı eşdeğer kılmak için ya Kamara'yı boş kurulum + sıralı `Add` ile ölçen ikinci bir mod eklenmeli ya da raporda "Kamara: toplu Enc kurulumu; Naive/Mitra: sıralı ekleme" açıkça belirtilmeli. İlk benchmark için yalnız `build` karşılaştırılır ve etiketlenir. |
| 7 | İndeks boyutu | **Kısmen çözüldü** | `Status()` artık build sonrası ve mutasyonlar sonrası olmak üzere iki kez alınıyor (mantıksal adres + değer bayt toplamı; Kamara'da dolgu dahil). Fiziksel PostgreSQL alanı hâlâ ölçülmüyor. |
| 8 | İstemci durum boyutu | **Çözüldü** | `ClientStateBytes` (tüm vault dizini) ve `AlgorithmStateBytes` (yalnız algoritma durum dosyası) ayrı; ikisi de build sonrası ve mutasyonlar sonrası. Vault dizini yerel belge kayıtları (`doc-*.state`) ve anahtar/nonce dosyalarını da içerir. |
| 9 | Ortam bilgisi | **Kısmen çözüldü** | `results.json` çalışma zamanı, işletim sistemi, işlemci kimliği (`PROCESSOR_IDENTIFIER`), mimari, mantıksal işlemci sayısı, RAM, veri dosyası SHA-256'ları ve `--note` içeriğini kaydediyor. PostgreSQL/MinIO sürümleri, sunucu bayrakları (günlük kapalı mı, gövde sınırı) ve kaynak sürümü (`git rev-parse HEAD`) elle kaydedilmeli (`--note` kullanılabilir). |
| 10 | Platform | **Açık** | `benchmark`, `smoke` ve `verify` Windows dışında `PlatformNotSupportedException` fırlatır. `plan` ve `analyze` her platformda çalışır. Deneyler Windows makinede yapılmalı. |

## Çalıştırma sırası

Komutlar DSSE kökünde PowerShell içindir. Sonraki aşamanın koşulları sağlanmadan ağır deney başlatılmaz.

### 1. Doğruluk ve veri ön kontrolü

```powershell
dotnet test Backend/CipherSearch.Tests -c Release --no-restore --filter "Category!=Integration"
$env:CIPHERSEARCH_ORACLE_ROOT = (Get-Location).Path
$env:CIPHERSEARCH_ORACLE_OUT = Join-Path (Get-Location) 'results/first-benchmark/oracle'
dotnet test Backend/CipherSearch.Tests -c Release --no-restore --filter FullyQualifiedName~EnronOracleTests
dotnet build Backend/CipherSearch.Client -c Release --no-restore
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- validate-dataset --data DataSet/processed/enron_1000.jsonl --output results/first-benchmark/normalization-1000
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- plan --data DataSet/processed/enron_1000.jsonl --output results/first-benchmark/plan-1000
```

Oracle ortam değişkenli koşu üç yöntemi (Naive, Kamara, Mitra) şema katmanında doğrular. Başlangıç, add/update/delete, yeniden ekleme, boş belge, olmayan kelime ve kimlik/revizyon eşitliği kapsanır; her karşılaştırma %100 eşleşmelidir. Test çıktısında "Skipped" yerine "Passed" görülmeli ve `workload-*.json` ile `oracle-*.json` dosyaları oluşmalıdır. Yeniden başlatma sonrası eşitlik bu testte değil, `verify` adımında sınanır. `plan` çıktısı kontrol edilir: sınıf başına seçilen kelime sayıları, Kamara kapasitesi ve tahmini kurulum isteği boyutu. Testler kriptografik güvenlik ispatı olarak sunulmaz.

### 2. Gerçek depolama ve küçük deneme

Mevcut PostgreSQL ve MinIO erişimi doğrulanır. Ayrı deney kimlikleri ve vault dizinleri kullanılır; demo verileri temizlenmez. Sunucu çalışmıyorsa ayrı terminalde (benchmark için sızıntı günlüğü kapalı):

```powershell
dotnet build Backend/CipherSearch.Server -c Release --no-restore
./scripts/Start-Server.ps1 -NoLeakageLog
```

Ardından:

```powershell
./scripts/Run-Checks.ps1 -Storage
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- smoke --schemes naive-hmac-v2,kamara-2012-v1,mitra-v2 --output results/first-benchmark/smoke
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- verify --output results/first-benchmark/smoke
```

`smoke` 8 belgelik küçük bir veriyle çalışır, ilk mutasyonun yanıtını bilerek düşürür (kayıp onay simülasyonu) ve yeniden denemeyi sınar. `verify` yeni istemci sürecinde kayıtlı durumdan (`resume.json`) kontrol yapar; sunucu yeniden başlatma dayanıklılığı ayrıca sınanır. Küçük deneme ölçümleri nihai performans sonucu olarak kullanılmaz.

### 3. İlk benchmark

Önce tek koşuluk pilot (ölçüm tekrarlarına dahil edilmez); süre, disk, mesaj boyutu ve Kamara kurulum isteği boyutu görülür:

```powershell
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- benchmark --data DataSet/processed/enron_1000.jsonl --runs 1 --schemes naive-hmac-v2,kamara-2012-v1,mitra-v2 --note "pilot; leakage log off" --output results/first-benchmark/pilot-1000
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- analyze --output results/first-benchmark/pilot-1000
```

Pilot temizse gerçek koşu (3 yöntem × 5 tekrar = 15 koşu):

```powershell
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- benchmark --data DataSet/processed/enron_1000.jsonl --runs 5 --schemes naive-hmac-v2,kamara-2012-v1,mitra-v2 --note "leakage log off; <PostgreSQL/MinIO sürümleri, git HEAD>" --output results/first-benchmark/enron-1000
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- analyze --output results/first-benchmark/enron-1000
```

`analyze`, koşu tamamlanmadan da çalıştırılabilir; `results.json` her koşudan sonra yeniden yazılır. Çıktı `summary.md` ve `summary.csv` olarak aynı klasöre yazılır.

Her tekrarda yeni kapsam, anahtarlar ve istemci durumu (`vault-{run}-{scheme}` dizini boş olmak zorundadır); aynı veri, sorgular ve işlem dizisi (sabit tohum 2026) kullanılır. Yöntem sırası her tekrarda döndürülür. Pilotta kullanılan seçenekler gerçek koşuyla aynı olmalıdır (aynı `--queries-per-class` ve `--mutations`); süre kısaltmak için yalnız `--runs` değiştirilir.

Sorgular seyrek, orta sıklıkta, sık ve sonuçsuz kelimeleri kapsar (açık iş 1). Her güncelleme türü için koşu başına 100 ölçüm alınır; 5 koşuda yöntem başına tür başına 500 örnek olur ve p95 örnek sayısı `summary.md`'de `n` sütununda raporlanır. Mitra'nın geçmiş maliyetini ayrı bir senaryoyla ölçme işi açık işlerde (madde 2). Bu sayılar belgede verilmiş sonuçlar değil, deney protokolüdür.

### 4. Ölçekleme ve RQ1

1k koşuları doğru ve ölçümler temiz olduğunda aynı protokol 5k ve 10k için tekrarlanır: üç ölçek toplam 45 koşu. Önce her ölçek için `plan` komutu çalıştırılır. 5k ve 10k için Kamara kurulum isteği varsayılan 64 MiB sınırını aşar; sunucu `./scripts/Start-Server.ps1 -NoLeakageLog -MaxSetupRequestBytes <bayt>` ile yeniden başlatılır. Değer, pilotla gerçek kurulum boyutu ölçüldükten ve bellek yeterliliği kontrol edildikten sonra seçilir. Naive'in sıralı ingest süresi de pilotla görülür (açık iş 5). 50k, protokolün 1.000.000 hücre sınırını aştığı için mevcut uygulamada çalıştırılamaz; kapasite/aktarım/bellek sınırları ayrıca çözülmedikçe açıkça kapsam sınırı olarak raporlanır.

Her işlem için ham örnekler (`results.json`), tekrar başına medyan ve p95 (`summary.md`) saklanır. Beş tekrarın değişkenliği "koşu medyanı aralığı" sütununda gösterilir; farklı sorgu sınıfları tek bir yanıltıcı ortalamada birleştirilmez. H1: 10k belgede Mitra tek kelime aramasının p95 ≤ 500 ms hedefi, tanımlı sorgu dağılımı ve bu bilgisayar için değerlendirilir; ölçülen süre HTTP ve istemci durum yükleme maliyetini de içerdiğinden bu bileşenler raporlanır (sızıntı günlüğü kapalı koşulmalıdır).

| Ölçüm | Tanım | Koddaki durum |
|---|---|---|
| İlk kurulum | Setup, veri yükleme ve toplam; Kamara padding dahil | `setup`, `ingest`, `build` ayrı ölçülüyor. Kamara'da `setup` tüm yüklemeyi kapsıyor, `ingest` yok; Naive ve Mitra'da `setup` ≈ 0, `ingest` sıralı ekleme. Yalnız `build` yöntemler arası karşılaştırılabilir. |
| Arama | Token üretimi, HTTP, sunucu işleme, istemci sonuç işleme; oracle ve UI hariç | `search`: oracle hariç, sınıf bazında. Süre; durum dosyasının DPAPI ile yüklenmesini, eşleşen belge kayıtlarının yüklenmesini ve epoch isteğini de içerir. Sunucu günlüğü kapalıysa günlük yazımı dahil değildir. |
| Arama ve belge çözme | Sonuç belgelerinin indirilmesi ve çözülmesi dahil, ayrı metrik | `search-and-decrypt`: sorgu başına koşu başına 1 örnek; `client.Read` çağrılarını içerir. |
| Add / update / delete | Uçtan uca işlem süresi; şifreleme/indeks alt maliyetleri mümkün olan ayrı sınırlar içinde | `add` / `update` / `delete` uçtan uca; alt maliyet ayrımı yok. Mutasyon başına dört DPAPI'li atomik durum yazımı süreye dahil. Koşu başına tür başına 100 örnek; `ItemCount` (ve update için `PreviousItemCount`) belgedeki kelime sayısını verir. |
| Doğrulama | Gerçek kriptografik doğrulama maliyeti; oracle ayrı | Sonuç MAC'i uygulanmadı, ölçülen kriptografik doğrulama yok. Oracle ölçüm dışında. GCM çözme yalnız `search-and-decrypt` içinde. |
| İndeks | Mantıksal indeks byte'ı ve mümkünse fiziksel PostgreSQL alanı ayrı | `IndexBytes`/`IndexEntries` (build sonrası) ve `FinalIndexBytes`/`FinalIndexEntries` (mutasyonlar sonrası), mantıksal (adres + değer). Fiziksel alan yok. |
| İstemci durumu | Algoritma durumu ve toplam vault disk boyutu ayrı | `AlgorithmStateBytes` ve `ClientStateBytes` (tüm vault); ikisi de build ve mutasyonlar sonrası. |
| Trafik | Mevcut sayaç HTTP JSON gövde byte'ı; ağ başlıkları/TLS dahil değildir | `RequestBytes` / `ResponseBytes` yalnız `DocumentClient` istekleri; başlık ve TLS yok. Mitra'da bir mutasyon iki istektir (`opaque-blobs` + `private-index-writes`). `summary.md`'de işlem ve sınıf bazında medyan olarak yer alır. |

RQ1 cevabı, Mitra'nın Naive ve Kamara'ya göre her metrikte mutlak farkını ve oranını gösterecek: oran = Mitra / karşılaştırılan yöntem; ek maliyet (%) = (oran − 1) × 100 (`summary.md`'deki Mitra oranı tablosu). Sonuçlar veri büyüklüğü, sorgu sıklığı ve güncelleme geçmişine göre açıklanacak. Ölçüm alınmadan daha hızlı/yavaş veya hedef sağlandı denmeyecek.

## Değişiklik ve çıktı sınırı

Yeni benchmark framework'ü, algoritmaların ikinci kopyası veya arayüz değişikliği eklenmez. Mevcut runner, ortak doğruluk testleri ve gerekli ölçüm noktaları kullanılır. Kapasite/taşıma sınırı için gereken değişiklik ayrıca dar tutulur; büyük bir yeniden tasarım sessizce bu işe eklenmez.

Çıktılar: test kayıtları, oracle kanıtları, veri ve kaynak kod SHA-256'ları, ham ölçümler, ortam bilgisi (CPU/RAM/OS/.NET/servis sürümleri), medyan/p95 karşılaştırma tablosu ve RQ1 yorumu. CLI bugün veri dosyalarının SHA-256'larını, çalışma zamanı, işletim sistemi, işlemci kimliği, mimari, işlemci sayısı, RAM, seçilen Kamara kapasitesini ve `--note` metnini kaydediyor; `analyze` medyan/p95 tablolarını üretiyor. Geri kalanı (servis sürümleri, sunucu bayrakları, kaynak sürümü) elle veya `--note` ile eklenmelidir. Eski `results/smoke` dosyaları yeni deney sonucu sayılmaz. Her yeniden koşuda benzersiz çıktı klasörü kullanılır (CLI varsayılanı `tmp/experiments/<UTC zaman damgası>`; vault dizini boş olmak zorunda olduğundan aynı dizin yeniden kullanılamaz). Bu kopya Git deposu olduğundan deney öncesi `git rev-parse HEAD` ve `git status` kaydedilir; çalışma ağacı temiz değilse kaynak dosya hash manifesti de eklenir.

CLI ölçüm sırasında konsola yalnız koşu başında ve sonunda (ve sorgu sınıfı ile Kamara kapasitesini seçerken) yazıyor; ölçülen işlemlerin içinde ilerleme yazısı yok. Mevcut `EncryptedDocumentBytes` alanı hesaplanmış zarf boyutudur; ölçülmüş MinIO disk tüketimi olarak etiketlenmez.

Kaynaklar: kullanıcı tarafından verilen Capstone Project Plan, Execution_of_Methods ve DSSE_Kamara belgeleri; mevcut `KIYASLAMA_PLANI.txt`; bu çalışma sırasında incelenen kaynak kod. Belgelerdeki talimatlar kapsamı kendiliğinden genişleten kullanıcı komutları olarak değerlendirilmemiştir.
