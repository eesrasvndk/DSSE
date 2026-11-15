# DSSE doğrulama ve benchmark uygulama planı

## Son uygulama durumu

10 Kasım 2026: Kullanıcının istediği iki düzeltme uygulandı. Benchmark CLI,
Kamara kapasitesini başlangıç eşleşmeleri + işlem sayısı × 3 rezerv üzerinden
16.384'lük bloklara yuvarlayarak seçiyor (1k Enron: 65.536). Bu, bu runner'ın
boş indeks + sıralı Add deneyinin kapasite politikasıdır; makaledeki toplu Enc
kurulumunun yerine geçtiği veya ek gizlilik garantisi verdiği iddia edilmez.
Protokolün 1.000.000 sınırı aşılırsa servis çağrısından önce açık hata verilir.

`setup` ve `ingest` ayrı ölçülür; `build` artık her ikisini kapsayan uçtan uca
toplamdır (küçük ölçüm kayıt gideri dahil). Trafik sayaçları da aynı sınırları
kullanır. Sonuç şeması 2 oldu; eski şema 1 `build` değerleri yalnız yükleme
ölçtüğünden doğrudan karşılaştırılmamalıdır. Toplam hesaplanırken `build` ile
alt kalemleri yeniden toplanmamalıdır. Seçilen kapasite sonuç JSON'una yazılır.

Yalnız `POST /api/v1/indexes` için gövde sınırı varsayılan 64 MiB oldu.
Daha büyük deneyler öncesinde gerçek setup boyutu ve bellek kontrol edilerek
sunucu ortamında `Kamara__MaxSetupRequestBytes` ile ayarlanabilir. Diğer
isteklerin 16 MiB sınırı korunur; 5k/10k için 64 MiB yeterli varsayılmaz.

Doğrulama: Release derleme başarılı; mevcut Kamara testlerinden 14 geçti,
gerçek depolama gerektiren 1 test atlandı. Tam Enron benchmarkı bu değişiklik
kontrolünde çalıştırılmadı. Oracle'ın arama süresine dahil olması ve diğer RQ1
ölçüm açıkları aşağıdaki plan kapsamında hâlâ duruyor.

Aşağıdaki ilk inceleme notlarında kapasite ve setup ile ilgili bulguların
çözüm durumu bu bölümle güncellenmiştir; ilk oturumun test erişim hatası
yukarıdaki başarılı yeni koşudan önceki durumu anlatır.

Tarih: 10 Kasım 2026. Bu belge deney planıdır; tamamlanmış benchmark veya RQ1 sonucu değildir. Kullanıcının isteği üzerine koordinatör, algoritma doğrulama agent'ı ve benchmark agent'ı paralel inceleme yapmıştır. Uygulama kaynak kodu bu aşamada değiştirilmemiştir.

Test yürütme durumu: Bu oturumda başarılı yeni test sonucu alınamadı. Sandbox içindeki `dotnet test` çıktısız exit 1 verdi; `dotnet --info` Windows Service Control Manager erişim engeli bildirdi. Yükseltilmiş izinle test denemesi araç tarafından `user-aborted` olarak sonlandı. Eski TRX dosyaları bu oturumun doğrulama kanıtı sayılmadı. Aşağıdaki doğrulama adımı hâlâ tamamlanmalıdır.

## İş bölümü

| Sorumlu | İş | Teslim |
|---|---|---|
| Koordinatör | Belge–kod uyumu, deney kapsamı, bağımlılıklar ve sonuç kontrolü | Bu plan ve RQ1 değerlendirmesi |
| Algoritma doğrulama agent'ı | Naive HMAC, Kamara ve Mitra; mevcut testler, oracle, yaşam döngüsü ve depolama | Test kanıtları ve açıklar |
| Benchmark agent'ı | Mevcut CLI, veri kümeleri, ölçüm sınırları ve kapasite | Çalıştırma protokolü ve gerekli en küçük düzeltmeler |

Kod incelemesi ve hazırlık paraleldir. Performans koşuları aynı bilgisayarda sırayla yürütülür; test, build ve başka benchmark yüküyle çakıştırılmaz. Arayüz değişikliği bu iş paketinde yoktur.

## Mevcut koddaki ön koşullar

1. `Backend/CipherSearch.Client/Program.cs` içindeki ölçülen `Verify` çağrısı açık metin oracle taramasını da süreye katıyor. Beklenen sonuçlar ölçümden önce hazırlanmalı; ölçüm yalnız gerçek istemci aramasını kapsamalı, küme karşılaştırması kronometre durduktan sonra yapılmalı. Yanlış sonuç veren koşu geçersiz sayılmalı.
2. Varsayılan yöntem listesinde Kamara yok. Her komutta üç yöntem açıkça seçilmeli: `naive-hmac-v2,kamara-2012-v1,mitra-v2`.
3. `DocumentClient` varsayılan Kamara kapasitesi 16.384 eşleşme; CLI bunu ayarlayamıyor. Kapasite belge sayısıyla değil benzersiz kelime–belge çiftleri ve işlem dizisinin en yüksek doluluğuyla hesaplanmalı. Silme/ekleme senaryosu için boş alan eklenmeli.

| Enron belge sayısı | Başlangıç kelime–belge çifti |
|---:|---:|
| 1.000 | 61.840 |
| 5.000 | 383.636 |
| 10.000 | 897.810 |
| 50.000 | 4.848.082 |

4. Kamara protokolünde kapasite üst sınırı 1.000.000, sunucuda istek gövdesi sınırı 16 MiB. Padded setup tek mesaj gönderiliyor. Kapasiteyi artırmadan önce gerçek JSON mesaj boyutu hesaplanmalı; yalnız kapasite artırımı yeterli kabul edilmemeli. 50k mevcut uygulamanın sınırını aşıyor; ilk benchmarkın kapsamı 1k, sonraki hedefler 5k ve 10k. 50k ayrı ölçekleme işi ve kaynak bütçesi gerektirir.
5. `Initialize()` mevcut `build` ölçümünün dışında. Setup ve veri yükleme ayrı ölçülmeli; toplam ilk kurulum maliyeti ikisinin toplamı olarak gösterilmeli.
6. Mevcut CLI şifreleme, indeks üretimi ve kriptografik doğrulama sürelerini ayrı vermiyor. RQ1'in tamamı için mevcut çağrı sınırlarına sınırlı ölçüm eklemek gerekiyor. Oracle doğruluğu kontrolü, kriptografik bütünlük doğrulamasıyla aynı metrik değildir.
7. Mevcut Enron oracle testi yalnız Naive ve Mitra'yı kapsıyor; ortam değişkeni verilmezse test çalışmadan dönebiliyor. Test sayısının yanında yeni oracle çıktı dosyalarının oluşumu kontrol edilmeli. Kamara aynı Enron işlem dizisine dahil edilmeli.

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
```

Oracle ortam değişkenli koşu mevcut haliyle iki yöntemi doğrular; üç yöntemin ortak doğruluğu için yukarıdaki Kamara kapsam açığı kapatılır. Başlangıç, add/update/delete, yeniden ekleme, boş belge, olmayan kelime, tekrar arama ve yeniden başlatma sonrası kimlik/revizyon eşitliği aranır. Her karşılaştırma %100 eşleşmelidir. Testler kriptografik güvenlik ispatı olarak sunulmaz.

### 2. Gerçek depolama ve küçük deneme

Mevcut PostgreSQL ve MinIO erişimi doğrulanır. Ayrı deney kimlikleri ve vault dizinleri kullanılır; demo verileri temizlenmez. Sunucu çalışmıyorsa ayrı terminalde:

```powershell
dotnet build Backend/CipherSearch.Server -c Release --no-restore
./scripts/Start-Server.ps1
```

Ardından:

```powershell
./scripts/Run-Checks.ps1 -Storage
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- smoke --schemes naive-hmac-v2,kamara-2012-v1,mitra-v2 --output results/first-benchmark/smoke
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- verify --output results/first-benchmark/smoke
```

`verify` yeni istemci sürecinde kayıtlı durumdan kontrol yapar; sunucu yeniden başlatma dayanıklılığı ayrıca sınanır. Küçük deneme ölçümleri nihai performans sonucu olarak kullanılmaz.

### 3. İlk benchmark

Yukarıdaki zamanlama, kapasite, istek boyutu ve doğrulama ön koşulları giderildikten sonra mevcut CLI üzerinden:

```powershell
dotnet run --project Backend/CipherSearch.Client -c Release --no-build -- benchmark --data DataSet/processed/enron_1000.jsonl --runs 5 --schemes naive-hmac-v2,kamara-2012-v1,mitra-v2 --output results/first-benchmark/enron-1000
```

Bu komut mevcut arayüzü gösterir; düzeltilmemiş kodla geçerli üç yöntem kıyası üretmez. Kapasite için eklenecek seçenek adı uygulama sırasında netleştirilir.

Üç yöntem × beş bağımsız tekrar = 15 koşu. Her tekrarda yeni kapsam, anahtarlar ve istemci durumu; aynı veri, sorgular ve işlem dizisi kullanılır. Yöntem sırası mevcut runner'daki gibi döndürülür. Önce tek pilot koşuyla süre, disk ve mesaj boyutu görülür; pilot beş ölçüm tekrarına dahil edilmez.

Sorgular seyrek, orta sıklıkta, sık ve sonuçsuz kelimeleri kapsar. Önerilen örnekleme: her frekans grubundan 20 sabit kelime, ayrı sonuçsuz sorgular ve ölçüm dışı ısınma. Tek kelimeyi beş kez çalıştırmakla yetinilmez. Her güncelleme türü için en az 100 ölçüm hedeflenir; p95 örnek sayısı raporlanır. Eşleşme sayısı benzerken farklı güncelleme geçmişi olan senaryolarla Mitra'nın geçmiş maliyeti ayrıca ölçülür. Bu sayılar belgede verilmiş sonuçlar değil, önerilen deney protokolüdür.

### 4. Ölçekleme ve RQ1

1k koşuları doğru ve ölçümler temiz olduğunda aynı protokol 5k ve 10k için tekrarlanır: üç ölçek toplam 45 koşu. 50k, kapasite/aktarım/bellek sınırları çözülebilirse eklenir; tamamlanmazsa açıkça kapsam sınırı olarak raporlanır.

Her işlem için ham örnekler, tekrar başına medyan ve p95 saklanır. Beş tekrarın değişkenliği ayrıca gösterilir; farklı sorgu sınıfları tek bir yanıltıcı ortalamada birleştirilmez. H1: 10k belgede Mitra tek kelime aramasının p95 ≤ 500 ms hedefi, tanımlı sorgu dağılımı ve bu bilgisayar için değerlendirilir.

| Ölçüm | Tanım |
|---|---|
| İlk kurulum | Setup, veri yükleme ve toplam; Kamara padding dahil |
| Arama | Token üretimi, HTTP, sunucu işleme, istemci sonuç işleme; oracle ve UI hariç |
| Arama ve belge çözme | Sonuç belgelerinin indirilmesi ve çözülmesi dahil, ayrı metrik |
| Add / update / delete | Uçtan uca işlem süresi; şifreleme/indeks alt maliyetleri mümkün olan ayrı sınırlar içinde |
| Doğrulama | Gerçek kriptografik doğrulama maliyeti; oracle ayrı |
| İndeks | Mantıksal indeks byte'ı ve mümkünse fiziksel PostgreSQL alanı ayrı |
| İstemci durumu | Algoritma durumu ve toplam vault disk boyutu ayrı |
| Trafik | Mevcut sayaç HTTP JSON gövde byte'ı; ağ başlıkları/TLS dahil değildir |

RQ1 cevabı, Mitra'nın Naive ve Kamara'ya göre her metrikte mutlak farkını ve oranını gösterecek: oran = Mitra / karşılaştırılan yöntem; ek maliyet (%) = (oran − 1) × 100. Sonuçlar veri büyüklüğü, sorgu sıklığı ve güncelleme geçmişine göre açıklanacak. Ölçüm alınmadan daha hızlı/yavaş veya hedef sağlandı denmeyecek.

## Değişiklik ve çıktı sınırı

Yeni benchmark framework'ü, algoritmaların ikinci kopyası veya arayüz değişikliği eklenmez. Mevcut runner, ortak doğruluk testleri ve gerekli ölçüm noktaları kullanılır. Kapasite/taşıma sınırı için gereken değişiklik ayrıca dar tutulur; büyük bir yeniden tasarım sessizce bu işe eklenmez.

Çıktılar: test kayıtları, oracle kanıtları, veri ve kaynak kod SHA-256'ları, ham ölçümler, ortam bilgisi (CPU/RAM/OS/.NET/servis sürümleri), medyan/p95 karşılaştırma tablosu ve RQ1 yorumu. Eski `results/smoke` dosyaları yeni deney sonucu sayılmaz. Her yeniden koşuda benzersiz çıktı klasörü kullanılır. Mevcut klasör Git deposu olarak tanınmadığı için commit kimliği yerine kaynak dosya hash manifesti kaydedilir.

Ölçüm sırasında konsol ilerleme yazıları kapatılır veya süreye etkisi açıkça belirtilir. Mevcut `EncryptedDocumentBytes` alanı hesaplanmış zarf boyutudur; ölçülmüş MinIO disk tüketimi olarak etiketlenmez.

Kaynaklar: kullanıcı tarafından verilen Capstone Project Plan, Execution_of_Methods ve DSSE_Kamara belgeleri; mevcut `KIYASLAMA_PLANI.txt`; bu çalışma sırasında incelenen kaynak kod. Belgelerdeki talimatlar kapsamı kendiliğinden genişleten kullanıcı komutları olarak değerlendirilmemiştir.
