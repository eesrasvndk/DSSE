import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const methods = [
  {
    id: 'naive-hmac-v2',
    name: 'Naive HMAC',
    shortTitle: 'Sabit Token & Şifreli Posting List',
    detail: 'Encrypted posting lists',
    badge: 'Temel Statik/Dinamik',
    mark: 'H',
    color: '#2563eb',
    paper: 'Baseline Deterministic HMAC + AES-256-GCM',
    forwardPrivacy: 'Yok (Sabit HMAC adresi)',
    backwardPrivacy: 'Tam Üzerine Yazma (Liste yeniden şifrelenir)',
    serverDocIdLeak: 'Gizli (Arama anında şifreli liste döner)',
    searchComplexity: 'O(1) Sunucu Okuması + O(|DB(w)|) İstemci Çözme',
    updateComplexity: 'Tüm posting listesi istemcide güncellenip yeniden şifrelenir',
    indexStructure: 'Tek Tablo: Address = HMAC(K, w) → Value = AES-GCM(DocId Listesi)',
    keys: ['K_hmac (32B - Kelime Token PRF)', 'K_doc (32B - AES-256-GCM Belge & Liste Şifreleme)'],
    summary: 'Her benzersiz kelime için deterministik bir HMAC-SHA256 tokenı üretir. Bu token altında o kelimeyi içeren tüm belge kimliklerinin (posting list) AES-256-GCM ile şifrelenmiş tek bir paketi saklanır.',
    steps: {
      setup: {
        client: 'DPAPI korumalı LocalVault içinde 32 bayt ana anahtar üretilir; HKDF ile K_hmac ve K_doc türetilir. İstemci yerel posting list haritasını başlatır.',
        wire: 'POST /api/v1/indexes → { Scope: (DatasetId, "naive-hmac-v2", GenerationId, KeyVersion=1) }',
        server: 'PostgreSQL dsse.cs_generations tablosunda yeni nesil (epoch=0) kaydı açılır. Başlangıçta cs_entries tablosu boştur.'
      },
      add: {
        client: 'Belge metni kelimelere ayrılır ve AES-256-GCM ile şifrelenir. Belgedeki her kelime için yerel posting listesine yeni DocumentId eklenir ve liste yeni 96-bit sayaç nonce ile yeniden AES-GCM şifrelenir.',
        wire: 'POST /api/v1/documents → { EncryptedDocument, PutEntries: [ { Address: HMAC(K, w), Value: AES-GCM(PostingList) } ] }',
        server: 'MinIO dsse-documents bucket\'ına şifreli belge yazılır; PostgreSQL cs_entries tablosunda ilgili HMAC adreslerindeki şifreli listeler güncellenir (UPSERT).'
      },
      search: {
        client: 'Aranan kelime normalize edilir ve tek bir sabit token hesaplanır: Token = HMAC-SHA256(K_hmac, w).',
        wire: 'POST /api/v1/searches → { Message: "naive.search", Token: <32-byte HMAC> }',
        server: 'Sunucu cs_entries tablosunda doğrudan address = Token sorgusu yapar. Eşleşen tek şifreli posting list paketini döner; içindeki belge ID\'lerini göremez.'
      },
      delete: {
        client: 'Silinen belgenin kelimeleri yerel durumdan bulunur. İlgili kelimelerin posting listelerinden DocumentId çıkarılır; liste boşaldıysa RemoveAddresses, doluysa yeni şifreli liste PutEntries olarak hazırlanır.',
        wire: 'POST /api/v1/documents/{id}/delete → { RemoveAddresses: [...], PutEntries: [...] }',
        server: 'MinIO\'dan şifreli belge silinir; cs_entries tablosunda boşalan kelime adresleri silinir, kalanların şifreli listesi güncellenir.'
      }
    }
  },
  {
    id: 'kamara-2012-v1',
    name: 'Kamara (2012)',
    shortTitle: 'Çift Zincirli Arama (As/Ts) ve Silme (Ad/Td) İndeksi',
    detail: 'Linked search and deletion indexes',
    badge: 'CCS 2012 · Dinamik SSE',
    mark: 'K',
    color: '#7c3aed',
    paper: 'Kamara, Papamanthou, Roeder (ACM CCS 2012)',
    forwardPrivacy: 'Yok (AddToken içindeki F(w) deterministiktir)',
    backwardPrivacy: 'XOR Bağlantı Koparma + Ts[free] Boş Hücre Havuzu',
    serverDocIdLeak: 'Açık (Arama zinciri As açıldığında sunucu eşleşen DocumentId\'leri görür)',
    searchComplexity: 'O(|DB(w)|) — Sunucu yalnız eşleşen kelime zincirini yürür',
    updateComplexity: 'O(|w(f)|) — Kelime başına As/Ad düğümü ekleme veya XOR ile silme',
    indexStructure: 'Arama Tablosu Ts + Arama Dizisi As (52B) + Silme Tablosu Td + Silme Dizisi Ad (88B) + Ts[free]',
    keys: ['K1 (F PRF - Ts/Td Tablo Başları)', 'K2 (G PRF - Baş İşaretçi Maskesi)', 'K3 (P PRF - H1/H2 Düğüm Maskeleri)', 'K4 (AES-256-GCM Belge Şifreleme)'],
    summary: 'Arama süresini belge sayısından bağımsız (optimal O(|DB(w)|)) tutarken dinamik ekleme ve silmeyi desteklemek için şifreli arama zinciri (As) ile çift yönlü silme zincirini (Ad) birleştirir. Sabit kapasiteli hücre havuzu (16.384 çift) kullanır.',
    steps: {
      setup: {
        client: 'İstemci 16.384 hücrelik As (52B) ve Ad (88B) dizilerini rastgele permütasyonla kurar. Boş hücre çiftlerini Ts[free] zincirine bağlar ve tüm başlangıç yapısını tek seferde şifreler.',
        wire: 'POST /api/v1/indexes → { Setup: "kamara.setup" (Şifreli As/Ad hücreleri, Ts/Td ve Ts[free] başı) }',
        server: 'Sunucu 0x4B önekli adres uzayına tüm şifreli As ve Ad hücrelerini yazar. Hangi hücrenin dolu, hangisinin boş dolgu (padding) olduğunu ayırt edemez.'
      },
      add: {
        client: 'Belgedeki her benzersiz kelime için (F(w), G(w)) ve sıfır işaretçili şifreli (As, Ad) düğüm çifti içeren AddToken oluşturulur. P(w) sunucuya verilmez.',
        wire: 'POST /api/v1/documents → { EncryptedDocument, IndexMutation: "kamara.mutate" (AddToken: F(w), G(w), λ_i) }',
        server: 'Sunucu Ts[free]\'den boş bir (As, Ad) hücre çifti alır, kelime zincirinin (Ts[F(w)]) başına bağlar, eski başın Ad komşu işaretçilerini XOR farkıyla günceller ve Td[F(f)] silme zincirini kaydeder.'
      },
      search: {
        client: 'İstemci aranan kelime için 3 bileşenli arama tokenı üretir: SrchToken = (F_K1(w), G_K2(w), P_K3(w)).',
        wire: 'POST /api/v1/searches → { Message: "kamara.search", F: <32B>, G: <16B>, P: <32B> }',
        server: 'Sunucu Ts[F(w)] ⊕ G(w) ile ilk As adresini bulur; P(w) ve düğümdeki rastgele r ile H1(P(w), r) maskesini üretip As zincirini sonuna kadar açar ve bulduğu DocumentId listesini döner.'
      },
      delete: {
        client: 'İstemci silinecek belge için DelToken = (F_K1(f), G_K2(f), P_K3(f), id(f)) üretir.',
        wire: 'POST /api/v1/documents/{id}/delete → { IndexMutation: "kamara.mutate" (DelToken) }',
        server: 'Sunucu Td[F(f)] üzerinden belgenin Ad zincirini H2(P(f), r\') ile açar; önceki/sonraki As ve Ad komşu işaretçilerini XOR ile birbirine bağlar, silinen Ad hücresini rastgele doldurur ve boşalan As hücresini Ts[free] havuzuna geri ekler.'
      }
    }
  },
  {
    id: 'mitra-v2',
    name: 'MITRA (2018)',
    shortTitle: 'Sayaç Tabanlı İleri Gizli (Forward-Private) DSSE',
    detail: 'Counter-based update history',
    badge: 'CCS 2018 · Forward Private',
    mark: 'M',
    color: '#059669',
    paper: 'Ghareh Chamani, Papadopoulos, Papamanthou, Jalili (ACM CCS 2018)',
    forwardPrivacy: 'Var (Her güncelleme yeni sayaçla bağımsız PRF adresi üretir)',
    backwardPrivacy: 'Geçmiş Tabanlı (Silme işlemi yeni DELETE kaydı ekler, istemcide elenir)',
    serverDocIdLeak: 'Tamamen Gizli (Opak Blob + XOR maskeli indeks kaydı)',
    searchComplexity: 'O(a_w) — Kelimenin toplam ekleme + silme geçmişi sayısı kadar okuma',
    updateComplexity: 'O(|w(f)|) — Değişen kelime başına 1 yeni PRF adresi ve 1 XOR maskesi',
    indexStructure: 'İstemcide FileCnt[w] Sayacı + Sunucuda T[Addr(w, cnt)] = (DocId || Op) ⊕ Mask(w, cnt) + Opak Bloblar',
    keys: ['K_addr (PRF - Kelime/Sayaç Adres Üretimi)', 'K_mask (PRF - Değer XOR Maskesi)', 'K_doc (AES-256-GCM Opak Blob Şifreleme)'],
    summary: 'İleri gizlilik (Forward Privacy) sağlamak için her kelimenin güncelleme sayacını (FileCnt[w]) istemcide tutar. Her ekleme ve silme işlemi sunucuda yepyeni, ilişkilendirilemez bir PRF adresine yazılır; sunucu yeni eklenen belgenin daha önce aranan bir kelimeyi içerdiğini anlayamaz.',
    steps: {
      setup: {
        client: 'İstemci LocalVault içinde boş kelime sayaç tablosu (FileCnt = {}) ve HKDF anahtarlarını oluşturur.',
        wire: 'POST /api/v1/indexes → { Scope: (DatasetId, "mitra-v2", GenerationId, KeyVersion=1) }',
        server: 'PostgreSQL dsse.cs_generations tablosunda yeni nesil açılır. MITRA\'da cs_documents tablosuna belge kimliği dahi yazılmaz!'
      },
      add: {
        client: 'Belge şifrelenip rastgele bir BlobId ile MinIO\'ya yüklenir. Her kelime için yerel sayaç artırılır (cnt = FileCnt[w] + 1); Addr = PRF(K_addr, w || cnt) ve Val = (DocId || ADD) ⊕ PRF(K_mask, w || cnt) hesaplanır.',
        wire: 'POST /api/v1/opaque-blobs + POST /api/v1/private-index-writes → { Entries: [ { Address, Value } ] }',
        server: 'Sunucu belge kimliği, sürüm veya işlem türü (Add/Delete) bilmeden yalnızca opak (Address, Value) çiftlerini cs_entries tablosuna ekler.'
      },
      search: {
        client: 'İstemci kelimenin güncel sayacına (c = FileCnt[w]) bakar ve 1\'den c\'ye kadar tüm geçmiş adresleri üretir: [Addr(w, 1), Addr(w, 2), ..., Addr(w, c)].',
        wire: 'POST /api/v1/searches → { Message: "mitra.search", Addresses: [Addr_1, ..., Addr_c] }',
        server: 'Sunucu gönderilen adreslerdeki şifreli kayıtları okur ve döner. İstemci maskeleri (PRF(K_mask, w || i)) kaldırır, ADD ve DELETE geçmişini kronolojik birleştirip yalnız canlı belgeleri gösterir.'
      },
      delete: {
        client: 'Silinen belgedeki her kelime için sayaç tekrar artırılır (cnt = FileCnt[w] + 1) ve bu kez (DocId || DELETE) ⊕ PRF(K_mask, w || cnt) kaydı üretilir.',
        wire: 'POST /api/v1/private-index-writes → { Entries: [ { Address: Addr(w, cnt), Value: MaskedDelete } ] }',
        server: 'Sunucu bunun bir silme işlemi olduğunu dahi anlamaz; yeni bir opak indeks kaydı olarak yazar. Sonraki aramada hem ADD hem DELETE kaydı döner, istemci bunları birbirinden düşer.'
      }
    }
  }
];

const sections = {
  algoritmalar: '1. Algoritmalar Nasıl Çalışır?',
  documents: '2. Belge Koleksiyonu',
  search: '3. Şifreli Arama',
  verification: '4. Üçlü Karşılaştırma',
  server: '5. Sunucu Görünümü & Sızıntı'
};

const sampleKeywords = ['meeting', 'energy', 'contract', 'houston', 'trading', 'schedule', 'finance', 'project'];
const maxBytes = 256 * 1024;
const pageSize = 10;
const number = new Intl.NumberFormat('tr-TR');
const size = bytes => bytes === undefined || bytes === null ? '—' : bytes < 1024 ? bytes + ' B' : bytes < 1048576
  ? (bytes / 1024).toFixed(1) + ' KiB' : (bytes / 1048576).toFixed(2) + ' MiB';
const textBytes = text => new TextEncoder().encode(text).length;

async function api(scheme, path, method = 'GET', data) {
  const response = await fetch('/api/' + (scheme ? scheme + '/' : '') + path, {
    method,
    headers: {
      'X-CipherSearch': 'local-client',
      ...(data !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  const result = await response.json().catch(() => null);
  if (!response.ok || result === null)
    throw new Error(result?.message || 'Servis isteği tamamlanamadı. Yerel servisleri kontrol edip tekrar deneyin.');
  return result;
}

function App() {
  const [section, setSection] = useState('algoritmalar');
  const [scheme, setScheme] = useState(methods[0].id);
  const [overview, setOverview] = useState(null);
  const [collection, setCollection] = useState(null);
  const [search, setSearch] = useState(null);
  const [verification, setVerification] = useState(null);
  const [leakageEvents, setLeakageEvents] = useState([]);
  const [query, setQuery] = useState('meeting');
  const [verify, setVerify] = useState(true);
  const [page, setPage] = useState(0);
  const [busy, setBusy] = useState('Koleksiyon yükleniyor…');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [editor, setEditor] = useState(null);
  const [reader, setReader] = useState(null);
  const [deleting, setDeleting] = useState(null);
  const fileInput = useRef(null);
  const method = methods.find(m => m.id === scheme);

  async function refreshOverview() {
    try {
      const [ov, leak] = await Promise.all([
        api(null, 'overview'),
        api(null, 'server-leakage')
      ]);
      setOverview(ov);
      setLeakageEvents(leak.events || []);
    } catch { /* ignore background overview errors */ }
  }

  async function refresh() {
    const data = await api(scheme, 'documents');
    setCollection(data);
    setPage(0);
    await refreshOverview();
  }

  async function perform(label, action) {
    setBusy(label);
    setError('');
    setNotice('');
    try { await action(); }
    catch (failure) { setError(failure.message); }
    finally { setBusy(''); }
  }

  useEffect(() => {
    let active = true;
    setBusy('Koleksiyon yükleniyor…');
    setCollection(null);
    setPage(0);
    setError('');
    setNotice('');
    Promise.all([
      api(scheme, 'documents'),
      api(null, 'overview').catch(() => null),
      api(null, 'server-leakage').catch(() => ({ events: [] }))
    ])
      .then(([data, ov, leak]) => {
        if (!active) return;
        setCollection(data);
        if (ov) setOverview(ov);
        if (leak) setLeakageEvents(leak.events || []);
      })
      .catch(failure => { if (active) setError(failure.message); })
      .finally(() => { if (active) setBusy(''); });
    return () => { active = false; };
  }, [scheme]);

  function newDocument() {
    setError('');
    setEditor({ documentId: crypto.randomUUID(), revision: 0, name: '', text: '' });
  }

  async function upload(files) {
    if (!files.length) return;
    await perform('Dosyalar hazırlanıyor…', async () => {
      if (files.length > 20) throw new Error('Tek seferde en fazla 20 metin dosyası seçebilirsiniz.');
      const prepared = [];
      for (const file of files) {
        if (!/\.(txt|md|csv|json|jsonl|eml)$/i.test(file.name) || file.size > maxBytes)
          throw new Error(file.name + ' en fazla 256 KiB boyutunda desteklenen bir metin dosyası olmalıdır.');
        let text;
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer()); }
        catch { throw new Error(file.name + ' geçerli bir UTF-8 metin dosyası değil.'); }
        if (!text.trim()) throw new Error(file.name + ' boş.');
        prepared.push({ documentId: crypto.randomUUID(), revision: 0, name: file.name.slice(0, 180), text });
      }
      let uploaded = 0;
      try {
        for (const doc of prepared) {
          setBusy(`Şifreleniyor ve yükleniyor (${uploaded + 1} / ${prepared.length})…`);
          await api(scheme, 'documents', 'POST', doc);
          uploaded++;
        }
      } catch (failure) {
        await refresh().catch(() => {});
        throw new Error(uploaded + ' dosya yüklendi. ' + failure.message);
      }
      await refresh();
      setNotice(number.format(uploaded) + ' dosya şifrelenerek koleksiyona eklendi.');
    });
  }

  function importEnron() {
    return perform(`${method.name} koleksiyonuna Enron 1.000 veri seti aktarılıyor…`, async () => {
      const result = await api(scheme, 'import-enron', 'POST');
      await refresh();
      setNotice(result.imported
        ? `${number.format(result.imported)} Enron belgesi ${method.name} indeksine şifrelenerek aktarıldı.`
        : 'Bu koleksiyonda Enron belgeleri zaten mevcut.');
    });
  }

  function seedDemoAll() {
    return perform('Üç algoritmaya (Naive HMAC, Kamara, MITRA) ortak 25 Enron belgesi eşitleniyor…', async () => {
      const result = await api(null, 'seed-demo-all', 'POST');
      await refresh();
      const totalAdded = (result.results || []).reduce((acc, r) => acc + (r.imported || 0), 0);
      setNotice(totalAdded > 0
        ? `Üç algoritmaya ortak 25 Enron belgesi başarıyla yüklendi (${totalAdded} yeni şifreli kayıt). Artık 3'lü karşılaştırma yapabilirsiniz!`
        : 'Her üç algoritmada da ortak 25 Enron belgesi zaten yüklü ve eşlenmiş durumda.');
    });
  }

  function find(event, customQuery) {
    if (event) event.preventDefault();
    const targetQuery = (customQuery !== undefined ? customQuery : query).trim();
    if (!targetQuery) return;
    if (customQuery !== undefined) setQuery(customQuery);
    return perform(verify ? `${method.name} üzerinde şifreli arama ve açık metin doğrulaması yapılıyor…` : `${method.name} şifreli indeksinde aranıyor…`, async () => {
      const data = await api(scheme, 'search', 'POST', { keyword: targetQuery, verify, inspect: true });
      setSearch({ ...data, keyword: targetQuery, scheme });
      setPage(0);
      await refreshOverview();
    });
  }

  function runVerification(event, customQuery) {
    if (event) event.preventDefault();
    const targetQuery = (customQuery !== undefined ? customQuery : query).trim();
    if (!targetQuery) return;
    if (customQuery !== undefined) setQuery(customQuery);
    setVerification(null);
    return perform('Naive HMAC, Kamara ve MITRA koleksiyonları aynı sorgu ile karşılaştırılıyor…', async () => {
      const res = await api(null, 'verification', 'POST', { keyword: targetQuery });
      setVerification(res);
      await refreshOverview();
    });
  }

  function openDocument(doc, edit = false) {
    return perform('Belge istemcide AES-256-GCM ile çözülüyor…', async () => {
      const data = await api(scheme, 'documents/' + doc.documentId);
      if (edit) setEditor({ ...data.document, text: data.text });
      else setReader(data);
    });
  }

  function save(event) {
    event.preventDefault();
    return perform('Belge şifreleniyor ve indeks güncelleniyor…', async () => {
      const path = editor.revision ? 'documents/' + editor.documentId : 'documents';
      await api(scheme, path, editor.revision ? 'PUT' : 'POST', editor);
      setEditor(null);
      await refresh();
      setNotice('Belge AES-256-GCM ile şifrelendi ve indeks güncellendi.');
    });
  }

  function remove() {
    return perform('Belge siliniyor ve şifreli indeks güncelleniyor…', async () => {
      await api(scheme, 'documents/' + deleting.documentId, 'DELETE', { revision: deleting.revision });
      setDeleting(null);
      await refresh();
      setNotice('Belge koleksiyondan ve arama sonuçlarından kaldırıldı.');
    });
  }

  const searching = section === 'search';
  const rows = searching ? search?.documents ?? [] : collection?.documents ?? [];
  const visible = rows.slice(page * pageSize, (page + 1) * pageSize);
  const unavailable = Boolean(busy || !collection);
  const modalOpen = Boolean(editor || reader || deleting);
  const bytes = editor ? textBytes(editor.text) : 0;

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-icon" aria-hidden="true">◈</span>
        <span>CipherSearch<small>Dinamik Şifreli Arama (DSSE)</small></span>
      </div>

      <nav className="sections" aria-label="Çalışma alanı bölümleri">
        <h2>Çalışma Alanı</h2>
        {Object.entries(sections).map(([id, label]) => (
          <button
            key={id}
            className="section-link"
            aria-current={section === id ? 'page' : undefined}
            disabled={Boolean(busy || modalOpen)}
            onClick={() => { setSection(id); setPage(0); setError(''); }}
          >
            {label}
          </button>
        ))}
      </nav>

      <nav aria-label="DSSE Algoritmaları">
        <h2>3 DSSE Algoritması (Ayrı Seçim)</h2>
        {methods.map(item => {
          const stat = overview?.schemes?.find(s => s.scheme === item.id);
          return (
            <button
              key={item.id}
              className="method"
              aria-pressed={scheme === item.id}
              disabled={Boolean(busy || modalOpen)}
              onClick={() => setScheme(item.id)}
            >
              <span className="method-mark" style={{ background: scheme === item.id ? item.color : undefined }} aria-hidden="true">{item.mark}</span>
              <span>
                <strong>{item.name}</strong>
                <small>{item.shortTitle}</small>
                {stat && <small className="method-mini-stat">{stat.documentCount} belge · {size(stat.status?.indexBytes)}</small>}
              </span>
              <span className="method-indicator" aria-hidden="true" />
            </button>
          );
        })}
      </nav>

      <div className="sidebar-actions">
        <button className="seed-btn" disabled={Boolean(busy || modalOpen)} onClick={seedDemoAll}>
          ⚡ 3 Yönteme Ortak 25 Belge Yükle
        </button>
      </div>

      <div className="sidebar-note">
        <span className="dot" aria-hidden="true" /> Güven Sınırı Aktif
        <small>İstemci (5190) anahtarları tutar; Depolama Sunucusu (5180) yalnız şifreli indeks ve blokları görür.</small>
      </div>
    </aside>

    <main className="main">
      <header className="topbar">
        <div className="topbar-left">
          <span>{sections[section]}</span>
          <span className="breadcrumb-separator" aria-hidden="true">/</span>
          <strong style={{ color: method.color }}>{method.name}</strong>
          <span className="scheme-pill">{method.badge}</span>
        </div>
        <div className="topbar-right">
          <span className="trust-pill client-pill" title="Tarayıcı + Güvenilir İstemci Servisi (DPAPI + AES-256-GCM)">
            <span className="dot" /> İstemci: 127.0.0.1:5190
          </span>
          <span className="trust-pill server-pill" title="Güvenilmeyen Depolama Sunucusu (PostgreSQL dsse + MinIO)">
            <span className="dot warning-dot" /> Sunucu: 127.0.0.1:5180
          </span>
        </div>
      </header>

      <div className="content">
        {/* Üstte 3 Algoritma Hızlı Seçim ve Canlı Durum Kartları */}
        <div className="algo-selector-strip" role="region" aria-label="Algoritma Seçimi ve Canlı Metrikler">
          {methods.map(item => {
            const stat = overview?.schemes?.find(s => s.scheme === item.id);
            const active = scheme === item.id;
            return (
              <div
                key={item.id}
                className={'algo-strip-card' + (active ? ' active' : '')}
                style={{ '--algo-color': item.color }}
                onClick={() => { if (!busy && !modalOpen) setScheme(item.id); }}
              >
                <div className="algo-strip-head">
                  <span className="algo-strip-mark" style={{ background: item.color }}>{item.mark}</span>
                  <div>
                    <div className="algo-strip-title">
                      <strong>{item.name}</strong>
                      {active && <span className="active-tag">SEÇİLİ</span>}
                    </div>
                    <small>{item.shortTitle}</small>
                  </div>
                </div>
                <div className="algo-strip-metrics">
                  <div><span>Belgeler</span><strong>{stat ? number.format(stat.documentCount) : '—'}</strong></div>
                  <div><span>İndeks Boyutu</span><strong>{stat?.status ? size(stat.status.indexBytes) : '—'}</strong></div>
                  <div><span>Kayıt (cs_entries)</span><strong>{stat?.status ? number.format(stat.status.indexEntries) : '—'}</strong></div>
                  <div><span>Epoch</span><strong>{stat?.status ? number.format(stat.status.epoch) : '—'}</strong></div>
                </div>
              </div>
            );
          })}
        </div>

        {error && !modalOpen && <div className="alert error" role="alert">{error}</div>}
        {notice && <div className="alert success" role="status">{notice}</div>}

        {/* BÖLÜM 1: 3 ALGORİTMA NASIL ÇALIŞIR? */}
        {section === 'algoritmalar' && (
          <AlgorithmExplorer
            selectedMethod={method}
            allMethods={methods}
            onSelectMethod={setScheme}
            onGoSearch={() => setSection('search')}
            onGoCompare={() => setSection('verification')}
            onGoServer={() => setSection('server')}
            onSeedAll={seedDemoAll}
            busy={busy}
          />
        )}

        {/* BÖLÜM 4: ÜÇLÜ KARŞILAŞTIRMA VE DOĞRULAMA */}
        {section === 'verification' && (
          <ComparisonView
            query={query}
            setQuery={setQuery}
            busy={busy}
            result={verification}
            overview={overview}
            onSubmit={runVerification}
            onSeedAll={seedDemoAll}
            onSelectSchemeAndInspect={(targetScheme, row) => {
              setScheme(targetScheme);
              if (row.observation) {
                setSearch({
                  keyword: verification.keyword,
                  scheme: targetScheme,
                  documents: row.matchedDocuments || [],
                  elapsedMs: row.elapsedMs || 0,
                  oracle: { passed: row.status === 'PASS', expectedCount: row.expected?.length || 0 },
                  searchId: row.observation.searchId,
                  observation: row.observation
                });
              }
              setSection('server');
            }}
          />
        )}

        {/* BÖLÜM 5: SUNUCU GÖRÜNÜMÜ VE SIZINTI ANALİZİ */}
        {section === 'server' && (
          <ServerView
            method={method}
            allMethods={methods}
            onSelectMethod={setScheme}
            search={search}
            leakageEvents={leakageEvents}
            overview={overview}
            onSearch={() => setSection('search')}
            onRefreshLeakage={refreshOverview}
            busy={busy}
          />
        )}

        {/* BÖLÜM 2 & 3: BELGE KOLEKSİYONU VE ŞİFRELİ ARAMA */}
        {(section === 'documents' || searching) && (
          <>
            <div className="page-heading">
              <div>
                <h1>{searching ? `${method.name} ile Şifreli Arama` : `${method.name} Belge Koleksiyonu`}</h1>
                <p>
                  {searching
                    ? `${method.shortTitle} yapısını kullanarak sunucuya açık kelime göndermeden arama yapın.`
                    : `${method.name} algoritmasının kendi izole anahtar ve şifreli indeks kapsamındaki belgeleri yönetin.`}
                </p>
              </div>
              <div className="toolbar">
                {section === 'documents' && (
                  <>
                    <button className="secondary" disabled={Boolean(busy)} onClick={seedDemoAll}>
                      ⚡ 3 Yönteme Ortak 25 Belge Yükle
                    </button>
                    <button className="primary" disabled={unavailable} onClick={newDocument}>
                      <span aria-hidden="true">＋</span> Yeni Belge Ekle
                    </button>
                  </>
                )}
                {searching && (
                  <button className="secondary" disabled={Boolean(busy)} onClick={() => setSection('verification')}>
                    ⇄ 3 Algoritmayı Yan Yana Kıyasla
                  </button>
                )}
              </div>
            </div>

            <section className="library" aria-label={sections[section]} aria-busy={Boolean(busy)}>
              {!searching && (
                <div className="library-head">
                  <div>
                    <h2>{method.name} Koleksiyon Yönetimi</h2>
                    <p>
                      Her belge istemcide <strong>AES-256-GCM</strong> ile şifrelenir; indeks güncellemeleri{' '}
                      <code>{method.id}</code> protokolüyle PostgreSQL <code>dsse.cs_entries</code> tablosuna yazılır.
                    </p>
                  </div>
                  <div className="toolbar">
                    <button className="secondary" disabled={unavailable} onClick={() => fileInput.current.click()}>
                      Dosya Yükle (.txt/.md/.json)
                    </button>
                    <button className="secondary" disabled={Boolean(busy)} onClick={importEnron}>
                      Enron 1.000 Yükle ({method.name})
                    </button>
                    <input
                      ref={fileInput}
                      type="file"
                      hidden
                      multiple
                      accept=".txt,.md,.csv,.json,.jsonl,.eml"
                      onChange={event => {
                        const files = Array.from(event.currentTarget.files);
                        event.currentTarget.value = '';
                        upload(files);
                      }}
                    />
                  </div>
                </div>
              )}

              {searching && (
                <div className="search-box-area">
                  <form className="search standalone-search" onSubmit={e => find(e)}>
                    <div className="search-field">
                      <span className="search-icon" aria-hidden="true" />
                      <input
                        aria-label="Aranacak kelime"
                        placeholder="Tek bir anahtar kelime girin, örn. meeting, energy, contract"
                        value={query}
                        onChange={event => setQuery(event.target.value)}
                        maxLength={200}
                        disabled={unavailable}
                        required
                      />
                    </div>
                    <button className="primary" disabled={unavailable || !query.trim()}>
                      Şifreli Ara ({method.name})
                    </button>
                  </form>

                  <div className="search-options-row">
                    <label className="verify">
                      <input
                        type="checkbox"
                        checked={verify}
                        disabled={unavailable}
                        onChange={event => setVerify(event.target.checked)}
                      />
                      Sonuçları istemcide açık metin taraması (Plaintext Oracle) ile doğrula
                    </label>
                    <div className="chip-group">
                      <span>Hızlı örnek sorgular:</span>
                      {sampleKeywords.map(kw => (
                        <button
                          key={kw}
                          type="button"
                          className={'chip' + (query === kw ? ' active' : '')}
                          disabled={unavailable}
                          onClick={() => find(null, kw)}
                        >
                          {kw}
                        </button>
                      ))}
                    </div>
                  </div>

                  {search && search.scheme === scheme && (
                    <div className="search-telemetry-banner">
                      <div className="telemetry-item">
                        <span>Aranan Kelime (İstemci)</span>
                        <strong>“{search.keyword}”</strong>
                      </div>
                      <div className="telemetry-item">
                        <span>Arama Süresi</span>
                        <strong>{search.elapsedMs.toFixed(2)} ms</strong>
                      </div>
                      <div className="telemetry-item">
                        <span>İstemci Canlı Sonuç</span>
                        <strong>{number.format(search.documents.length)} belge</strong>
                      </div>
                      <div className="telemetry-item">
                        <span>Sunucudan Dönen Kayıt</span>
                        <strong>
                          {search.observation ? number.format(search.observation.returnedEntryCount) : '—'} kayıt
                        </strong>
                      </div>
                      <div className="telemetry-item">
                        <span>Gönderilen Token / Adres</span>
                        <strong>
                          {search.observation
                            ? `${search.observation.tokenCount} token · ${search.observation.addressCount} adres`
                            : '—'}
                        </strong>
                      </div>
                      <div className="telemetry-item">
                        <span>Sunucuda Görünen DocID</span>
                        <strong className={search.observation?.observedDocumentCount > 0 ? 'warn-value' : 'safe-value'}>
                          {search.observation ? `${search.observation.observedDocumentCount} adet` : '—'}
                        </strong>
                      </div>
                      <div className="telemetry-actions">
                        <button className="primary-outline" onClick={() => setSection('server')}>
                          🔍 Sunucu Ne Gördü? (Detaylı İncele)
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              <div className="collection-head">
                <div>
                  <h3>
                    {searching ? 'Şifreli Arama Sonuçları' : 'Koleksiyondaki Belgeler'}{' '}
                    <span className="count">{number.format(rows.length)}</span>
                  </h3>
                  {searching && search && (
                    <p>
                      “{search.keyword}” sorgusu · {search.elapsedMs.toFixed(1)} ms
                      {search.oracle && (
                        <span className={search.oracle.passed ? 'check passed' : 'check failed'}>
                          {search.oracle.passed
                            ? '✓ Oracle Doğrulandı (%100 Eşleşme)'
                            : '✗ Uyuşmazlık · Beklenen: ' + number.format(search.oracle.expectedCount)}
                        </span>
                      )}
                    </p>
                  )}
                </div>
                <div className="toolbar">
                  {searching && search && (
                    <button className="quiet" disabled={Boolean(busy)} onClick={() => setSection('server')}>
                      Sunucu görünümünü aç →
                    </button>
                  )}
                  {searching && (query || search) && (
                    <button
                      className="quiet"
                      disabled={Boolean(busy)}
                      onClick={() => { setSearch(null); setQuery(''); setPage(0); }}
                    >
                      Aramayı temizle
                    </button>
                  )}
                  {!searching && (
                    <button className="quiet" disabled={Boolean(busy)} onClick={() => perform('Koleksiyon yenileniyor…', refresh)}>
                      Yenile
                    </button>
                  )}
                </div>
              </div>

              {busy && (
                <div className="working" role="status">
                  <span className="spinner" aria-hidden="true" />
                  {busy}
                </div>
              )}

              {visible.length > 0 ? (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">Belge Adı ve Kimliği (DocumentId)</th>
                        <th scope="col">Sürüm (Revision)</th>
                        <th scope="col">İşlemler</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visible.map(doc => (
                        <tr key={doc.documentId}>
                          <td>
                            <button className="doc-name" disabled={Boolean(busy)} onClick={() => openDocument(doc)}>
                              <span className="file-icon" aria-hidden="true">▤</span>
                              <span>
                                {doc.name}
                                <small className="document-id">{doc.documentId}</small>
                              </span>
                            </button>
                          </td>
                          <td>
                            <span className="revision">v{doc.revision}</span>
                          </td>
                          <td>
                            <div className="row-actions">
                              <button className="quiet" disabled={Boolean(busy)} onClick={() => openDocument(doc)}>
                                Oku (Çöz)
                              </button>
                              <button className="quiet" disabled={Boolean(busy)} onClick={() => openDocument(doc, true)}>
                                Düzenle
                              </button>
                              <button
                                className="quiet danger-text"
                                disabled={Boolean(busy)}
                                onClick={() => { setError(''); setDeleting(doc); }}
                              >
                                Sil
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                !busy && (
                  <div className="empty">
                    <span className="empty-icon" aria-hidden="true">▤</span>
                    <h3>
                      {!collection
                        ? 'Koleksiyon erişilemez durumda'
                        : searching
                        ? search
                          ? 'Eşleşen belge bulunamadı'
                          : 'Arama yapmak için bir anahtar kelime girin'
                        : `${method.name} koleksiyonu henüz boş`}
                    </h3>
                    <p>
                      {!collection
                        ? 'Yerel servisleri kontrol edip sayfayı yenileyin.'
                        : searching
                        ? search
                          ? 'Başka bir anahtar kelime deneyin veya koleksiyona örnek veri yükleyin.'
                          : 'Örneğin "meeting", "energy" veya "contract" kelimesini aratabilirsiniz.'
                        : 'Yeni belge oluşturun, dosya yükleyin veya "⚡ 3 Yönteme Ortak 25 Belge Yükle" butonuna tıklayın.'}
                    </p>
                  </div>
                )
              )}

              <div className="library-footer">
                <span>
                  {rows.length > pageSize
                    ? `${number.format(page * pageSize + 1)}–${number.format(Math.min(rows.length, (page + 1) * pageSize))} / Toplam ${number.format(rows.length)}`
                    : `AES-256-GCM belge şifreleme · Aktif Şema: ${method.id}`}
                </span>
                {rows.length > pageSize && (
                  <div className="toolbar">
                    <button className="quiet" disabled={page === 0 || Boolean(busy)} onClick={() => setPage(page - 1)}>
                      Önceki
                    </button>
                    <button
                      className="quiet"
                      disabled={(page + 1) * pageSize >= rows.length || Boolean(busy)}
                      onClick={() => setPage(page + 1)}
                    >
                      Sonraki
                    </button>
                  </div>
                )}
              </div>
            </section>
          </>
        )}
      </div>
    </main>

    {editor && (
      <Modal title={editor.revision ? 'Belgeyi Düzenle (Update)' : 'Yeni Belge Oluştur (Add)'} onClose={() => setEditor(null)} busy={busy}>
        <form onSubmit={save}>
          <label htmlFor="document-name">Belge Adı (Yalnızca istemci kasasında saklanır)</label>
          <input
            id="document-name"
            autoFocus
            required
            maxLength={180}
            value={editor.name}
            disabled={Boolean(busy)}
            onChange={event => setEditor({ ...editor, name: event.target.value })}
            placeholder="Örn. Houston Enerji Toplantı Notları"
          />
          <label htmlFor="document-text">Belge Metni (AES-256-GCM ile şifrelenir ve indekslenir)</label>
          <textarea
            id="document-text"
            required
            rows={10}
            value={editor.text}
            disabled={Boolean(busy)}
            onChange={event => setEditor({ ...editor, text: event.target.value })}
            placeholder="Aranabilir belge içeriğini girin…"
          />
          <div className={'editor-meta' + (bytes > maxBytes ? ' danger-text' : '')}>{size(bytes)} / 256 KiB</div>
          {error && <p className="alert error" role="alert">{error}</p>}
          <div className="modal-actions">
            <button type="button" className="secondary" disabled={Boolean(busy)} onClick={() => setEditor(null)}>
              İptal
            </button>
            <button className="primary" disabled={Boolean(busy || !editor.name.trim() || !editor.text.trim() || bytes > maxBytes)}>
              {busy ? 'Şifreleniyor…' : 'Şifrele ve Kaydet'}
            </button>
          </div>
        </form>
      </Modal>
    )}

    {reader && (
      <Modal title={reader.document.name} onClose={() => setReader(null)}>
        <div className="reader-meta">
          <span>İstemcide AES-256-GCM ile çözüldü · {size(textBytes(reader.text))}</span>
          <span>Sürüm (Revision) v{reader.document.revision}</span>
        </div>
        <p className="document-id">{reader.document.documentId}</p>
        <pre className="reader">{reader.text}</pre>
        <div className="modal-actions">
          <button
            className="secondary"
            onClick={() => {
              setEditor({ ...reader.document, text: reader.text });
              setReader(null);
            }}
          >
            Düzenle
          </button>
          <button className="primary" onClick={() => setReader(null)}>
            Kapat
          </button>
        </div>
      </Modal>
    )}

    {deleting && (
      <Modal title="Belge Silinsin mi?" onClose={() => setDeleting(null)} busy={busy}>
        <p>
          <strong>{deleting.name}</strong> belgesi <strong>{method.name}</strong> koleksiyonundan ve şifreli arama sonuçlarından kaldırılacak.
        </p>
        <p className="modal-subnote">
          {method.id === 'mitra-v2'
            ? 'Not: MITRA algoritmasında silme işlemi sunucuya yeni bir şifreli DELETE geçmiş kaydı ekler (Forward Privacy).'
            : method.id === 'kamara-2012-v1'
            ? 'Not: Kamara algoritmasında DelToken ile Ad/As zincir bağları XOR ile koparılır ve hücreler Ts[free] havuzuna iade edilir.'
            : 'Not: Naive HMAC algoritmasında ilgili kelimelerin şifreli posting listeleri güncellenerek yeniden yazılır.'}
        </p>
        {error && <p className="alert error" role="alert">{error}</p>}
        <div className="modal-actions">
          <button autoFocus className="secondary" disabled={Boolean(busy)} onClick={() => setDeleting(null)}>
            Vazgeç
          </button>
          <button className="danger" disabled={Boolean(busy)} onClick={remove}>
            {busy ? 'Siliniyor…' : 'Belgeyi Sil'}
          </button>
        </div>
      </Modal>
    )}
  </div>;
}

/* ============================================================================
 * 1. ALGORİTMALAR NASIL ÇALIŞIR? (3 ALGORİTMA MİMARİ VE PROTOKOL SİMÜLATÖRÜ)
 * ============================================================================ */
function AlgorithmExplorer({ selectedMethod, allMethods, onSelectMethod, onGoSearch, onGoCompare, onGoServer, onSeedAll, busy }) {
  const [activeOp, setActiveOp] = useState('search');
  const [compareAllOps, setCompareAllOps] = useState(false);

  const opLabels = {
    setup: { title: '1. Kurulum (Setup & KeyGen)', icon: '🔑' },
    add: { title: '2. Belge Ekleme (Add / Encrypt)', icon: '➕' },
    search: { title: '3. Şifreli Arama (Search)', icon: '🔍' },
    delete: { title: '4. Silme / Güncelleme (Delete / Update)', icon: '🗑️' }
  };

  return (
    <div className="explorer-container">
      <div className="page-heading">
        <div>
          <h1>3 DSSE Algoritması Nasıl Çalışır?</h1>
          <p>
            Yukarıdan veya aşağıdan bir algoritma seçerek <strong>Naive HMAC</strong>, <strong>Kamara (2012)</strong> ve{' '}
            <strong>MITRA (2018)</strong> yöntemlerinin indeks yapılarını, anahtar türetmelerini ve adım adım protokol mesajlarını inceleyin.
          </p>
        </div>
        <div className="toolbar">
          <button className="secondary" disabled={Boolean(busy)} onClick={onSeedAll}>
            ⚡ 3 Yönteme Ortak 25 Belge Yükle
          </button>
          <button className="primary" onClick={onGoCompare}>
            ⇄ Canlı 3'lü Karşılaştırmaya Geç
          </button>
        </div>
      </div>

      {/* Seçili Algoritma Detay Kartı */}
      <section className="library algo-hero-card" style={{ '--algo-accent': selectedMethod.color }}>
        <div className="algo-hero-header">
          <div>
            <span className="algo-badge" style={{ background: selectedMethod.color }}>{selectedMethod.badge}</span>
            <h2>{selectedMethod.name} — {selectedMethod.shortTitle}</h2>
            <p className="algo-paper-ref">Referans: {selectedMethod.paper}</p>
          </div>
          <div className="algo-switch-pills">
            {allMethods.map(m => (
              <button
                key={m.id}
                className={'pill-btn' + (m.id === selectedMethod.id ? ' active' : '')}
                style={m.id === selectedMethod.id ? { background: m.color, borderColor: m.color, color: '#fff' } : {}}
                onClick={() => onSelectMethod(m.id)}
              >
                {m.mark} · {m.name}
              </button>
            ))}
          </div>
        </div>

        <p className="algo-description">{selectedMethod.summary}</p>

        <div className="algo-specs-grid">
          <div className="spec-box">
            <span>İndeks Veri Yapısı (PostgreSQL cs_entries)</span>
            <strong>{selectedMethod.indexStructure}</strong>
          </div>
          <div className="spec-box">
            <span>Arama Karmaşıklığı</span>
            <strong>{selectedMethod.searchComplexity}</strong>
          </div>
          <div className="spec-box">
            <span>Güncelleme / Silme Davranışı</span>
            <strong>{selectedMethod.updateComplexity}</strong>
          </div>
          <div className="spec-box">
            <span>İleri Gizlilik (Forward Privacy)</span>
            <strong className={selectedMethod.id === 'mitra-v2' ? 'safe-value' : 'warn-value'}>
              {selectedMethod.forwardPrivacy}
            </strong>
          </div>
          <div className="spec-box">
            <span>Aramada Sunucuya Belge ID Sızıntısı</span>
            <strong className={selectedMethod.id === 'kamara-2012-v1' ? 'warn-value' : 'safe-value'}>
              {selectedMethod.serverDocIdLeak}
            </strong>
          </div>
          <div className="spec-box">
            <span>Türetilen Kriptografik Anahtarlar (HKDF)</span>
            <div className="key-tags">
              {selectedMethod.keys.map((k, i) => <code key={i}>{k}</code>)}
            </div>
          </div>
        </div>

        {/* Görsel İndeks Şeması */}
        <div className="visual-architecture-box">
          <h3>{selectedMethod.name} — Kriptografik İndeks ve Depolama Mimarisi</h3>
          {selectedMethod.id === 'naive-hmac-v2' && (
            <div className="arch-diagram">
              <div className="arch-node client-node">
                <strong>Güvenilir İstemci (Port 5190)</strong>
                <code>Token = HMAC-SHA256(K_hmac, "meeting")</code>
                <small>Yerel Posting List: [Doc1, Doc7, Doc12]</small>
              </div>
              <div className="arch-arrow">➔ Tek Sabit Adres ➔</div>
              <div className="arch-node server-node">
                <strong>PostgreSQL (dsse.cs_entries)</strong>
                <code>Address: 0x9F4A...2C (32B HMAC)</code>
                <code>Value: AES-256-GCM(Nonce, [Doc1, Doc7, Doc12], Tag)</code>
              </div>
              <div className="arch-arrow">➔ Çözülen ID ile İndir ➔</div>
              <div className="arch-node storage-node">
                <strong>MinIO (dsse-documents)</strong>
                <code>{`{Dataset}/{Scheme}/{Gen}/{DocId}/{Rev}.json`}</code>
                <small>AES-256-GCM Şifreli Belge</small>
              </div>
            </div>
          )}

          {selectedMethod.id === 'kamara-2012-v1' && (
            <div className="arch-diagram">
              <div className="arch-node client-node">
                <strong>Güvenilir İstemci (Port 5190)</strong>
                <code>SrchToken = (F_K1(w), G_K2(w), P_K3(w))</code>
                <code>DelToken = (F_K1(f), G_K2(f), P_K3(f), id(f))</code>
              </div>
              <div className="arch-arrow">➔ Zincir Yürüyüşü / XOR ➔</div>
              <div className="arch-node server-node">
                <strong>PostgreSQL (Ts, Td, As, Ad, Ts[free])</strong>
                <code>Ts[F(w)] ⊕ G(w) ➔ As[i] = (DocId, nextAs) ⊕ H1(P(w), r)</code>
                <code>Td[F(f)] ⊕ G(f) ➔ Ad[i] = (6 işaretçi + F(w)) ⊕ H2(P(f), r')</code>
                <small>16.384 Hücre Çifti + Ts[free] Boş Hücre Havuzu</small>
              </div>
              <div className="arch-arrow">➔ Eşleşen DocId'ler ➔</div>
              <div className="arch-node storage-node">
                <strong>MinIO (dsse-documents)</strong>
                <code>Sunucu arama anında DocId'leri görür</code>
                <small>Belge metni AES-256-GCM ile şifrelidir</small>
              </div>
            </div>
          )}

          {selectedMethod.id === 'mitra-v2' && (
            <div className="arch-diagram">
              <div className="arch-node client-node">
                <strong>Güvenilir İstemci (Port 5190)</strong>
                <code>FileCnt["meeting"] = 3 (1 Add, 1 Del, 1 Add)</code>
                <code>Addresses = [PRF(w,1), PRF(w,2), PRF(w,3)]</code>
              </div>
              <div className="arch-arrow">➔ İlişkisiz PRF Adresleri ➔</div>
              <div className="arch-node server-node">
                <strong>PostgreSQL (Opak cs_entries)</strong>
                <code>T[Addr(w, c)] = (DocId || Op) ⊕ G_K2(w, c)</code>
                <small>Sunucu hangi kaydın ADD veya DELETE olduğunu bilemez!</small>
              </div>
              <div className="arch-arrow">➔ Opak BlobId ➔</div>
              <div className="arch-node storage-node">
                <strong>MinIO (Opaque Blobs)</strong>
                <code>BlobId (DocId ile ilişkisiz rastgele GUID)</code>
                <small>Tam Forward Privacy & Gizli Erişim</small>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Adım Adım Protokol Simülatörü (Setup, Add, Search, Delete) */}
      <section className="library protocol-simulator">
        <div className="simulator-header">
          <div>
            <h2>Adım Adım İşlem Akışı (İstemci ↔ Protokol ↔ Sunucu)</h2>
            <p>Bir işlem seçerek güvenilir istemcinin ne hesapladığını, ağdan ne geçtiğini ve sunucunun ne yaptığını inceleyin.</p>
          </div>
          <label className="verify" style={{ margin: 0 }}>
            <input type="checkbox" checked={compareAllOps} onChange={e => setCompareAllOps(e.target.checked)} />
            3 Algoritmayı Bu İşlem İçin Alt Alta Karşılaştır
          </label>
        </div>

        <div className="op-tabs">
          {Object.entries(opLabels).map(([key, info]) => (
            <button
              key={key}
              className={'op-tab' + (activeOp === key ? ' active' : '')}
              onClick={() => setActiveOp(key)}
            >
              <span>{info.icon}</span> {info.title}
            </button>
          ))}
        </div>

        <div className="op-steps-wrapper">
          {(compareAllOps ? allMethods : [selectedMethod]).map(m => {
            const step = m.steps[activeOp];
            return (
              <div key={m.id} className="op-flow-row" style={{ '--algo-accent': m.color }}>
                <div className="op-flow-method-badge" style={{ background: m.color }}>
                  <span>{m.mark}</span>
                  <strong>{m.name}</strong>
                </div>
                <div className="op-flow-cards">
                  <div className="flow-step-card client-step">
                    <div className="step-tag">1. Güvenilir İstemci (127.0.0.1:5190)</div>
                    <p>{step.client}</p>
                  </div>
                  <div className="flow-step-card wire-step">
                    <div className="step-tag">2. Ağdaki Protokol Mesajı (HTTP / JSON Wire)</div>
                    <code>{step.wire}</code>
                  </div>
                  <div className="flow-step-card server-step">
                    <div className="step-tag">3. Güvenilmeyen Sunucu (127.0.0.1:5180)</div>
                    <p>{step.server}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="explorer-footer-cta">
          <button className="secondary" onClick={onGoSearch}>
            🔍 {selectedMethod.name} ile Canlı Arama Yap
          </button>
          <button className="secondary" onClick={onGoServer}>
            🛡️ Sunucu Sızıntı Görünümünü Aç
          </button>
          <button className="primary" onClick={onGoCompare}>
            📊 3 Algoritmayı Yan Yana Test Et
          </button>
        </div>
      </section>
    </div>
  );
}

/* ============================================================================
 * 4. ÜÇ ALGORİTMA KARŞILAŞTIRMASI VE DOĞRULAMA LABORATUVARI
 * ============================================================================ */
function ComparisonView({ query, setQuery, busy, result, overview, onSubmit, onSeedAll, onSelectSchemeAndInspect }) {
  const maxIndexBytes = Math.max(
    1,
    ...(overview?.schemes?.map(s => s.status?.indexBytes || 0) ?? [1])
  );
  const maxElapsedMs = Math.max(
    1,
    ...(result?.rows?.map(r => r.elapsedMs || 0) ?? [1])
  );

  return (
    <div className="comparison-container">
      <div className="page-heading">
        <div>
          <h1>3 Algoritma Yan Yana Karşılaştırma & Doğrulama</h1>
          <p>
            <strong>Naive HMAC</strong>, <strong>Kamara (2012)</strong> ve <strong>MITRA (2018)</strong> algoritmalarını aynı veri kümesi ve aynı anahtar kelime üzerinde çalıştırarak doğruluk, hız, indeks boyutu ve sunucu sızıntısını kıyaslayın.
          </p>
        </div>
        <div className="toolbar">
          <button className="secondary" disabled={Boolean(busy)} onClick={onSeedAll}>
            ⚡ 3 Yönteme Ortak 25 Belge Eşitle
          </button>
        </div>
      </div>

      {/* Canlı Depolama ve İndeks Boyutu Karşılaştırması */}
      <section className="library comparison-section">
        <div className="library-head">
          <div>
            <h2>Bölüm A — Canlı İndeks Boyutu ve Depolama Maliyeti Kıyaslaması</h2>
            <p>PostgreSQL <code>dsse.cs_entries</code> tablosunda her yöntemin şu an kapladığı şifreli indeks alanı ve kayıt sayısı.</p>
          </div>
        </div>
        <div className="storage-compare-grid">
          {methods.map(m => {
            const stat = overview?.schemes?.find(s => s.scheme === m.id);
            const indexBytes = stat?.status?.indexBytes || 0;
            const pct = Math.max(4, Math.round((indexBytes / maxIndexBytes) * 100));
            return (
              <div key={m.id} className="storage-card" style={{ '--algo-color': m.color }}>
                <div className="storage-card-head">
                  <span className="algo-strip-mark" style={{ background: m.color }}>{m.mark}</span>
                  <div>
                    <strong>{m.name}</strong>
                    <small>{m.shortTitle}</small>
                  </div>
                </div>
                <div className="storage-stat-list">
                  <div><span>Canlı Belge Sayısı</span><strong>{stat ? number.format(stat.documentCount) : '—'}</strong></div>
                  <div><span>Silinmiş Belge Kaydı</span><strong>{stat ? number.format(stat.deletedCount) : '—'}</strong></div>
                  <div><span>Benzersiz Kelime</span><strong>{stat ? number.format(stat.uniqueKeywords) : '—'}</strong></div>
                  <div><span>İndeks Hücre / Kayıt Sayısı</span><strong>{stat?.status ? number.format(stat.status.indexEntries) : '—'}</strong></div>
                  <div><span>PostgreSQL İndeks Boyutu</span><strong>{stat?.status ? size(stat.status.indexBytes) : '—'}</strong></div>
                  <div><span>Güncel Epoch</span><strong>{stat?.status ? number.format(stat.status.epoch) : '—'}</strong></div>
                </div>
                <div className="bar-track" title={`İndeks Boyutu: ${size(indexBytes)}`}>
                  <div className="bar-fill" style={{ width: `${pct}%`, background: m.color }} />
                </div>
                <small className="storage-explain">
                  {m.id === 'kamara-2012-v1'
                    ? 'Kamara, boyut gizleme (padding) için kurulumda 16.384 As/Ad hücre çiftini önceden ayırır.'
                    : m.id === 'mitra-v2'
                    ? 'MITRA, her (kelime, güncelleme) çifti için ayrı bir 32B adres + şifreli değer satırı tutar.'
                    : 'Naive HMAC, her benzersiz kelime için tek bir şifreli posting list satırı tutar.'}
                </small>
              </div>
            );
          })}
        </div>
      </section>

      {/* Canlı 3'lü Sorgu Karşılaştırma Motoru */}
      <section className="library comparison-section" aria-busy={Boolean(busy)}>
        <div className="library-head">
          <div>
            <h2>Bölüm B — Canlı 3'lü Arama, Oracle Doğruluk ve Sızıntı Testi</h2>
            <p>
              Tek bir anahtar kelimeyle üç algoritmayı aynı anda sorgulayın; açık metin referansı (Plaintext Oracle), arama süresi ve sunucunun gözlemlediği sızıntı metriklerini yan yana görün.
            </p>
          </div>
        </div>

        <form className="search standalone-search" onSubmit={e => onSubmit(e)}>
          <div className="search-field">
            <span className="search-icon" aria-hidden="true" />
            <input
              aria-label="Karşılaştırma kelimesi"
              placeholder="Karşılaştırılacak kelime, örn. meeting, energy, contract"
              value={query}
              maxLength={200}
              onChange={event => setQuery(event.target.value)}
              disabled={Boolean(busy)}
              required
            />
          </div>
          <button className="primary" disabled={Boolean(busy || !query.trim())}>
            🚀 3 Algoritmayı Aynı Anda Çalıştır ve Kıyasla
          </button>
        </form>

        <div className="search-options-row">
          <div className="chip-group">
            <span>Örnek kıyaslama kelimeleri:</span>
            {sampleKeywords.map(kw => (
              <button
                key={kw}
                type="button"
                className={'chip' + (query === kw ? ' active' : '')}
                disabled={Boolean(busy)}
                onClick={() => onSubmit(null, kw)}
              >
                {kw}
              </button>
            ))}
          </div>
        </div>

        {busy && (
          <div className="working" role="status">
            <span className="spinner" aria-hidden="true" />
            {busy}
          </div>
        )}

        {result && (
          <div className="verification-results-box">
            <div className={'dataset-status-banner ' + (result.sameDataset ? 'ok' : 'warn')}>
              <div>
                <strong>“{result.keyword}” Sorgusu İçin 3'lü Kıyaslama Sonucu:</strong>{' '}
                {result.sameDataset
                  ? '✓ Her üç algoritmanın koleksiyonu birebir aynı belge kimlikleri ve içerik özetine (SHA-256 Fingerprint) sahip.'
                  : '⚠ Koleksiyonlar şu an farklı belgeler içeriyor! Tam karşılaştırma için "⚡ 3 Yönteme Ortak 25 Belge Eşitle" butonuna basın.'}
              </div>
              {!result.sameDataset && (
                <button className="primary" disabled={Boolean(busy)} onClick={onSeedAll}>
                  ⚡ Hemen Eşitle
                </button>
              )}
            </div>

            <div className="three-col-results">
              {result.rows.map(row => {
                const m = methods.find(item => item.id === row.scheme);
                const obs = row.observation;
                const timePct = Math.max(8, Math.round(((row.elapsedMs || 0) / maxElapsedMs) * 100));
                return (
                  <div key={row.scheme} className="compare-result-card" style={{ '--algo-color': m.color }}>
                    <div className="compare-card-top">
                      <div>
                        <span className="algo-badge" style={{ background: m.color }}>{m.name}</span>
                        <h4>{m.shortTitle}</h4>
                      </div>
                      <span className={'check ' + (row.status === 'PASS' ? 'passed' : row.status === 'FAIL' ? 'failed' : '')}>
                        {row.status === 'PASS' ? '✓ PASS (Doğrulandı)' : row.status}
                      </span>
                    </div>

                    <div className="compare-metric-rows">
                      <div className="c-row">
                        <span>Açık Metin Referansı (Oracle)</span>
                        <strong>{row.expected === null ? '—' : `${number.format(row.expected.length)} belge`}</strong>
                      </div>
                      <div className="c-row">
                        <span>Şifreli Aramadan Bulunan</span>
                        <strong>{row.actual === null ? '—' : `${number.format(row.actual.length)} belge`}</strong>
                      </div>
                      <div className="c-row">
                        <span>Şifreli Arama Süresi</span>
                        <strong>{row.elapsedMs ? `${row.elapsedMs.toFixed(2)} ms` : '—'}</strong>
                      </div>
                      <div className="bar-track small-bar">
                        <div className="bar-fill" style={{ width: `${timePct}%`, background: m.color }} />
                      </div>
                      <div className="c-row">
                        <span>Sunucudan Dönen Ham Kayıt</span>
                        <strong>{obs ? `${obs.returnedEntryCount} kayıt` : '—'}</strong>
                      </div>
                      <div className="c-row">
                        <span>Sunucuya Gönderilen Token</span>
                        <strong>
                          {obs
                            ? row.scheme === 'kamara-2012-v1'
                              ? '3 bileşen (F, G, P)'
                              : row.scheme === 'mitra-v2'
                              ? `${obs.tokenCount} geçmiş adresi`
                              : '1 sabit HMAC token'
                            : '—'}
                        </strong>
                      </div>
                      <div className="c-row">
                        <span>Dokunulan İndeks Adresi</span>
                        <strong>{obs ? `${obs.addressCount} adres` : '—'}</strong>
                      </div>
                      <div className="c-row">
                        <span>Aramada Sunucuya Sızan DocID</span>
                        <strong className={obs?.observedDocumentCount > 0 ? 'warn-value' : 'safe-value'}>
                          {obs ? (obs.observedDocumentCount > 0 ? `${obs.observedDocumentCount} Belge ID Açık!` : '0 (Gizli)') : '—'}
                        </strong>
                      </div>
                    </div>

                    <button
                      className="secondary full-width-btn"
                      onClick={() => onSelectSchemeAndInspect(row.scheme, row)}
                    >
                      🔍 {m.name} Sunucu Gözlemini İncele →
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* Bölüm C: Teorik ve Mimari Kıyaslama Matrisi */}
      <section className="library comparison-section">
        <div className="library-head">
          <div>
            <h2>Bölüm C — 3 Algoritmanın Mimari ve Güvenlik Kıyaslama Matrisi</h2>
            <p>Projedeki üç şifreli arama yönteminin kriptografik tasarım, performans ve sızıntı (leakage) karşılaştırması.</p>
          </div>
        </div>
        <div className="table-scroll">
          <table className="matrix-table">
            <thead>
              <tr>
                <th>Kıyaslama Kriteri</th>
                <th>Naive HMAC (naive-hmac-v2)</th>
                <th>Kamara 2012 (kamara-2012-v1)</th>
                <th>MITRA 2018 (mitra-v2)</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Temel İndeks Yapısı</strong></td>
                <td>Kelime başına tek AES-GCM şifreli Posting List</td>
                <td>Şifreli Arama Zinciri (As/Ts) + Çift Yönlü Silme Dizisi (Ad/Td)</td>
                <td>Sayaç tabanlı PRF Anahtar-Değer tablosu + Opak Bloblar</td>
              </tr>
              <tr>
                <td><strong>İleri Gizlilik (Forward Privacy)</strong></td>
                <td><span className="badge-no">✗ Yok</span> (Sabit HMAC tokenı)</td>
                <td><span className="badge-no">✗ Yok</span> (AddToken F(w) deterministik)</td>
                <td><span className="badge-yes">✓ Var</span> (Her eklemede yeni sayaç adresi)</td>
              </tr>
              <tr>
                <td><strong>File-Injection Saldırı Direnci</strong></td>
                <td>Düşük (Enjekte edilen belgedeki tokenlar eşleşir)</td>
                <td>Düşük (F(w) üzerinden geçmiş/gelecek sorgular bağlanır)</td>
                <td>Yüksek (Enjeksiyon öncesi sorgular yeni kayıtlarla bağlanamaz)</td>
              </tr>
              <tr>
                <td><strong>Arama Sırasında Sunucuda DocID</strong></td>
                <td><span className="badge-yes">Gizli</span> (Liste AES-GCM şifrelidir)</td>
                <td><span className="badge-warn">Açık</span> (As zinciri sunucuda açılır, DocID görülür)</td>
                <td><span className="badge-yes">Gizli</span> (Değerler XOR maskelidir, BlobId ayrıdır)</td>
              </tr>
              <tr>
                <td><strong>Silme İşlemi Mekanizması</strong></td>
                <td>İstemci listeyi indirir/günceller ve yeniden şifreler</td>
                <td>DelToken ile Ad/As işaretçileri XOR ile koparılır, Ts[free]'ye döner</td>
                <td>Sunucuya yeni bir (DocId, DELETE) geçmiş kaydı eklenir</td>
              </tr>
              <tr>
                <td><strong>Silme Sonrası Sunucu Kayıt Sayısı</strong></td>
                <td>Azalır / Liste küçülür</td>
                <td>Aktif zincir kısalır; hücre serbest havuza (Ts[free]) geçer</td>
                <td>Büyür (Aramada ADD + DELETE döner, istemci filtreler)</td>
              </tr>
              <tr>
                <td><strong>Kapasite Modeli</strong></td>
                <td>Dinamik (Sınırsız büyüme)</td>
                <td>Sabit Kapasite (Kurulumda 16.384 / 131.072 hücre çifti)</td>
                <td>Dinamik (Sınırsız büyüme)</td>
              </tr>
              <tr>
                <td><strong>İstemci Durumu (DPAPI LocalVault)</strong></td>
                <td>Anahtar + Yerel Posting List önbelleği</td>
                <td>Anahtarlar (K1..K4) + Belge sürümleri</td>
                <td>Anahtarlar + Kelime başına sayaç haritası (FileCnt[w])</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

/* ============================================================================
 * 5. SUNUCU GÖRÜNÜMÜ & SIZINTI ANALİZİ ("SUNUCU TARAFINDA NE GÖSTERMELİYİZ?")
 * ============================================================================ */
function ServerView({ method, allMethods, onSelectMethod, search, leakageEvents, overview, onSearch, onRefreshLeakage, busy }) {
  const [filterScheme, setFilterScheme] = useState('ALL');
  const observation = search?.observation;
  const searchMethod = methods.find(item => item.id === (search?.scheme || method.id)) || method;

  const entryLabel = searchMethod.id === 'naive-hmac-v2'
    ? 'Şifreli Posting List Paketi'
    : searchMethod.id === 'kamara-2012-v1'
    ? 'Zincirden Açılan Eşleşen Belge Kimlikleri'
    : 'Şifreli Güncelleme Geçmişi Kayıtları (ADD + DELETE)';

  const tokenLabel = searchMethod.id === 'mitra-v2'
    ? 'İstenen PRF Geçmiş Adresleri [Addr(w, 1)..Addr(w, c)]'
    : searchMethod.id === 'kamara-2012-v1'
    ? 'Kamara Arama Token Bileşenleri: F_K1(w), G_K2(w), P_K3(w)'
    : 'Deterministik HMAC-SHA256 Arama Tokenı';

  const filteredEvents = leakageEvents.filter(ev => filterScheme === 'ALL' || ev.schemeId === filterScheme);

  return (
    <div className="server-view-container">
      <div className="page-heading">
        <div>
          <h1>Sunucu Görünümü & Sızıntı (Leakage) Denetçisi</h1>
          <p>
            Güvenilmeyen depolama sunucusunun (<code>127.0.0.1:5180</code>) gerçekte <strong>ne gördüğünü</strong>,{' '}
            <strong>neyi göremediğini</strong> ve 3 algoritmanın sunucu tarafında bıraktığı kriptografik izleri karşılaştırın.
          </p>
        </div>
        <div className="toolbar">
          <button className="secondary" disabled={Boolean(busy)} onClick={onRefreshLeakage}>
            ↻ Sunucu Günlüğünü Yenile
          </button>
          <button className="primary" onClick={onSearch}>
            🔍 Yeni Şifreli Arama Yap
          </button>
        </div>
      </div>

      {/* Sunucu Tarafında Ne Göstermemiz Gerekiyor? — Rehber Kartları */}
      <section className="library server-guide-box">
        <div className="library-head">
          <div>
            <h2>📌 Sunucu Tarafında Neleri Göstermemiz Gerekiyor? (DSSE Sunum & Değerlendirme Rehberi)</h2>
            <p>
              Bir DSSE (Dynamic Searchable Symmetric Encryption) sisteminde sunucu ekranı, sunucunun <strong>"Honest-but-Curious" (Dürüst ama Meraklı)</strong> modelde ne öğrendiğini kanıtlamak için şu 4 kritik noktayı göstermelidir:
            </p>
          </div>
        </div>
        <div className="guide-cards-grid">
          <div className="guide-card">
            <span className="guide-num">1</span>
            <h4>Gizlenen Veriler (Zero Plaintext)</h4>
            <p>
              Sunucu aranan kelimenin açık metnini (örn. <code>"meeting"</code>), belge içeriklerini ve <code>K1..K4</code> anahtarlarını <strong>asla görmez</strong>. Yalnızca 32 baytlık pseudorandom diziler ve AES-GCM şifreli bloklar görür.
            </p>
          </div>
          <div className="guide-card">
            <span className="guide-num">2</span>
            <h4>Arama Örüntüsü (Search Pattern)</h4>
            <p>
              Aynı kelime iki kez arandığında <strong>Naive HMAC</strong> ve <strong>Kamara</strong> birebir aynı token'ı gönderir (sunucu tekrar arandığını anlar). <strong>MITRA</strong> ise yeni ekleme yapıldıkça listeye yeni PRF adresleri ekler.
            </p>
          </div>
          <div className="guide-card">
            <span className="guide-num">3</span>
            <h4>Erişim Örüntüsü (Belge ID Sızıntısı)</h4>
            <p>
              Arama sırasında <strong>Kamara</strong> sunucuda <code>As</code> zincirini açtığı için eşleşen <code>DocumentId</code>'leri doğrudan görür. <strong>Naive HMAC</strong> ve <strong>MITRA</strong> ise indeks aramasında sunucuya <code>DocumentId</code> sızdırmaz (<code>0</code>).
            </p>
          </div>
          <div className="guide-card">
            <span className="guide-num">4</span>
            <h4>Silme ve İleri Gizlilik Farkı</h4>
            <p>
              Bir belge eklendikten sonra silindiğinde, <strong>MITRA</strong> sunucudan <code>2</code> geçmiş kaydı (ADD + DELETE) döndürür ama istemci bunu <code>0</code> canlı belgeye indirger. <strong>Kamara</strong> ise düğümü XOR ile koparıp <code>Ts[free]</code>'ye taşır.
            </p>
          </div>
        </div>
      </section>

      {/* İstemci vs. Sunucu Canlı Bakış Karşılaştırması */}
      {!search ? (
        <section className="library empty">
          <span className="empty-icon" aria-hidden="true">🛡️</span>
          <h2>Canlı Arama Gözlemi İçin Bir Sorgu Çalıştırın</h2>
          <p>
            İstemci ve Sunucu perspektifini yan yana görmek için Şifreli Arama sekmesinden bir kelime aratın (veya aşağıdaki canlı sunucu sızıntı günlüğünü inceleyin).
          </p>
          <button className="primary" onClick={onSearch}>Şifreli Aramaya Git</button>
        </section>
      ) : (
        <div className="trust-grid">
          <section className="library trust-panel client-perspective">
            <div className="panel-badge safe-badge">GÜVENİLİR TARAF (TRUSTED CLIENT · PORT 5190)</div>
            <h2>İstemcinin Bildiği & Çözdüğü Gerçek Veriler</h2>
            <p>DPAPI anahtar kasası ve AES-256-GCM şifre çözme yalnız bu katmanda çalışır.</p>
            <dl>
              <dt>Seçili Algoritma</dt>
              <dd><strong style={{ color: searchMethod.color }}>{searchMethod.name}</strong> ({search.scheme})</dd>
              <dt>Açık Arama Kelimesi</dt>
              <dd><code className="highlight-plain">"{search.keyword}"</code> (Sunucuya gönderilmez)</dd>
              <dt>İstemci Canlı Eşleşme</dt>
              <dd><strong>{number.format(search.documents.length)} canlı belge</strong></dd>
              <dt>Plaintext Oracle Kontrolü</dt>
              <dd>
                {search.oracle ? (
                  <span className={search.oracle.passed ? 'check passed' : 'check failed'}>
                    {search.oracle.passed ? 'PASS (%100 Doğru)' : 'FAIL'}
                  </span>
                ) : 'Çalıştırılmadı'}
              </dd>
              <dt>Arama Süresi</dt>
              <dd>{search.elapsedMs.toFixed(2)} ms</dd>
            </dl>

            {search.scheme === 'mitra-v2' && observation && observation.returnedEntryCount > search.documents.length && (
              <div className="mitra-history-callout">
                <strong>💡 MITRA Silme Filtrelemesi Tespit Edildi:</strong> Sunucu bu kelime için{' '}
                <strong>{observation.returnedEntryCount}</strong> adet geçmiş kaydı (ADD + DELETE) döndürdü; istemci bunları kronolojik olarak çözüp silinenleri eleyerek{' '}
                <strong>{search.documents.length}</strong> canlı belge buldu!
              </div>
            )}

            <h3>İstemcide Çözülen Eşleşen Belgeler</h3>
            {search.documents.length ? (
              <ul className="observation-list">
                {search.documents.slice(0, 8).map(doc => (
                  <li key={doc.documentId}>
                    <strong>{doc.name} (v{doc.revision})</strong>
                    <code>DocId: {doc.documentId}</code>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted-note">Canlı eşleşen belge yok.</p>
            )}
          </section>

          <section className="library trust-panel server-perspective">
            <div className="panel-badge warn-badge">GÜVENİLMEYEN TARAF (UNTRUSTED SERVER · PORT 5180)</div>
            <h2>Sunucunun Gözlemlediği Ham Protokol Verisi</h2>
            <p>Sunucu aranan kelimenin <code>"{search.keyword}"</code> olduğunu bilmez; yalnızca aşağıdaki bayt dizilerini görür:</p>
            {observation ? (
              <>
                <dl>
                  <dt>Arama İşlem Kimliği (SearchId)</dt>
                  <dd><code>{observation.searchId}</code></dd>
                  <dt>Döndürülen {entryLabel}</dt>
                  <dd><strong>{number.format(observation.returnedEntryCount)} kayıt</strong></dd>
                  <dt>Gözlenen Token Bileşeni</dt>
                  <dd><strong>{number.format(observation.tokenCount)} adet</strong></dd>
                  <dt>Erişilen İndeks Adresi (cs_entries)</dt>
                  <dd><strong>{number.format(observation.addressCount)} adres</strong></dd>
                  <dt>Sunucuya Sızan Belge Kimliği (DocID)</dt>
                  <dd>
                    <strong className={observation.observedDocumentCount > 0 ? 'warn-value' : 'safe-value'}>
                      {observation.observedDocumentCount > 0
                        ? `${observation.observedDocumentCount} Belge ID Sunucu Tarafından Görüldü!`
                        : '0 (Sunucu hangi belgelerin eşleştiğini göremedi)'}
                    </strong>
                  </dd>
                </dl>

                <ObservationSamples
                  label={tokenLabel}
                  values={observation.tokenSamples}
                  count={observation.tokenCount}
                  sublabels={search.scheme === 'kamara-2012-v1' ? ['F_K1(w) — Ts Tablo Adresi PRF', 'G_K2(w) — Baş İşaretçi Maskesi', 'P_K3(w) — As Zinciri H1 Maske Anahtarı'] : null}
                />
                <ObservationSamples
                  label="PostgreSQL dsse.cs_entries İçinde Erişilen Opak Adresler (Hex)"
                  values={observation.addressSamples}
                  count={observation.addressCount}
                />
                <ObservationSamples
                  label="Arama Sırasında Sunucunun Açıkça Gördüğü Belge Kimlikleri (DocumentId)"
                  values={observation.documentIdSamples}
                  count={observation.observedDocumentCount}
                  emptyText={
                    search.scheme === 'kamara-2012-v1'
                      ? 'Bu aramada eşleşen belge olmadığı için DocumentId açığa çıkmadı.'
                      : `${searchMethod.name} algoritmasında indeks araması sırasında sunucu DocumentId göremez (Şifreli/XOR maskeli).`
                  }
                />
              </>
            ) : (
              <p className="alert">Sunucu gözlemi alınamadı. Depolama sunucusunun Development modunda çalıştığından emin olun.</p>
            )}
          </section>
        </div>
      )}

      {/* Canlı Sunucu Sızıntı Günlüğü (tmp/server-leakage.jsonl) */}
      <section className="library leakage-log-section">
        <div className="library-head">
          <div>
            <h2>Canlı Sunucu Gözlem & Sızıntı Günlüğü (<code>tmp/server-leakage.jsonl</code>)</h2>
            <p>
              Depolama sunucusunun (<code>5180</code>) kendisine gelen her <code>search</code>, <code>add</code>, <code>update</code> ve{' '}
              <code>delete</code> isteğinde kaydettiği gerçek ağ boyutu, süre ve erişim izleri.
            </p>
          </div>
          <div className="toolbar">
            <select
              className="scheme-filter-select"
              value={filterScheme}
              onChange={e => setFilterScheme(e.target.value)}
              aria-label="Algoritmaya göre filtrele"
            >
              <option value="ALL">Tüm Algoritmalar ({leakageEvents.length})</option>
              {allMethods.map(m => (
                <option key={m.id} value={m.id}>{m.name} ({m.id})</option>
              ))}
            </select>
          </div>
        </div>

        {filteredEvents.length > 0 ? (
          <div className="table-scroll">
            <table className="leakage-table">
              <thead>
                <tr>
                  <th>Algoritma</th>
                  <th>İşlem</th>
                  <th>Epoch</th>
                  <th>İstek / Yanıt Boyutu</th>
                  <th>Sunucu Süresi</th>
                  <th>Gözlenen Token / Adres</th>
                  <th>Dönen Kayıt</th>
                  <th>Sızan DocID</th>
                  <th>Örnek Token / Adres (Hex)</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.slice(0, 20).map(ev => {
                  const m = allMethods.find(x => x.id === ev.schemeId);
                  return (
                    <tr key={ev.eventId}>
                      <td>
                        <span className="algo-mini-pill" style={{ background: m?.color || '#475569' }}>
                          {m ? m.name : ev.schemeId}
                        </span>
                      </td>
                      <td>
                        <span className={'op-pill op-' + ev.operation}>{ev.operation.toUpperCase()}</span>
                      </td>
                      <td>v{ev.epoch}</td>
                      <td>{size(ev.requestBytes)} / {size(ev.responseBytes)}</td>
                      <td>{(ev.elapsedMicroseconds / 1000).toFixed(2)} ms</td>
                      <td>{ev.tokenCount} token · {ev.addressCount} adres</td>
                      <td>{ev.returnedEntryCount}</td>
                      <td>
                        <span className={ev.observedDocumentCount > 0 ? 'warn-value' : 'safe-value'}>
                          {ev.observedDocumentCount}
                        </span>
                      </td>
                      <td>
                        <code className="hex-preview">
                          {ev.tokenSamples?.[0]
                            ? ev.tokenSamples[0].slice(0, 24) + '…'
                            : ev.addressSamples?.[0]
                            ? ev.addressSamples[0].slice(0, 24) + '…'
                            : '—'}
                        </code>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty">
            <p>Henüz kaydedilmiş bir sunucu sızıntı olayı yok. Bir belge ekleyin veya arama yapın.</p>
          </div>
        )}
      </section>
    </div>
  );
}

function ObservationSamples({ label, values, count, sublabels, emptyText }) {
  return (
    <details className="samples" open>
      <summary>{label} · <strong>{number.format(count)}</strong></summary>
      {values && values.length ? (
        <ul className="observation-list">
          {values.map((value, index) => (
            <li key={index}>
              {sublabels && sublabels[index] && <small className="token-sublabel">{sublabels[index]}</small>}
              <code>{value}</code>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted-note">{emptyText || 'Bu aramada gözlemlenen değer yok.'}</p>
      )}
      {count > (values?.length || 0) && <p className="muted-note">Toplam {number.format(count)} değerden ilk {values.length} tanesi gösteriliyor.</p>}
    </details>
  );
}

function Modal({ title, children, onClose, busy }) {
  const ref = useRef(null);
  useEffect(() => {
    const previous = document.activeElement;
    const dialog = ref.current;
    dialog.showModal();
    return () => { dialog.close(); previous?.focus(); };
  }, []);
  return (
    <dialog ref={ref} className="modal" aria-label={title} onCancel={event => { event.preventDefault(); if (!busy) onClose(); }}>
      <div className="modal-heading">
        <h2>{title}</h2>
        <button className="quiet close" aria-label="Pencereyi kapat" disabled={Boolean(busy)} onClick={onClose}>×</button>
      </div>
      {children}
    </dialog>
  );
}

createRoot(document.getElementById('root')).render(<App />);
