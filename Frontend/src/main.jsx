import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const methods = [
  { id: 'naive-hmac-v2', name: 'Naive HMAC', detail: 'Encrypted posting lists', mark: 'H' },
  { id: 'kamara-2012-v1', name: 'Kamara', detail: 'Linked search and deletion indexes', mark: 'K' },
  { id: 'mitra-v2', name: 'Mitra', detail: 'Counter-based update history', mark: 'M' },
];
const sections = { documents: 'Documents', search: 'Encrypted Search', server: 'Server View', verification: 'Verification' };
const maxBytes = 256 * 1024;
const pageSize = 12;
const number = new Intl.NumberFormat('en-US');
const size = bytes => bytes < 1024 ? bytes + ' B' : bytes < 1048576
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
    throw new Error(result?.message || 'The workspace service could not complete the request. Check the local services and retry.');
  return result;
}

function App() {
  const [section, setSection] = useState('documents');
  const [scheme, setScheme] = useState(methods[0].id);
  const [collection, setCollection] = useState(null);
  const [search, setSearch] = useState(null);
  const [verification, setVerification] = useState(null);
  const [query, setQuery] = useState('');
  const [verify, setVerify] = useState(false);
  const [page, setPage] = useState(0);
  const [busy, setBusy] = useState('Loading collection…');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [editor, setEditor] = useState(null);
  const [reader, setReader] = useState(null);
  const [deleting, setDeleting] = useState(null);
  const fileInput = useRef(null);
  const method = methods.find(m => m.id === scheme);

  async function refresh() {
    setCollection(await api(scheme, 'documents'));
    setSearch(null);
    setVerification(null);
    setPage(0);
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
    setBusy('Loading collection…');
    setCollection(null);
    setSearch(null);
    setPage(0);
    setError('');
    setNotice('');
    api(scheme, 'documents')
      .then(data => { if (active) setCollection(data); })
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
    await perform('Preparing files…', async () => {
      if (files.length > 20) throw new Error('Select up to 20 text files per upload.');
      const prepared = [];
      for (const file of files) {
        if (!/\.(txt|md|csv|json|jsonl|eml)$/i.test(file.name) || file.size > maxBytes)
          throw new Error(file.name + ' must be a supported text file up to 256 KiB.');
        let text;
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer()); }
        catch { throw new Error(file.name + ' is not valid UTF-8 text.'); }
        if (!text.trim()) throw new Error(file.name + ' is empty.');
        prepared.push({ documentId: crypto.randomUUID(), revision: 0, name: file.name.slice(0, 180), text });
      }
      let uploaded = 0;
      try {
        for (const doc of prepared) {
          setBusy('Encrypting file ' + (uploaded + 1) + ' of ' + prepared.length + '…');
          await api(scheme, 'documents', 'POST', doc);
          uploaded++;
        }
      } catch (failure) {
        await refresh().catch(() => {});
        throw new Error(uploaded + ' files confirmed. ' + failure.message);
      }
      await refresh();
      setNotice(number.format(uploaded) + (uploaded === 1 ? ' file uploaded.' : ' files uploaded.'));
    });
  }
  function importEnron() {
    return perform('Importing Enron documents…', async () => {
      const result = await api(scheme, 'import-enron', 'POST');
      await refresh();
      setNotice(result.imported ? number.format(result.imported) + (result.imported === 1 ? ' Enron document imported.' : ' Enron documents imported.')
        : 'This collection already contains the Enron import.');
    });
  }
  function find(event) {
    event.preventDefault();
    return perform(verify ? 'Searching and checking results…' : 'Searching encrypted index…', async () => {
      const keyword = query.trim();
      const data = await api(scheme, 'search', 'POST', { keyword, verify, inspect: true });
      setSearch({ ...data, keyword, scheme });
      setPage(0);
    });
  }
  function runVerification(event) {
    event.preventDefault();
    setVerification(null);
    return perform('Comparing the three collections…', async () =>
      setVerification(await api(null, 'verification', 'POST', { keyword: query.trim() })));
  }
  function openDocument(doc, edit = false) {
    return perform('Decrypting document…', async () => {
      const data = await api(scheme, 'documents/' + doc.documentId);
      if (edit) setEditor({ ...data.document, text: data.text });
      else setReader(data);
    });
  }
  function save(event) {
    event.preventDefault();
    return perform('Encrypting and saving…', async () => {
      const path = editor.revision ? 'documents/' + editor.documentId : 'documents';
      await api(scheme, path, editor.revision ? 'PUT' : 'POST', editor);
      setEditor(null);
      await refresh();
      setNotice('Document saved.');
    });
  }
  function remove() {
    return perform('Deleting document…', async () => {
      await api(scheme, 'documents/' + deleting.documentId, 'DELETE', { revision: deleting.revision });
      setDeleting(null);
      await refresh();
      setNotice('Document deleted.');
    });
  }

  const searching = section === 'search';
  const rows = searching ? search?.documents ?? [] : collection?.documents ?? [];
  const indexBytes = collection?.status?.indexBytes;
  const documentCount = collection?.documents.length;
  const visible = rows.slice(page * pageSize, (page + 1) * pageSize);
  const unavailable = Boolean(busy || !collection);
  const modalOpen = Boolean(editor || reader || deleting);
  const bytes = editor ? textBytes(editor.text) : 0;

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-icon" aria-hidden="true">◈</span><span>CipherSearch<small>Encrypted Document Search</small></span></div>
      <nav className="sections" aria-label="Workspace sections">
        {Object.entries(sections).map(([id, label]) => <button key={id} className="section-link"
          aria-current={section === id ? 'page' : undefined} disabled={Boolean(busy || modalOpen)}
          onClick={() => { setSection(id); setPage(0); setError(''); }}>{label}</button>)}
      </nav>
      <nav aria-label="Search methods">
        <h2>Search methods</h2>
        {methods.map(item => <button key={item.id} className="method" aria-pressed={scheme === item.id}
          disabled={Boolean(busy || modalOpen)} onClick={() => setScheme(item.id)}>
          <span className="method-mark" aria-hidden="true">{item.mark}</span>
          <span><strong>{item.name}</strong><small>{item.detail}</small></span>
          <span className="method-indicator" aria-hidden="true" />
        </button>)}
      </nav>
      <div className="sidebar-note"><span className="dot" aria-hidden="true" /> Local workspace<small>Each method has its own collection.</small></div>
    </aside>

    <main className="main">
      <header className="topbar">
        <span>{sections[section]} <span className="breadcrumb-separator" aria-hidden="true">/</span> <strong>{section === 'verification' ? 'All methods' : method.name}</strong></span>
        <span className="local-pill"><span className="dot" aria-hidden="true" /> Local client</span>
      </header>
      <div className="content">
        <div className="page-heading">
          <div><h1>{searching ? 'Encrypted Document Search' : sections[section]}</h1>
            <p>{section === 'documents' ? 'Manage the ' + method.name + ' collection.' :
              searching ? 'Search the ' + method.name + ' encrypted index.' :
              section === 'server' ? 'Inspect what the client and storage server observed for one search.' :
              'Compare encrypted results with the plaintext reference across all three methods.'}</p></div>
          {section === 'documents' && <button className="primary" disabled={unavailable} onClick={newDocument}><span aria-hidden="true">＋</span> New document</button>}
        </div>

        {section === 'documents' && <div className="metrics">
          <div><span>Active method</span><strong>{method.name}</strong><small>{method.detail}</small></div>
          <div><span>Documents</span><strong>{documentCount === undefined ? '—' : number.format(documentCount)}</strong><small>In this collection</small></div>
          <div><span>Index size</span><strong>{indexBytes === undefined ? '—' : size(indexBytes)}</strong><small>Stored index addresses and values</small></div>
        </div>}

        {error && !modalOpen && <div className="alert error" role="alert">{error}</div>}
        {notice && <div className="alert success" role="status">{notice}</div>}

        {section === 'server' && <ServerView search={search} onSearch={() => setSection('search')} />}
        {section === 'verification' && <VerificationView query={query} setQuery={setQuery} busy={busy}
          result={verification} onSubmit={runVerification} />}
        {(section === 'documents' || searching) && <section className="library" aria-label={sections[section]} aria-busy={Boolean(busy)}>
          {!searching && <div className="library-head">
            <div><h2>Document collection</h2><p>Upload UTF-8 text files up to 256 KiB each.</p></div>
            <div className="toolbar">
              <button className="secondary" disabled={unavailable} onClick={() => fileInput.current.click()}>Upload files</button>
              <button className="secondary" disabled={Boolean(busy)} onClick={importEnron}>Import Enron 1,000</button>
              <input ref={fileInput} type="file" hidden multiple accept=".txt,.md,.csv,.json,.jsonl,.eml" onChange={event => {
                const files = Array.from(event.currentTarget.files);
                event.currentTarget.value = '';
                upload(files);
              }} />
            </div>
          </div>}
          {searching && <><form className="search standalone-search" onSubmit={find}>
            <div className="search-field"><span className="search-icon" aria-hidden="true" />
              <input aria-label="Search keyword" placeholder="Keyword, e.g. meeting" value={query}
                onChange={event => setQuery(event.target.value)} maxLength={200} disabled={unavailable} required />
            </div>
            <button className="primary" disabled={unavailable || !query.trim()}>Search</button>
          </form>
          <label className="verify"><input type="checkbox" checked={verify} disabled={unavailable}
            onChange={event => setVerify(event.target.checked)} /> Verify results against a plaintext scan</label></>}

          <div className="collection-head">
            <div><h3>{searching ? 'Search results' : 'All documents'} <span className="count">{number.format(rows.length)}</span></h3>
              {searching && search && <p>“{search.keyword}” <span aria-hidden="true">·</span> {search.elapsedMs.toFixed(1)} ms search
                {search.oracle && <span className={search.oracle.passed ? 'check passed' : 'check failed'}>
                  {search.oracle.passed ? 'Verified' : 'Verification mismatch · expected ' + number.format(search.oracle.expectedCount)}
                </span>}</p>}
            </div>
            <div className="toolbar">
              {searching && search && <button className="quiet" disabled={Boolean(busy)} onClick={() => setSection('server')}>Inspect server view</button>}
              {searching && (query || search) && <button className="quiet" disabled={Boolean(busy)} onClick={() => { setSearch(null); setQuery(''); setPage(0); }}>Clear search</button>}
              {!searching && <button className="quiet" disabled={Boolean(busy)} onClick={() => perform('Refreshing collection…', refresh)}>Refresh</button>}
            </div>
          </div>
          {busy && <div className="working" role="status"><span className="spinner" aria-hidden="true" />{busy}</div>}
          {visible.length > 0 ? <div className="table-scroll"><table>
            <thead><tr><th scope="col">Document</th><th scope="col">Revision</th><th scope="col">Actions</th></tr></thead>
            <tbody>{visible.map(doc => <tr key={doc.documentId}>
              <td><button className="doc-name" disabled={Boolean(busy)} onClick={() => openDocument(doc)}>
                <span className="file-icon" aria-hidden="true">▤</span><span>{doc.name}<small className="document-id">{doc.documentId}</small></span>
              </button></td>
              <td><span className="revision">v{doc.revision}</span></td>
              <td><div className="row-actions"><button className="quiet" disabled={Boolean(busy)} onClick={() => openDocument(doc, true)}>Edit</button>
                <button className="quiet danger-text" disabled={Boolean(busy)} onClick={() => { setError(''); setDeleting(doc); }}>Delete</button></div></td>
            </tr>)}</tbody>
          </table></div> : !busy && <div className="empty"><span className="empty-icon" aria-hidden="true">▤</span>
            <h3>{!collection ? 'Collection unavailable' : searching ? search ? 'No matching documents' : 'Enter a keyword to search' : 'Your collection is empty'}</h3>
            <p>{!collection ? 'Check the local services, then refresh the Documents section.' : searching ? search ? 'Try another keyword.' : 'For example, search for meeting.' : 'Create a document, upload text files, or import the Enron sample.'}</p>
          </div>}
          <div className="library-footer">
            <span>{rows.length > pageSize
              ? number.format(page * pageSize + 1) + '–' + number.format(Math.min(rows.length, (page + 1) * pageSize)) + ' of ' + number.format(rows.length)
              : 'AES-256-GCM document encryption'}</span>
            {rows.length > pageSize && <div className="toolbar">
              <button className="quiet" disabled={page === 0 || Boolean(busy)} onClick={() => setPage(page - 1)}>Previous</button>
              <button className="quiet" disabled={(page + 1) * pageSize >= rows.length || Boolean(busy)} onClick={() => setPage(page + 1)}>Next</button>
            </div>}
          </div>
        </section>}
      </div>
    </main>

    {editor && <Modal title={editor.revision ? 'Edit document' : 'New document'} onClose={() => setEditor(null)} busy={busy}>
      <form onSubmit={save}>
        <label htmlFor="document-name">Document name</label>
        <input id="document-name" autoFocus required maxLength={180} value={editor.name} disabled={Boolean(busy)}
          onChange={event => setEditor({ ...editor, name: event.target.value })} placeholder="e.g. Meeting notes" />
        <label htmlFor="document-text">Document text</label>
        <textarea id="document-text" required rows={10} value={editor.text} disabled={Boolean(busy)}
          onChange={event => setEditor({ ...editor, text: event.target.value })} placeholder="Enter searchable text…" />
        <div className={'editor-meta' + (bytes > maxBytes ? ' danger-text' : '')}>{size(bytes)} / 256 KiB</div>
        {error && <p className="alert error" role="alert">{error}</p>}
        <div className="modal-actions"><button type="button" className="secondary" disabled={Boolean(busy)} onClick={() => setEditor(null)}>Cancel</button>
          <button className="primary" disabled={Boolean(busy || !editor.name.trim() || !editor.text.trim() || bytes > maxBytes)}>{busy ? 'Saving…' : 'Encrypt and save'}</button></div>
      </form>
    </Modal>}
    {reader && <Modal title={reader.document.name} onClose={() => setReader(null)}>
      <div className="reader-meta"><span>Decrypted locally · {size(textBytes(reader.text))}</span><span>Revision {reader.document.revision}</span></div>
      <p className="document-id">{reader.document.documentId}</p>
      <pre className="reader">{reader.text}</pre>
      <div className="modal-actions"><button className="secondary" onClick={() => { setEditor({ ...reader.document, text: reader.text }); setReader(null); }}>Edit</button>
        <button className="primary" onClick={() => setReader(null)}>Done</button></div>
    </Modal>}
    {deleting && <Modal title="Delete document?" onClose={() => setDeleting(null)} busy={busy}>
      <p><strong>{deleting.name}</strong> will be removed from this collection and its search results.</p>
      {error && <p className="alert error" role="alert">{error}</p>}
      <div className="modal-actions"><button autoFocus className="secondary" disabled={Boolean(busy)} onClick={() => setDeleting(null)}>Cancel</button>
        <button className="danger" disabled={Boolean(busy)} onClick={remove}>{busy ? 'Deleting…' : 'Delete document'}</button></div>
    </Modal>}
  </div>;
}

function ServerView({ search, onSearch }) {
  if (!search) return <section className="library empty">
    <h2>No search to inspect</h2><p>Run an encrypted search to capture the client result and server observation.</p>
    <button className="secondary" onClick={onSearch}>Go to encrypted search</button>
  </section>;
  const method = methods.find(item => item.id === search.scheme);
  const observation = search.observation;
  const entryLabel = search.scheme === 'naive-hmac-v2' ? 'Encrypted posting lists' :
    search.scheme === 'kamara-2012-v1' ? 'Matching document IDs' : 'History records';
  const tokenLabel = search.scheme === 'mitra-v2' ? 'Requested history addresses' :
    search.scheme === 'kamara-2012-v1' ? 'Search token components (F, G, P)' : 'HMAC search token';
  return <div className="trust-grid">
    <section className="library trust-panel">
      <h2>Trusted Client</h2><p>Plaintext query and processed search results</p>
      <dl>
        <dt>Method</dt><dd>{method.name}</dd>
        <dt>Keyword</dt><dd><code>{search.keyword}</code></dd>
        <dt>Matching documents</dt><dd>{number.format(search.documents.length)}</dd>
        <dt>Plaintext verification</dt><dd>{search.oracle ? search.oracle.passed ? 'PASS' : 'FAIL' : 'Not run'}</dd>
      </dl>
      <h3>Client results</h3>
      {search.documents.length ? <ul className="observation-list">{search.documents.slice(0, 8).map(doc =>
        <li key={doc.documentId}><strong>{doc.name}</strong><code>{doc.documentId}</code></li>)}</ul> : <p>No matching documents.</p>}
      {search.documents.length > 8 && <p>Showing 8 of {number.format(search.documents.length)} matches.</p>}
    </section>
    <section className="library trust-panel">
      <h2>Untrusted Server</h2><p>Local storage service · encrypted search protocol</p>
      {observation ? <>
        <dl>
          <dt>Search ID</dt><dd><code>{observation.searchId}</code></dd>
          <dt>{entryLabel} returned</dt><dd>{number.format(observation.returnedEntryCount)}</dd>
          <dt>Index addresses observed</dt><dd>{number.format(observation.addressCount)}</dd>
        </dl>
        <ObservationSamples label={tokenLabel} values={observation.tokenSamples} count={observation.tokenCount} />
        <ObservationSamples label="Observed index addresses" values={observation.addressSamples} count={observation.addressCount} />
        <ObservationSamples label="Document IDs observed in search" values={observation.documentIdSamples} count={observation.observedDocumentCount} />
      </> : <p className="alert">Server observation unavailable. Start the storage server in Development and run the search again.</p>}
    </section>
  </div>;
}

function ObservationSamples({ label, values, count }) {
  return <details className="samples" open={label.startsWith('HMAC') || label.startsWith('Search token') || label.startsWith('Requested')}>
    <summary>{label} · {number.format(count)}</summary>
    {values.length ? <ul className="observation-list">{values.map((value, index) =>
      <li key={index}><code>{value}</code></li>)}</ul> : <p>None observed in this search.</p>}
    {count > values.length && <p>Showing {values.length} of {number.format(count)}.</p>}
  </details>;
}

function VerificationView({ query, setQuery, busy, result, onSubmit }) {
  return <section className="library verification-panel" aria-busy={Boolean(busy)}>
    <form className="search standalone-search" onSubmit={onSubmit}>
      <div className="search-field"><span className="search-icon" aria-hidden="true" />
        <input aria-label="Verification keyword" placeholder="Keyword, e.g. meeting" value={query} maxLength={200}
          onChange={event => setQuery(event.target.value)} disabled={Boolean(busy)} required />
      </div>
      <button className="primary" disabled={Boolean(busy || !query.trim())}>Run verification</button>
    </form>
    <p className="verification-note">Collections must have matching document IDs and content. Import Enron into each method to compare the same dataset.</p>
    {busy && <div className="working" role="status"><span className="spinner" aria-hidden="true" />{busy}</div>}
    {result && <>
      <div className="collection-head"><div><h3>Results for “{result.keyword}”</h3>
        <p>{result.sameDataset ? 'All three collections share the same document IDs and content.' :
          result.rows.some(row => row.status === 'Unavailable') ? 'At least one collection could not be verified.' :
            'The collections contain different documents or content.'}</p></div></div>
      <div className="table-scroll"><table>
        <thead><tr><th scope="col">Method</th><th scope="col">Expected</th><th scope="col">Actual</th><th scope="col">Status</th></tr></thead>
        <tbody>{result.rows.map(row => <tr key={row.scheme}>
          <td>{methods.find(item => item.id === row.scheme)?.name}</td>
          <td>{row.expected === null ? '—' : number.format(row.expected.length)}</td>
          <td>{row.actual === null ? '—' : number.format(row.actual.length)}</td>
          <td><span className={'check ' + (row.status === 'PASS' ? 'passed' : row.status === 'FAIL' ? 'failed' : '')}>{row.status}</span></td>
        </tr>)}</tbody>
      </table></div>
    </>}
  </section>;
}

function Modal({ title, children, onClose, busy }) {
  const ref = useRef(null);
  useEffect(() => {
    const previous = document.activeElement;
    const dialog = ref.current;
    dialog.showModal();
    return () => { dialog.close(); previous?.focus(); };
  }, []);
  return <dialog ref={ref} className="modal" aria-label={title} onCancel={event => { event.preventDefault(); if (!busy) onClose(); }}>
    <div className="modal-heading"><h2>{title}</h2><button className="quiet close" aria-label="Close dialog" disabled={Boolean(busy)} onClick={onClose}>×</button></div>
    {children}
  </dialog>;
}

createRoot(document.getElementById('root')).render(<App />);
