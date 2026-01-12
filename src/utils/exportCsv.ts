export function toCsv<T extends Record<string, unknown>>(rows: T[], headers?: (keyof T)[]) {
  if (!rows.length) return '';
  const keys = headers?.length ? headers : (Object.keys(rows[0]) as (keyof T)[]);
  const esc = (v: unknown) => {
    const s = v == null ? '' : String(v);
    const needs = /[",\n\r]/.test(s);
    const body = s.replace(/"/g, '""');
    return needs ? `"${body}"` : body;
  };
  const head = keys.map(k => esc(k)).join(',');
  const lines = rows.map(r => keys.map(k => esc(r[k])).join(','));
  return [head, ...lines].join('\r\n');
}

export function downloadCsv(filename: string, csv: string) {
  const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}