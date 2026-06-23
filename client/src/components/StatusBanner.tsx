type Kind = 'info' | 'success' | 'warn' | 'error';

export function StatusBanner({ kind, children }: { kind: Kind; children: React.ReactNode }) {
  if (!children) return null;
  return <div className={`veil-banner veil-banner-${kind}`}>{children}</div>;
}
