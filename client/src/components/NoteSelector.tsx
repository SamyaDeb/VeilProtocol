import type { StoredNote } from '../types';
import { noteLeafIndex } from '../lib/notes';

interface Props {
  notes: StoredNote[];
  value: string; // commitment
  onChange: (commitment: string) => void;
  filterAsset?: string;
  placeholder?: string;
}

function shortField(s: string): string {
  const hex = BigInt(s).toString(16);
  return hex.length > 12 ? `${hex.slice(0, 10)}…` : hex;
}

export function NoteSelector({ notes, value, onChange, filterAsset, placeholder }: Props) {
  const candidates = filterAsset
    ? notes.filter((n) => !n.spent && !n.pending && n.asset_id === filterAsset)
    : notes.filter((n) => !n.spent && !n.pending);

  return (
    <select
      className="veil-select"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      <option value="">{placeholder ?? '— select a note —'}</option>
      {candidates.map((n) => (
        <option key={n.commitment} value={n.commitment}>
          {n.amount} tokens · asset {shortField(n.asset_id)} · leaf #{noteLeafIndex(n) ?? '?'}
        </option>
      ))}
    </select>
  );
}
