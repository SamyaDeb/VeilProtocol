// Privacy UX helpers (THREAT_MODEL §1).
//
// Warn users about patterns that degrade anonymity — round-number amounts,
// immediate deposit→withdraw of the same value, small anonymity sets.

export interface PrivacyWarning {
  level: 'low' | 'medium' | 'high';
  message: string;
}

/**
 * Check an amount for round-number risk.
 * Rare, distinctive amounts shrink the anonymity set because on-chain observers
 * can correlate in/out notes of the same value (THREAT_MODEL §1.2).
 */
export function checkAmountPrivacy(amount: bigint): PrivacyWarning | null {
  if (amount <= 0n) return null;
  const s = amount.toString();

  // Check for round-number multiples (1000, 10000, etc.)
  if (/^[1-9]0{3,}$/.test(s)) {
    return {
      level: 'medium',
      message:
        'Round-number amounts (e.g. 1000, 10000) are distinctive and may be ' +
        'correlated by an observer. Consider using an irregular value.',
    };
  }

  // Very large single amounts
  if (amount > 1_000_000_000n) {
    return {
      level: 'low',
      message:
        'Large amounts can narrow the potential anonymity set. ' +
        'Splitting across multiple notes improves privacy.',
    };
  }

  return null;
}

/**
 * Warn if the user is about to withdraw the same amount they recently deposited.
 * This is the classic "same-amount in/out" linkage attack (THREAT_MODEL §1.1).
 */
export function checkDepositWithdrawLinkage(
  depositAmount: bigint,
  withdrawAmount: bigint,
  timeDeltaMs: number,
): PrivacyWarning | null {
  if (depositAmount !== withdrawAmount) return null;
  const minutes = timeDeltaMs / 60_000;
  if (minutes < 60) {
    return {
      level: 'high',
      message:
        `Withdrawing the same amount deposited ${Math.round(minutes)} min ago ` +
        'creates a strong linkage between your deposit and withdrawal. ' +
        'Wait for more transactions to join the pool first.',
    };
  }
  return null;
}

/**
 * Warn when the anonymity set is too small for comfortable privacy.
 */
export function checkAnonSetSize(commitmentCount: number): PrivacyWarning | null {
  if (commitmentCount < 10) {
    return {
      level: 'high',
      message: `Only ${commitmentCount} commitments in the pool — the anonymity set is very small. Your transaction is more linkable. Wait for more deposits.`,
    };
  }
  if (commitmentCount < 50) {
    return {
      level: 'medium',
      message: `${commitmentCount} commitments in the pool — anonymity set is growing but still small.`,
    };
  }
  return null;
}

/**
 * Privacy indicator text for amounts.
 * Public fields visible on-chain: the existence of a commitment and nullifier.
 * Private: amount, asset, parties, timing within a batch window.
 */
export function fieldPrivacyLabel(fieldName: string): 'public' | 'private' {
  const publicFields = new Set(['recipient', 'public_amount', 'asset_id (for oracle reads)']);
  return publicFields.has(fieldName) ? 'public' : 'private';
}
