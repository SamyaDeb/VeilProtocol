// Placeholder for proving-based screens not yet ported in this migration pass.
// Each will become a feature folder with: a form, a Web Worker prover call
// (client/src/prover/<x>.js), an auditor-ciphertext step (RULE 4), and a signed
// Soroban submit — following the Wallet/Auditor pattern already in place.

export function ComingSoon({ screen, circuit }: { screen: string; circuit: string }) {
  return (
    <section className="veil-card">
      <h2>{screen}</h2>
      <p className="veil-muted">
        This screen is scaffolded but not yet wired in the TS/React migration.
      </p>
      <p className="veil-muted">
        Next step: port the prover for <code>{circuit}</code> into a Web Worker,
        add Merkle-path lookup, encrypt the output note to the auditor key, then
        submit the signed transaction.
      </p>
    </section>
  );
}
