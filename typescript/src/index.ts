/**
 * @algovoi/revocation-ref — content-addressed revocation references (commercial, unpublished).
 *
 *   revocationRef = "sha256:" + SHA-256(JCS({ prev_revocation_ref, reason, revoked_at_ms,
 *                                             revoked_ref, revoker_id }))
 *
 * A grantor revokes a delegation (or other authority) before it expires. The revocation_ref is the
 * content hash of the revocation envelope, so any tamper (target, time, reason, revoker) changes the
 * ref and is detectable offline. Revocations chain via prev_revocation_ref.
 *
 * Construction only; the revocation cascade PROOF (an action at or after revoked_at_ms acted under
 * revoked authority) is the private AlgoVoi Orchestrator. Byte-identical to algovoi-revocation-ref
 * (Python). Commercial AlgoVoi licence, not published.
 */
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

export const SHA256_PREFIX = 'sha256:' as const;
export const REASONS = ['COMPROMISE', 'SUPERSEDED', 'POLICY', 'EXPIRY', 'MANUAL'] as const;
const REF_RE = /^sha256:[0-9a-f]{64}$/;

export class RevocationRefError extends Error {}

export interface RevocationEnvelope {
  revoker_id: string;
  revoked_ref: string;
  reason: (typeof REASONS)[number];
  revoked_at_ms: number;
  prev_revocation_ref?: string;
}

function normalise(env: Record<string, unknown>) {
  const rid = env.revoker_id;
  if (typeof rid !== 'string' || rid.length === 0) throw new RevocationRefError('revoker_id must be a non-empty string');
  const rr = env.revoked_ref;
  if (typeof rr !== 'string' || !REF_RE.test(rr)) throw new RevocationRefError('revoked_ref must be a "sha256:"-prefixed 64-hex ref');
  const reason = env.reason;
  if (typeof reason !== 'string' || !REASONS.includes(reason as never)) throw new RevocationRefError(`reason must be one of ${REASONS.join(', ')}`);
  const ra = env.revoked_at_ms;
  if (typeof ra !== 'number' || !Number.isInteger(ra) || ra < 0) throw new RevocationRefError('revoked_at_ms must be a non-negative integer (integer-millisecond)');
  const prev = env.prev_revocation_ref ?? '';
  if (prev !== '' && (typeof prev !== 'string' || !REF_RE.test(prev))) throw new RevocationRefError('prev_revocation_ref must be "" or a "sha256:"-prefixed 64-hex ref');
  return { prev_revocation_ref: prev as string, reason: reason as string, revoked_at_ms: ra, revoked_ref: rr, revoker_id: rid };
}

export function revocationRef(env: Record<string, unknown>): string {
  const n = normalise(env);
  const s = canonicalize({
    prev_revocation_ref: n.prev_revocation_ref, reason: n.reason,
    revoked_at_ms: n.revoked_at_ms, revoked_ref: n.revoked_ref, revoker_id: n.revoker_id,
  });
  if (s === undefined) throw new RevocationRefError('envelope is not JCS-canonicalisable');
  return SHA256_PREFIX + createHash('sha256').update(s).digest('hex');
}

export function tamperDetected(claimedRef: string, env: Record<string, unknown>): boolean {
  try { return revocationRef(env) !== claimedRef; } catch { return true; }
}

export function verifyChain(envelopes: Array<Record<string, unknown>>): string[] {
  const refs: string[] = [];
  let prev = '';
  envelopes.forEach((env, i) => {
    if ((env.prev_revocation_ref ?? '') !== prev) throw new RevocationRefError(`chain break at link ${i}: prev_revocation_ref does not match the prior link`);
    const r = revocationRef(env);
    refs.push(r);
    prev = r;
  });
  return refs;
}
