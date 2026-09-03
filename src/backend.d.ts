export interface BackendReport {
  kind: 'openssl' | 'javascript'
  library: string
  /** OpenSSL version, on the native backend only. */
  openssl?: string
  /** Parameter sets the native backend can express. */
  parameterSets?: string[]
  /** Why the native backend is unavailable, on the JavaScript backend only. */
  reason?: string
}

/** Describe the backend doing the maths in this process. Reports; never switches. */
export function backend(): BackendReport

/** Whether a parameter set runs natively here, e.g. isNative('ML-DSA-65'). */
export function isNative(alg: string): boolean
