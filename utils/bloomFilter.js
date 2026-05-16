/**
 * bloomFilter.js
 * Probabilistic set membership — O(k) lookup, ~1.2 MB for 700K items.
 *
 * No false negatives. ~0.1% false positive rate (safe: flagged domains
 * fall through to the next layer for verification).
 *
 * Parameters for 700K items @ 0.1% FPR:
 *   size = 10,000,000 bits  (m = -n*ln(p) / ln(2)^2)
 *   hashCount = 10          (k = m/n * ln(2))
 */

export class BloomFilter {

  constructor(size = 10_000_000, hashCount = 10) {
    this.size      = size;
    this.hashCount = hashCount;
    // Uint8Array: raw contiguous memory, 8 bits per element → size/8 bytes total.
    // Far cheaper than a regular JS array (no per-element object overhead).
    this.bitArray  = new Uint8Array(Math.ceil(size / 8));
    this.itemCount = 0;
  }

  /**
   * djb2 hash with seed — same string + different seed = different bit position.
   * Running this k times simulates k independent hash functions.
   */
  _hash(str, seed) {
    let hash = seed;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash + str.charCodeAt(i)) | 0;
    }
    return Math.abs(hash) % this.size;
  }

  /** Returns k bit positions for a given item. */
  _getPositions(item) {
    const positions = [];
    for (let i = 0; i < this.hashCount; i++) {
      positions.push(this._hash(item, i * 0x9e3779b9));
    }
    return positions;
  }

  /** Flip bit ON at position.  byteIndex = pos/8, bitOffset = pos%8 */
  _setBit(position) {
    this.bitArray[Math.floor(position / 8)] |= (1 << (position % 8));
  }

  /** Read bit at position. Returns 0 (OFF) or non-zero (ON). */
  _getBit(position) {
    return this.bitArray[Math.floor(position / 8)] & (1 << (position % 8));
  }

  /** Add a domain — flips k bits ON. O(k) */
  add(domain) {
    for (const pos of this._getPositions(domain)) this._setBit(pos);
    this.itemCount++;
  }

  /** Bulk add — used during initialization. */
  addAll(domains) {
    for (const domain of domains) this.add(domain);
  }

  /**
   * Check membership. O(k)
   * false → definitely NOT in set.
   * true  → probably in set (~0.1% false positive rate).
   */
  has(domain) {
    for (const pos of this._getPositions(domain)) {
      if (!this._getBit(pos)) return false;
    }
    return true;
  }

  /** Wipe all bits. Used when rebuilding from storage. */
  clear() {
    this.bitArray.fill(0);
    this.itemCount = 0;
  }

  /** Current false positive probability given load. Formula: (1 - e^(-k*n/m))^k */
  get falsePositiveRate() {
    return Math.pow(1 - Math.exp(-this.hashCount * this.itemCount / this.size), this.hashCount);
  }
}
