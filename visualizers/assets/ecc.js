/* ============================================================================
 * ecc.js — a faithful JavaScript mirror of the `ecc-rs` Rust library.
 *
 * Every function below follows the corresponding Rust function in
 *   ecc/src/finite_field.rs
 *   ecc/src/elliptic_curve.rs
 *   ecc/src/point.rs
 *   ecdsa/src/lib.rs
 * including its `assert!`s (a failing assert throws a `RustPanic`, which the
 * pages render as "this line panics").
 *
 * All field arithmetic uses BigInt so that the 256-bit secp256k1 parameters
 * are exact.
 * ========================================================================== */
(function (global) {
  'use strict';

  /* ── generic helpers ──────────────────────────────────────────────────── */

  /** `((x % n) + n) % n` for BigInt — always in 0 … n−1. */
  function mod(x, n) {
    const r = x % n;
    return r < 0n ? r + n : r;
  }

  /**
   * Mirror of `num_bigint::BigUint::modpow`: `(base ^ exp) mod m`.
   * Square-and-multiply, exactly like the Rust implementation.
   */
  function modPow(base, exp, m) {
    if (m === 1n) return 0n;
    let r = 1n;
    base = mod(base, m);
    while (exp > 0n) {
      if (exp & 1n) r = (r * base) % m;
      exp >>= 1n;
      base = (base * base) % m;
    }
    return mod(r, m);
  }

  function gcd(a, b) {
    a = a < 0n ? -a : a;
    b = b < 0n ? -b : b;
    while (b) {
      const t = a % b;
      a = b;
      b = t;
    }
    return a;
  }

  /** Trial division, up to √n. */
  function isPrime(n) {
    if (n < 2n) return false;
    if (n % 2n === 0n) return n === 2n;
    for (let d = 3n; d * d <= n; d += 2n) if (n % d === 0n) return false;
    return true;
  }

  function factorize(n) {
    const parts = [];
    let d = 2n;
    let tmp = n;
    while (d * d <= tmp) {
      while (tmp % d === 0n) {
        parts.push(d);
        tmp /= d;
      }
      d += 1n;
    }
    if (tmp > 1n) parts.push(tmp);
    return parts;
  }

  function factorizeText(n) {
    return factorize(n)
      .map((f) => f.toString())
      .join(' × ');
  }

  /* ── Rust panic modelling ─────────────────────────────────────────────── */

  /** Thrown where the Rust code would panic. */
  class RustPanic extends Error {
    constructor(message) {
      super(message);
      this.name = 'RustPanic';
      this.isPanic = true;
    }
  }

  /** Mirror of Rust's `assert!(cond, "msg")`. */
  function assert(cond, message) {
    if (!cond) throw new RustPanic(message);
  }

  /**
   * Runs `fn` and turns a modelled Rust panic into a value the page can
   * show, instead of letting it escape and leave the page half-rendered.
   */
  function guardPanic(fn) {
    try {
      return { ok: true, value: fn() };
    } catch (error) {
      if (!error || !error.isPanic) throw error;
      return { ok: false, panic: error.message };
    }
  }

  /* ── ecc/src/finite_field.rs ──────────────────────────────────────────── */

  const ff = {
    /**
     * `FiniteField::add(a, b, p)` — `(a + b).modpow(1, p)`.
     * The Rust asserts that both operands are already reduced.
     */
    add(a, b, p) {
      assert(a < p, 'a must be less than p');
      assert(b < p, 'b must be less than p');
      return mod(a + b, p);
    },

    /**
     * `FiniteField::sub(c, d, p)` — addition with the additive inverse:
     * `add(c, inverse_add(d, p), p)`.
     */
    sub(c, d, p) {
      const dInv = ff.inverseAdd(d, p);
      return ff.add(c, dInv, p);
    },

    /** `FiniteField::mul(a, b, p)` — `(a * b).modpow(1, p)`. */
    mul(a, b, p) {
      assert(a < p, 'a must be less than p');
      assert(b < p, 'b must be less than p');
      return mod(a * b, p);
    },

    /** `FiniteField::inverse_add(c, p)` — `(p - c) % p`. */
    inverseAdd(c, p) {
      assert(c < p, 'c must be smaller than p');
      return mod(p - c, p);
    },

    /**
     * `FiniteField::inverse_mul(c, p)` — `c.modpow(p - 2, p)`.
     * Fermat's little theorem: c^(p−1) ≡ 1, so c^(p−2) ≡ c⁻¹.
     */
    inverseMul(c, p) {
      return modPow(c, p - 2n, p);
    },

    /** `FiniteField::div(c, d, p)` — `mul(c, inverse_mul(d, p), p)`. */
    div(c, d, p) {
      const dInv = ff.inverseMul(d, p);
      return ff.mul(c, dInv, p);
    },
  };

  /* ── ecc/src/point.rs ──────────────────────────────────────────────────── */

  /** A point is `{x, y}` (affine) or `null` (`Point::Identity`). */
  const IDENTITY = null;

  function pt(x, y) {
    return { x: BigInt(x), y: BigInt(y) };
  }

  function ptEq(a, b) {
    if (a === IDENTITY || b === IDENTITY) return a === b;
    return a.x === b.x && a.y === b.y;
  }

  /** Rust-style rendering: `Point::Coordinate(5, 1)` / `Point::Identity`. */
  function ptCode(p) {
    return p === IDENTITY ? 'Point::Identity' : `Point::Coordinate(${p.x}, ${p.y})`;
  }

  /** Short rendering: `(5, 1)` / `Identity (∞)`. */
  function ptText(p) {
    return p === IDENTITY ? 'Identity (∞)' : `(${p.x}, ${p.y})`;
  }

  /** The additive inverse of a point is its reflection in the x-axis. */
  function ptNeg(p, curveP) {
    if (p === IDENTITY) return IDENTITY;
    return pt(p.x, mod(curveP - p.y, curveP));
  }

  /* ── ecc/src/elliptic_curve.rs ────────────────────────────────────────── */

  const ec = {
    /**
     * `EllipticCurve::on_curve(&self, point)`.
     * Note: the Rust returns `false` for `Point::Identity` — the identity is
     * not an affine coordinate.
     */
    onCurve(curve, point) {
      if (point === IDENTITY) return false;
      const lhs = modPow(point.y, 2n, curve.p);
      const x3 = modPow(point.x, 3n, curve.p);
      const ax = mod(point.x * curve.a, curve.p);
      const rhs = mod(x3 + ax + curve.b, curve.p);
      return lhs === rhs;
    },

    /**
     * `EllipticCurve::compute_x3_y3(&self, s, x1, y1, x2)`.
     * Shared by `add` and `double`; for doubling the caller passes x1 twice.
     */
    computeX3Y3(curve, s, x1, y1, x2) {
      const s2 = modPow(s, 2n, curve.p);
      const x3 = ff.sub(ff.sub(s2, x1, curve.p), x2, curve.p);
      const x1mx3 = ff.sub(x1, x3, curve.p);
      const y3 = ff.sub(ff.mul(s, x1mx3, curve.p), y1, curve.p);
      return [x3, y3];
    },

    /** `EllipticCurve::add(&self, c, d)`. */
    add(curve, c, d) {
      if (c === IDENTITY) return d;
      if (d === IDENTITY) return c;

      assert(ec.onCurve(curve, c), 'Point c is not on the curve');
      assert(ec.onCurve(curve, d), 'Point d is not on the curve');

      // Vertical line: c and d are reflections, so c + d = O.
      if (c.x === d.x && ff.add(c.y, d.y, curve.p) === 0n) return IDENTITY;

      assert(!ptEq(c, d), 'Points must be different for addition');

      const s = ff.div(ff.sub(d.y, c.y, curve.p), ff.sub(d.x, c.x, curve.p), curve.p);
      const [x3, y3] = ec.computeX3Y3(curve, s, c.x, c.y, d.x);
      return pt(x3, y3);
    },

    /** `EllipticCurve::double(&self, c)`. */
    double(curve, c) {
      if (c === IDENTITY) return IDENTITY;

      assert(ec.onCurve(curve, c), 'Point is not on the curve');

      // The tangent line is vertical when y = 0: 2P = O.
      if (c.y === 0n) return IDENTITY;

      const numerator = ff.add(
        ff.mul(3n, ff.mul(c.x, c.x, curve.p), curve.p),
        curve.a,
        curve.p,
      );
      const denominator = ff.mul(2n, c.y, curve.p);
      const s = ff.div(numerator, denominator, curve.p);
      const [x3, y3] = ec.computeX3Y3(curve, s, c.x, c.y, c.x);
      return pt(x3, y3);
    },

    /**
     * `EllipticCurve::multiply(&self, d, c)` — double-and-add.
     * The scalar is processed from the most significant bit down to the least
     * significant one; `d = 0` yields the identity.
     */
    multiply(curve, d, c) {
      if (d === 0n) return IDENTITY;

      let t = c;
      const bits = d.toString(2).length;
      for (let i = bits - 2; i >= 0; i -= 1) {
        t = ec.double(curve, t);
        if ((d >> BigInt(i)) & 1n) {
          // `add` refuses to add a point to itself, and the ladder can land
          // on exactly that: when `2 * prefix ≡ 1 (mod order)` the doubled
          // accumulator is the base point again. The value the ladder wants is
          // `t + c`, which for `t == c` is `2c` — the double we are holding.
          t = ptEq(t, c) ? ec.double(curve, t) : ec.add(curve, t, c);
        }
      }
      return t;
    },

    /** Every affine point satisfying the curve equation. */
    enumerate(curve) {
      const out = [];
      for (let x = 0n; x < curve.p; x += 1n) {
        for (let y = 0n; y < curve.p; y += 1n) {
          if (ec.onCurve(curve, pt(x, y))) out.push(pt(x, y));
        }
      }
      return out;
    },

    /** Order of the subgroup generated by `c`, by walking until we hit identity. */
    order(curve, c) {
      if (c === IDENTITY) return 1n;
      // #E(F_p) ≤ p + 1 + 2√p, so a generator reaches the identity well inside
      // this bound; a non-generator never does. The first step has to be a
      // double, because `add` refuses a point plus itself.
      const limit = 4n * curve.p + 100n;
      let t = c;
      for (let i = 1n; i < limit; i += 1n) {
        // The crate panics on some of these (p = 3, for one), and the order
        // is only a note on the page — 0 means "not available".
        const run = guardPanic(() => (i === 1n ? ec.double(curve, t) : ec.add(curve, t, c)));
        if (!run.ok) return 0n;
        t = run.value;
        if (t === IDENTITY) return i + 1n;
      }
      return 0n;
    },
  };

  /* ── double-and-add trace (used by point arithmetic and by ECDSA) ─────── */

  /**
   * Replays `EllipticCurve::multiply` and records what happens on every bit.
   *
   * `options.maxSteps` caps how many individual bit steps are narrated; the
   * rest are summarised so that 256-bit scalars stay readable.
   *
   * Returns `{ steps, ladder, result }` where `ladder` lists the successive
   * values of `t` so the page can draw the ladder on the curve.
   */
  function traceMultiply(curve, scalar, base, options) {
    const opts = options || {};
    const maxSteps = opts.maxSteps || Infinity;
    const steps = [];
    const ladder = [];
    const line = (tone, s) => ({ tone, s });

    if (scalar === 0n) {
      steps.push({
        title: 'd == 0 → Point::Identity',
        lines: [line('code', 'if *d == BigUint::from(0u32) { return Point::Identity; }')],
      });
      return { steps, ladder, result: IDENTITY, eqL: `${ptCode(base)} × 0`, eqR: 'Point::Identity' };
    }

    const bits = scalar.toString(2);
    steps.push({
      title: 't = c  (the running accumulator)',
      lines: [
        line('code', 'let mut t = c.clone();'),
        line('calc', `t starts at ${ptText(base)} = ${ptCode(base)}`),
        line('dim', `scalar d = ${scalar} = ${bits}₂, so d.bits() = ${bits}`),
      ],
    });

    let t = base;
    ladder.push({ label: 't = c', point: t });

    const total = bits.length - 1;
    const narrated = Math.min(total, maxSteps);
    let skipped = 0;
    for (let i = total - 1; i >= 0; i -= 1) {
      const bit = bits[total - i]; // bit for position i, read from the MSB down
      const position = total - 1 - i; // 0-based position from the MSB
      const doubledRun = guardPanic(() => ec.double(curve, t));
      if (!doubledRun.ok) {
        steps.push({
          title: 'panic!',
          lines: [
            line('bad', `assert! fails: ${doubledRun.panic}`),
            line('dim', 'the crate multiplies by the literal 3, and FiniteField::mul wants both operands smaller than p'),
          ],
        });
        return {
          steps, ladder, result: IDENTITY,
          eqL: `${ptCode(base)} × ${scalar}`, eqR: '— the program panics here', panic: doubledRun.panic,
        };
      }
      const doubled = doubledRun.value;
      if (position < narrated) {
        steps.push({
          title: `bit ${total - i} of ${total}: d.bit(${i}) = ${bit}  →  t = double(t)`,
          lines: [
            line('code', 't = self.double(&t);'),
            line('calc', `double(${ptText(t)}) = ${ptText(doubled)}`),
            line('dim', 'the tangent line at t meets the curve a third time; reflect it in the x-axis'),
          ],
        });
        t = doubled;
        ladder.push({ label: `2·t (bit ${bit})`, point: t });

        if (bit === '1') {
          // `add` refuses to add a point to itself, and the ladder can land on
          // exactly that: the crate doubles instead of adding.
          const same = ptEq(t, base);
          const addedRun = guardPanic(() => (same ? ec.double(curve, t) : ec.add(curve, t, base)));
          if (!addedRun.ok) {
            steps.push({
              title: 'panic!',
              lines: [
                line('bad', `assert! fails: ${addedRun.panic}`),
              ],
            });
            return {
              steps, ladder, result: IDENTITY,
              eqL: `${ptCode(base)} × ${scalar}`, eqR: '— the program panics here', panic: addedRun.panic,
            };
          }
          const added = addedRun.value;
          steps.push({
            title: `the bit is 1  →  t = add(t, c)`,
            lines: [
              line('code', 't = if t == *c { self.double(&t) } else { self.add(&t, c) };'),
              line('calc', same
                ? `t is the base point, so the crate doubles it: 2 · ${ptText(t)} = ${ptText(added)}`
                : `${ptText(t)} + ${ptText(base)} = ${ptText(added)}`),
              line('dim', 'the chord through the two points meets the curve a third time; reflect it'),
            ],
          });
          t = added;
          ladder.push({ label: '+ c', point: t });
        } else {
          steps.push({
            title: `the bit is 0  →  no addition`,
            lines: [
              line('code', 'if d.bit(i) { … }  // not taken'),
              line('dim', `t stays at ${ptText(t)}`),
            ],
          });
        }
      } else {
        // keep the ladder complete, but narrate only the first `narrated` bits
        t = doubled;
        ladder.push({ label: `2·t (bit ${bit})`, point: t });
        if (bit === '1') {
          const same = ptEq(t, base);
          const addedRun = guardPanic(() => (same ? ec.double(curve, t) : ec.add(curve, t, base)));
          if (!addedRun.ok) {
            steps.push({
              title: 'panic!',
              lines: [line('bad', `assert! fails: ${addedRun.panic}`)],
            });
            return {
              steps, ladder, result: IDENTITY,
              eqL: `${ptCode(base)} × ${scalar}`, eqR: '— the program panics here', panic: addedRun.panic,
            };
          }
          t = addedRun.value;
          ladder.push({ label: '+ c', point: t });
        }
        skipped += 1;
      }
    }

    if (skipped > 0) {
      steps.push({
        title: `… ${skipped} more bit${skipped > 1 ? 's' : ''}, same rule each time`,
        lines: [
          line('dim', `each remaining bit doubles t, and adds the base point when the bit is 1`),
          line('dim', `the ladder on the grid shows every step; only the first ${narrated} are narrated here`),
        ],
      });
    }

    steps.push({
      title: 'Result',
      lines: [
        line('ok', `t = ${ptText(t)}`),
        line('dim', `${ptText(base)} × ${scalar} ≡ ${ptText(t)}`),
      ],
    });

    return { steps, ladder, result: t, eqL: `${ptCode(base)} × ${scalar}`, eqR: ptCode(t) };
  }

  /* ── ecc/src/elliptic_curve.rs — narrated traces ──────────────────────── */

  /**
   * Narrated version of `EllipticCurve::add`. Mirrors the branch order of the
   * Rust code exactly, including the fact that the reflection test runs
   * *before* `assert!(c != d)`.
   */
  function traceAdd(curve, c, d) {
    const p = curve.p;
    const steps = [];
    const branches = [];
    const line = (tone, s) => ({ tone, s });
    const push = (title, lines) => steps.push({ title, lines });

    const out = {
      title: 'EllipticCurve::add',
      steps,
      branches,
      result: IDENTITY,
      panic: null,
      eqL: null,
      eqR: null,
      codeL: null,
      codeR: null,
    };

    // ── match arms ──
    if (c === IDENTITY && d === IDENTITY) {
      branches.push({ name: '(Identity, Identity)', value: false, detail: 'falls through to the coordinate arm, which does not match' });
    } else if (c === IDENTITY) {
      branches.push({ name: '(Point::Identity, _)', value: true, detail: 'the first arm matches' });
    } else if (d === IDENTITY) {
      branches.push({ name: '(_, Point::Identity)', value: true, detail: 'the second arm matches' });
    } else {
      branches.push({ name: '(Point::Identity, _)', value: false, detail: 'c is a coordinate pair' });
      branches.push({ name: '(_, Point::Identity)', value: false, detail: 'd is a coordinate pair' });
    }

    if (c === IDENTITY || d === IDENTITY) {
      const result = c === IDENTITY ? d : c;
      out.result = result;
      push('match arm', [
        line('code', c === IDENTITY ? '(Point::Identity, _) => d.clone()' : '(_, Point::Identity) => c.clone()'),
        line('calc', `one side is ${ptCode(c)} and the other is ${ptCode(d)}`),
        line('ok', `result = ${ptText(result)}`),
      ]);
      out.eqL = `${ptCode(c)} + ${ptCode(d)}`;
      out.eqR = ptCode(result);
      return out;
    }

    // ── on_curve assertions ──
    const cOn = ec.onCurve(curve, c);
    const dOn = ec.onCurve(curve, d);
    branches.push({
      name: 'on_curve(c)',
      value: cOn,
      detail: cOn ? 'y² and x³ + ax + b agree mod p' : 'the assert! would fire',
    });
    branches.push({
      name: 'on_curve(d)',
      value: dOn,
      detail: dOn ? 'y² and x³ + ax + b agree mod p' : 'the assert! would fire',
    });

    const curveLines = (point) => {
      const y2 = modPow(point.y, 2n, p);
      const x3 = modPow(point.x, 3n, p);
      const ax = mod(point.x * curve.a, p);
      const rhs = mod(x3 + ax + curve.b, p);
      return [
        line('calc', `y² = ${point.y}² mod ${p} = ${y2}`),
        line('calc', `x³ + ax + b = ${point.x}³ + ${curve.a}·${point.x} + ${curve.b} mod ${p} = ${rhs}`),
        line(y2 === rhs ? 'ok' : 'bad', y2 === rhs ? 'equal → on_curve is true' : 'not equal → on_curve is false'),
      ];
    };

    push('on_curve assertions', [
      line('code', 'assert!(self.on_curve(c), "Point c is not on the curve");'),
      line('code', 'assert!(self.on_curve(d), "Point d is not on the curve");'),
      ...curveLines(c).map((l) => ({ ...l, s: `c = ${ptCode(c)}: ${l.s}` })),
      ...curveLines(d).map((l) => ({ ...l, s: `d = ${ptCode(d)}: ${l.s}` })),
    ]);

    if (!cOn || !dOn) {
      out.panic = !cOn ? 'Point c is not on the curve' : 'Point d is not on the curve';
      out.eqL = `${ptCode(c)} + ${ptCode(d)}`;
      out.eqR = '— the program panics here';
      push('panic!', [
        line('bad', `assert! fails: ${out.panic}`),
        line('dim', 'the Rust program stops here; nothing is returned'),
      ]);
      return out;
    }

    // ── vertical line / reflection test ──
    const sameX = c.x === d.x;
    const ySum = ff.add(c.y, d.y, p);
    const reflection = sameX && ySum === 0n;
    branches.push({
      name: 'x1 == x2',
      value: sameX,
      detail: `x1 = ${c.x}, x2 = ${d.x}`,
    });
    branches.push({
      name: 'y1 + y2 ≡ 0 (mod p)',
      value: ySum === 0n,
      detail: `${c.y} + ${d.y} = ${c.y + d.y} mod ${p} = ${ySum}`,
    });

    push('vertical line test', [
      line('code', 'if x1 == x2 && FiniteField::add(y1, y2, &self.p) == BigUint::from(0u32) { return Point::Identity; }'),
      line('calc', `x1 == x2 → ${sameX}   (x1 = ${c.x}, x2 = ${d.x})`),
      line('calc', `y1 + y2 = ${c.y} + ${d.y} = ${c.y + d.y} ≡ ${ySum} (mod ${p}) → ${ySum === 0n}`),
      line(reflection ? 'ok' : 'dim', reflection
        ? 'the two points are reflections of each other: their chord is vertical, so c + d = O'
        : 'the branch does not fire — continue'),
    ]);

    if (reflection) {
      out.result = IDENTITY;
      out.eqL = `${ptCode(c)} + ${ptCode(d)}`;
      out.eqR = 'Point::Identity';
      push('result', [
        line('ok', `${ptText(c)} + ${ptText(d)} = Identity (∞)`),
        line('dim', 'the inverse of a point is its reflection in the x-axis, and P + (−P) = O'),
      ]);
      return out;
    }

    // ── assert!(c != d) ──
    const same = ptEq(c, d);
    branches.push({
      name: 'c != d',
      value: !same,
      detail: same ? 'the assertion would fire' : 'the points are different',
    });

    push('assert!(c != d)', [
      line('code', 'assert!(c != d, "Points must be different for addition");'),
      line(same ? 'bad' : 'ok', same
        ? 'c and d are the same point → the function panics. Use double() instead.'
        : 'c and d differ, so the assertion holds'),
    ]);

    if (same) {
      out.panic = 'Points must be different for addition';
      out.eqL = `${ptCode(c)} + ${ptCode(d)}`;
      out.eqR = '— the program panics here';
      push('panic!', [
        line('bad', `assert! fails: ${out.panic}`),
        line('dim', 'adding a point to itself is what double() is for'),
      ]);
      return out;
    }

    // ── slope ──
    const num = ff.sub(d.y, c.y, p);
    const den = ff.sub(d.x, c.x, p);
    const denInv = ff.inverseMul(den, p);
    const s = ff.mul(num, denInv, p);

    push('slope s', [
      line('code', 'let s = FiniteField::div(&FiniteField::sub(y2, y1, &self.p), &FiniteField::sub(x2, x1, &self.p), &self.p);'),
      line('calc', `y₂ − y₁ = sub(${d.y}, ${c.y}) = (${d.y} + (${p} − ${c.y})) mod ${p} = ${num}`),
      line('calc', `x₂ − x₁ = sub(${d.x}, ${c.x}) = (${d.x} + (${p} − ${c.x})) mod ${p} = ${den}`),
      line('calc', `den⁻¹ = ${den}^(${p} − 2) mod ${p} = ${denInv}   (Fermat's little theorem)`),
      line('calc', `s = ${num} × ${denInv} mod ${p} = ${s}`),
      line('dim', 'this is the slope of the chord through the two points, over the finite field'),
    ]);

    // ── x3 / y3 ──
    const s2 = modPow(s, 2n, p);
    const x3 = ff.sub(ff.sub(s2, c.x, p), d.x, p);
    const x1mx3 = ff.sub(c.x, x3, p);
    const y3 = ff.sub(ff.mul(s, x1mx3, p), c.y, p);

    push('x₃ and y₃', [
      line('code', 'let (x3, y3) = self.compute_x3_y3(&s, x1, y1, x2);'),
      line('calc', `s² = ${s}² mod ${p} = ${s2}`),
      line('calc', `x₃ = s² − x₁ − x₂ = (${s2} − ${c.x} − ${d.x}) mod ${p} = ${x3}`),
      line('calc', `x₁ − x₃ = (${c.x} − ${x3}) mod ${p} = ${x1mx3}`),
      line('calc', `y₃ = s(x₁ − x₃) − y₁ = (${s} × ${x1mx3} − ${c.y}) mod ${p} = ${y3}`),
      line('dim', 'the third intersection of the chord with the curve, reflected in the x-axis'),
    ]);

    out.result = pt(x3, y3);
    out.eqL = `${ptCode(c)} + ${ptCode(d)}`;
    out.eqR = ptCode(out.result);
    push('result', [
      line('ok', `${ptText(c)} + ${ptText(d)} ≡ ${ptText(out.result)}`),
      line('dim', `the result is on the curve: y² ≡ ${modPow(y3, 2n, p)}, x³ + ax + b ≡ ${mod(mod(modPow(x3, 3n, p) + mod(x3 * curve.a, p) + curve.b, p), p)}`),
    ]);
    return out;
  }

  /** Narrated version of `EllipticCurve::double`. */
  function traceDouble(curve, c) {
    const p = curve.p;
    const steps = [];
    const branches = [];
    const line = (tone, s) => ({ tone, s });
    const push = (title, lines) => steps.push({ title, lines });

    const out = {
      title: 'EllipticCurve::double',
      steps,
      branches,
      result: IDENTITY,
      panic: null,
      eqL: null,
      eqR: null,
    };

    if (c === IDENTITY) {
      branches.push({ name: 'Point::Identity', value: true, detail: 'the identity arm matches' });
      push('match arm', [
        line('code', 'Point::Identity => Point::Identity'),
        line('ok', 'result = Identity (∞)'),
      ]);
      out.eqL = '2 · Point::Identity';
      out.eqR = 'Point::Identity';
      return out;
    }

    branches.push({ name: 'Point::Identity', value: false, detail: 'c is a coordinate pair' });

    const on = ec.onCurve(curve, c);
    branches.push({
      name: 'on_curve(c)',
      value: on,
      detail: on ? 'y² and x³ + ax + b agree mod p' : 'the assert! would fire',
    });

    const y2 = modPow(c.y, 2n, p);
    const xCubed = modPow(c.x, 3n, p);
    const ax = mod(c.x * curve.a, p);
    const rhs = mod(xCubed + ax + curve.b, p);

    push('on_curve assertion', [
      line('code', 'assert!(self.on_curve(c), "Point is not on the curve");'),
      line('calc', `y² = ${c.y}² mod ${p} = ${y2}`),
      line('calc', `x³ + ax + b = ${c.x}³ + ${curve.a}·${c.x} + ${curve.b} mod ${p} = ${rhs}`),
      line(on ? 'ok' : 'bad', on ? 'equal → on_curve is true' : 'not equal → on_curve is false'),
    ]);

    if (!on) {
      out.panic = 'Point is not on the curve';
      out.eqL = `2 · ${ptCode(c)}`;
      out.eqR = '— the program panics here';
      push('panic!', [
        line('bad', `assert! fails: ${out.panic}`),
      ]);
      return out;
    }

    const yIsZero = c.y === 0n;
    branches.push({
      name: 'y1 == 0',
      value: yIsZero,
      detail: `y1 = ${c.y}`,
    });

    push('y₁ == 0 branch', [
      line('code', 'if y1 == &BigUint::from(0u32) { return Point::Identity; }'),
      line(yIsZero ? 'ok' : 'dim', yIsZero
        ? 'y₁ = 0, so the tangent line is vertical: 2P = O'
        : `y₁ = ${c.y} ≠ 0, so the tangent is not vertical — continue`),
    ]);

    if (yIsZero) {
      out.result = IDENTITY;
      out.eqL = `2 · ${ptCode(c)}`;
      out.eqR = 'Point::Identity';
      push('result', [line('ok', `2 · ${ptText(c)} ≡ Identity (∞)`)]);
      return out;
    }

    const slopeRun = guardPanic(() => {
      const x1sq = ff.mul(c.x, c.x, p);
      const three = ff.mul(3n, x1sq, p);
      return {
        x1sq,
        three,
        numerator: ff.add(three, curve.a, p),
        denominator: ff.mul(2n, c.y, p),
      };
    });
    if (!slopeRun.ok) {
      out.panic = slopeRun.panic;
      out.eqL = `2 · ${ptCode(c)}`;
      out.eqR = '— the program panics here';
      push('panic!', [
        line('bad', `assert! fails: ${out.panic}`),
        line('dim', 'the crate multiplies by the literal 3, and FiniteField::mul wants both operands smaller than p'),
      ]);
      return out;
    }
    const { x1sq, three, numerator, denominator } = slopeRun.value;

    push('numerator = 3x₁² + a', [
      line('code', 'FiniteField::mul(&BigUint::from(3u32), &FiniteField::mul(x1, x1, &self.p), &self.p)'),
      line('calc', `x₁² = ${c.x}² mod ${p} = ${x1sq}`),
      line('calc', `3·x₁² = 3 × ${x1sq} mod ${p} = ${three}`),
      line('calc', `numerator = a + 3x₁² = (${curve.a} + ${three}) mod ${p} = ${numerator}`),
    ]);

    push('denominator = 2·y₁', [
      line('code', 'let denominator = FiniteField::mul(&BigUint::from(2u32), y1, &self.p);'),
      line('calc', `denominator = 2 × ${c.y} mod ${p} = ${denominator}`),
    ]);

    const denInv = ff.inverseMul(denominator, p);
    const s = ff.mul(numerator, denInv, p);

    push('slope s', [
      line('code', 'let s = FiniteField::div(&numerator, &denominator, &self.p);'),
      line('calc', `denominator⁻¹ = ${denominator}^(${p} − 2) mod ${p} = ${denInv}`),
      line('calc', `check: ${denominator} × ${denInv} = ${denominator * denInv} ≡ ${mod(denominator * denInv, p)} (mod ${p})`),
      line('calc', `s = ${numerator} × ${denInv} mod ${p} = ${s}`),
      line('dim', 'the tangent line at the point — the derivative of y² = x³ + ax + b is 2y dy/dx = 3x² + a'),
    ]);

    const s2 = modPow(s, 2n, p);
    const x3 = ff.sub(ff.sub(s2, c.x, p), c.x, p);
    const x1mx3 = ff.sub(c.x, x3, p);
    const y3 = ff.sub(ff.mul(s, x1mx3, p), c.y, p);

    push('x₃ and y₃', [
      line('code', 'let (x3, y3) = self.compute_x3_y3(&s, x1, y1, x1);'),
      line('dim', 'doubling passes x₁ as x₂, so x₃ = s² − 2x₁'),
      line('calc', `s² = ${s}² mod ${p} = ${s2}`),
      line('calc', `x₃ = s² − x₁ − x₁ = (${s2} − ${c.x} − ${c.x}) mod ${p} = ${x3}`),
      line('calc', `x₁ − x₃ = (${c.x} − ${x3}) mod ${p} = ${x1mx3}`),
      line('calc', `y₃ = s(x₁ − x₃) − y₁ = (${s} × ${x1mx3} − ${c.y}) mod ${p} = ${y3}`),
    ]);

    out.result = pt(x3, y3);
    out.eqL = `2 · ${ptCode(c)}`;
    out.eqR = ptCode(out.result);
    push('result', [
      line('ok', `2 · ${ptText(c)} ≡ ${ptText(out.result)}`),
    ]);
    return out;
  }

  /* ── ecdsa/src/lib.rs ─────────────────────────────────────────────────── */

  /* SHA-256, so the page works offline and over plain file:// as well. */
  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function rotr(x, n) {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
  }

  /** SHA-256 of a UTF-8 string; returns a 32-byte Uint8Array. */
  function sha256(text) {
    return sha256Bytes(new TextEncoder().encode(text));
  }

  /** SHA-256 of raw bytes; returns a 32-byte Uint8Array. */
  function sha256Bytes(input) {
    const bytes = input;
    const len = bytes.length;
    const withOne = len + 1;
    const padLen = (56 - (withOne % 64) + 64) % 64;
    const total = withOne + padLen + 8;

    const buf = new Uint8Array(total);
    buf.set(bytes);
    buf[len] = 0x80;
    const bitLen = BigInt(len) * 8n;
    for (let i = 0; i < 8; i += 1) {
      buf[total - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
    }

    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const w = new Uint32Array(64);

    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i += 1) {
        const j = off + i * 4;
        w[i] = ((buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3]) >>> 0;
      }
      for (let i = 16; i < 64; i += 1) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }

      let a = H[0], b = H[1], c = H[2], d = H[3];
      let e = H[4], f = H[5], g = H[6], h = H[7];

      for (let i = 0; i < 64; i += 1) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e;
        e = (d + t1) >>> 0;
        d = c; c = b; b = a;
        a = (t1 + t2) >>> 0;
      }

      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }

    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i += 1) {
      out[i * 4] = (H[i] >>> 24) & 0xff;
      out[i * 4 + 1] = (H[i] >>> 16) & 0xff;
      out[i * 4 + 2] = (H[i] >>> 8) & 0xff;
      out[i * 4 + 3] = H[i] & 0xff;
    }
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function hexToBigInt(hex) {
    return hex ? BigInt(`0x${hex}`) : 0n;
  }

  const ecdsa = {
    /**
     * `Ecdsa::generate_hash_less_than(message, max)`.
     * SHA-256 of the message, reduced modulo (max − 1), then shifted by one so
     * the result lands in 1 … max−1.
     */
    generateHashLessThan(message, max) {
      const digest = sha256(message);
      const hash = hexToBigInt(bytesToHex(digest));
      const modulus = max - 1n;
      return mod(hash, modulus) + 1n;
    },

    /** The teaching curve `y² = x³ + 2x + 2 (mod 17)`. */
    smallCurve() {
      return {
        name: 'teaching curve',
        equation: 'y² = x³ + 2x + 2 (mod 17)',
        curve: { a: 2n, b: 2n, p: 17n },
        generator: pt(5n, 1n),
        order: 19n,
        isReal: true,
      };
    },

    /** secp256k1 — the curve Bitcoin uses. */
    secp256k1() {
      return {
        name: 'secp256k1',
        equation: 'y² = x³ + 7 (mod p)',
        curve: {
          a: 0n,
          b: 7n,
          p: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
        },
        generator: pt(
          BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
          BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
        ),
        order: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
        isReal: false,
      };
    },

    /** `Ecdsa::generate_public_key` — `Q = d·G`. */
    publicKey(ctx, d) {
      return ec.multiply(ctx.curve, d, ctx.generator);
    },

    /**
     * `Ecdsa::sign(hash, private_key, k)`.
     * Returns `{ r, s, R, steps }`.
     */
    sign(ctx, hash, d, k) {
      const n = ctx.order;
      const steps = [];
      const line = (tone, s) => ({ tone, s });
      const push = (title, lines) => steps.push({ title, lines });

      assert(hash < n, 'Hash must be less than the order');
      assert(d < n, 'Private key must be less than the order');
      assert(k < n, 'k must be less than the order');

      push('preconditions', [
        line('code', 'assert!(hash < &self.order, "Hash must be less than the order");'),
        line('code', 'assert!(private_key < &self.order, "Private key must be less than the order");'),
        line('code', 'assert!(k < &self.order, "k must be less than the order");'),
        line('ok', `hash = ${hash} < ${n},  d = ${d} < ${n},  k = ${k} < ${n}`),
      ]);

      const R = ec.multiply(ctx.curve, k, ctx.generator);
      push('R = k·G', [
        line('code', 'let random_point = self.curve.multiply(k, &self.generator);'),
        line('calc', `k·G = ${ptText(R)}`),
        line('dim', 'the same double-and-add ladder as the point arithmetic page'),
      ]);

      if (R === IDENTITY) {
        throw new RustPanic('The random point should not be the identity');
      }

      const r = R.x % n;
      push('r = x(R) mod n', [
        line('code', 'let r = match random_point { Point::Coordinate(x, _) => x % &self.order, … };'),
        line('calc', `x(R) = ${R.x}`),
        line('calc', `r = ${R.x} mod ${n} = ${r}`),
      ]);

      const dr = ff.mul(d, r, n);
      push('d·r mod n', [
        line('code', 'let d_times_r = FiniteField::mul(private_key, &r, &self.order);'),
        line('calc', `${d} × ${r} mod ${n} = ${dr}`),
      ]);

      const hPlusDr = ff.add(hash, dr, n);
      push('hash + d·r mod n', [
        line('code', 'let hash_plus_d_times_r = FiniteField::add(hash, &d_times_r, &self.order);'),
        line('calc', `${hash} + ${dr} mod ${n} = ${hPlusDr}`),
      ]);

      const kInv = ff.inverseMul(k, n);
      push('k⁻¹', [
        line('code', 'let k_inverse = FiniteField::inverse_mul(k, &self.order);'),
        line('calc', `k⁻¹ = ${k}^(${n} − 2) mod ${n} = ${kInv}`),
        line('dim', 'Fermat\'s little theorem: the order n is prime, so k^(n−1) ≡ 1'),
      ]);

      const s = ff.mul(hPlusDr, kInv, n);
      push('s = (hash + d·r)·k⁻¹ mod n', [
        line('code', 'let s = FiniteField::mul(&hash_plus_d_times_r, &k_inverse, &self.order);'),
        line('calc', `${hPlusDr} × ${kInv} mod ${n} = ${s}`),
      ]);

      push('signature', [
        line('ok', `(r, s) = (${r}, ${s})`),
      ]);

      return { r, s, R, steps };
    },

    /**
     * `Ecdsa::verify(hash, public_key, signature)`.
     * Returns `{ valid, P, steps }`.
     */
    verify(ctx, hash, publicKey, signature) {
      const n = ctx.order;
      const [r, s] = signature;
      const steps = [];
      const line = (tone, s2) => ({ tone, s: s2 });
      const push = (title, lines) => steps.push({ title, lines });

      assert(hash < n, 'Hash must be less than the order');

      const sInv = ff.inverseMul(s, n);
      push('w = s⁻¹', [
        line('code', 'let s_inverse = FiniteField::inverse_mul(s, &self.order);'),
        line('calc', `w = ${s}^(${n} − 2) mod ${n} = ${sInv}`),
      ]);

      const u1 = ff.mul(hash, sInv, n);
      push('u1 = hash·w mod n', [
        line('code', 'let u1 = FiniteField::mul(hash, &s_inverse, &self.order);'),
        line('calc', `u1 = ${hash} × ${sInv} mod ${n} = ${u1}`),
      ]);

      const u2 = ff.mul(r, sInv, n);
      push('u2 = r·w mod n', [
        line('code', 'let u2 = FiniteField::mul(r, &s_inverse, &self.order);'),
        line('calc', `u2 = ${r} × ${sInv} mod ${n} = ${u2}`),
      ]);

      const u1G = ec.multiply(ctx.curve, u1, ctx.generator);
      push('u1·G', [
        line('code', 'let u1_generator = self.curve.multiply(&u1, &self.generator);'),
        line('calc', `u1·G = ${ptText(u1G)}`),
      ]);

      const u2Q = ec.multiply(ctx.curve, u2, publicKey);
      push('u2·Q', [
        line('code', 'let u2_public_key = self.curve.multiply(&u2, public_key);'),
        line('calc', `u2·Q = ${ptText(u2Q)}`),
      ]);

      const P = ec.add(ctx.curve, u1G, u2Q);
      push('P = u1·G + u2·Q', [
        line('code', 'let p = self.curve.add(&u1_generator, &u2_public_key);'),
        line('calc', `P = ${ptText(P)}`),
      ]);

      let valid = false;
      let verdict;
      if (P === IDENTITY) {
        verdict = [
          line('bad', 'P is the identity, so there is no x-coordinate to compare.'),
          line('bad', 'verify returns false'),
        ];
      } else {
        const xMod = P.x % n;
        valid = xMod === r;
        verdict = [
          line('calc', `x(P) = ${P.x}`),
          line('calc', `x(P) mod n = ${xMod}`),
          line('calc', `r = ${r}`),
          line(valid ? 'ok' : 'bad', valid
            ? 'they are equal → the signature is valid'
            : 'they differ → the signature is invalid'),
        ];
      }

      push('verdict', [
        line('code', 'match p { Point::Coordinate(x, _) => (x % &self.order) == *r, Point::Identity => false }'),
        ...verdict,
      ]);

      return { valid, P, u1, u2, u1G, u2Q, sInv, steps };
    },
  };

  /* ── Rust source viewer ──────────────────────────────────────────────── */

  /**
   * Renders a snapshot of a `.rs` file (produced by `sync-rs-source.mjs`) as
   * numbered lines, optionally highlighting one region.
   *
   * `region` may be the name of a symbol registered in `RS`, or a
   * `[start, end]` line range.
   */
  const rsView = {
    file(file) {
      return global.RS ? global.RS[file] : null;
    },

    resolve(file, region) {
      const data = rsView.file(file);
      if (!data) return null;
      if (!region) return null;
      // A region may be a single symbol name, a [start, end] line range, or a
      // list of either — the list is used when several items should light up.
      const names = Array.isArray(region) ? region : [region];
      const spans = [];
      for (const name of names) {
        const span = Array.isArray(name) ? name : data.regions[name];
        if (span) spans.push(span);
      }
      return spans.length ? spans : null;
    },

    html(file, region) {
      const data = rsView.file(file);
      if (!data) {
        return '<p class="cap">The Rust source snapshot is missing. Run '
          + '<code>node visualizers/assets/sync-rs-source.mjs</code>.</p>';
      }
      const spans = rsView.resolve(file, region);
      const out = [];
      for (let i = 0; i < data.lines.length; i += 1) {
        const n = i + 1;
        const hl = spans && spans.some((span) => n >= span[0] && n <= span[1]);
        out.push(
          `<div class="lst-line${hl ? ' hl' : ''}"><span class="n">${n}</span>`
          + `<span>${escapeHtml(data.lines[i])}</span></div>`,
        );
      }
      return out.join('');
    },

    /**
     * Scrolls the highlighted region of a rendered source panel into view.
     * The panel has a fixed height, so without this the interesting lines
     * would often sit below the fold.
     */
    reveal(file, region) {
      const panel = document.querySelector('#rs');
      if (!panel) return;
      const target = panel.querySelector('.lst-line.hl');
      if (!target) return;
      const offset = target.offsetTop - panel.offsetTop - panel.clientHeight / 2 + target.offsetHeight;
      panel.scrollTop = Math.max(0, offset);
    },
  };

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  /* ── BIP-340 Schnorr signatures ────────────────────────────────────── */

  /**
   * A tagged hash: SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data). The tag keeps a
   * hash used in one context from being valid in another.
   */
  function taggedHash(tag, parts) {
    const tagBytes = new TextEncoder().encode(tag);
    const tagHash = sha256Bytes(tagBytes);

    let total = 0;
    for (const part of parts) total += part.length;

    const buffer = new Uint8Array(64 + total);
    buffer.set(tagHash, 0);
    buffer.set(tagHash, 32);

    let offset = 64;
    for (const part of parts) {
      buffer.set(part, offset);
      offset += part.length;
    }

    return sha256Bytes(buffer);
  }

  /** The 32-byte big-endian encoding of a number. */
  function encode32(value) {
    const out = new Uint8Array(32);
    let v = value;
    for (let i = 31; i >= 0; i -= 1) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }

  /** The 32-byte big-endian encoding of a hex string. */
  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i += 1) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  const schnorr = {
    /** The small curve the visualizer draws: y² = x³ + 10 (mod 19). */
    teaching: {
      curve: { p: 19n, a: 0n, b: 10n },
      generator: { x: 1n, y: 12n },
      order: 19n,
    },

    /** secp256k1, the curve BIP-340 is defined for. */
    secp256k1: {
      curve: {
        p: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
        a: 0n,
        b: 7n,
      },
      generator: {
        x: BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
        y: BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
      },
      order: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
    },

    /** Whether the point's y-coordinate is even. */
    hasEvenY(point) {
      return point !== IDENTITY && point.y % 2n === 0n;
    },

    /** The negation of a point: the same x, the opposite y. */
    negate(params, point) {
      if (point === IDENTITY) return IDENTITY;
      return pt(point.x, mod(params.curve.p - point.y, params.curve.p));
    },

    /**
     * Recovers the point with the given x-coordinate, choosing the even
     * y-coordinate. This is BIP-340's `lift_x`.
     */
    liftX(params, x) {
      const p = params.curve.p;
      if (x >= p) return null;

      const x3 = modPow(x, 3n, p);
      const ax = mod(x * params.curve.a, p);
      const c = mod(x3 + ax + params.curve.b, p);

      // y = c^((p+1)/4) mod p — valid because p = 3 (mod 4)
      const exponent = (p + 1n) / 4n;
      const y = modPow(c, exponent, p);
      if (modPow(y, 2n, p) !== c) return null;

      return pt(x, y % 2n === 0n ? y : mod(p - y, p));
    },

    /** The public key: the x-coordinate of d·G. */
    publicKey(params, secretKey) {
      const order = params.order;
      if (secretKey === 0n || secretKey >= order) throw new RustPanic('the secret key must be in 1 … n−1');
      const point = ec.multiply(params.curve, secretKey, params.generator);
      if (point === IDENTITY) throw new RustPanic('the secret key must be in 1 … n−1');
      return point.x;
    },

    /**
     * Signs a message.
     *
     * BIP-340 says to fail when the derived nonce is zero. On secp256k1 that
     * never happens in practice; on a small curve it happens once in n
     * signatures, so we retry with a counter mixed into the auxiliary
     * randomness. The first attempt uses the auxiliary randomness exactly as
     * given.
     */
    sign(params, secretKey, message, aux) {
      const baseAux = aux || new Uint8Array(32);
      const messageBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;

      for (let attempt = 0; attempt < 8; attempt += 1) {
        const attemptAux = baseAux.slice();
        const counter = new Uint8Array(4);
        new DataView(counter.buffer).setUint32(0, attempt, false);
        for (let i = 0; i < 4; i += 1) attemptAux[28 + i] ^= counter[i];

        try {
          return schnorr.signOnce(params, secretKey, messageBytes, attemptAux);
        } catch (error) {
          if (error && error.nonceIsZero) continue;
          throw error;
        }
      }
      throw new RustPanic('the derived nonce was zero');
    },

    /** One signing attempt with fixed auxiliary randomness. */
    signOnce(params, secretKey, message, aux) {
      const n = params.order;
      const p = params.curve.p;
      if (secretKey === 0n || secretKey >= n) throw new RustPanic('the secret key must be in 1 … n−1');

      const pPoint = ec.multiply(params.curve, secretKey, params.generator);
      if (pPoint === IDENTITY) throw new RustPanic('the secret key must be in 1 … n−1');
      const pX = pPoint.x;

      // The secret key is negated when the public point has an odd y.
      const d = schnorr.hasEvenY(pPoint) ? secretKey : mod(n - secretKey, n);

      // t = bytes(d) XOR hash_aux(a)
      const auxHash = taggedHash('BIP0340/aux', [aux]);
      const t = new Uint8Array(32);
      const dBytes = encode32(d);
      for (let i = 0; i < 32; i += 1) t[i] = dBytes[i] ^ auxHash[i];

      // rand = hash_nonce(t ‖ bytes(P) ‖ m)
      const rand = taggedHash('BIP0340/nonce', [t, encode32(pX), message]);

      const kPrime = mod(BigInt('0x' + bytesToHex(rand)), n);
      if (kPrime === 0n) {
        const error = new RustPanic('the derived nonce was zero');
        error.nonceIsZero = true;
        throw error;
      }

      const rPoint = ec.multiply(params.curve, kPrime, params.generator);
      if (rPoint === IDENTITY) {
        const error = new RustPanic('the derived nonce was zero');
        error.nonceIsZero = true;
        throw error;
      }
      const rX = rPoint.x;
      const k = schnorr.hasEvenY(rPoint) ? kPrime : mod(n - kPrime, n);

      // e = int(hash_challenge(bytes(R) ‖ bytes(P) ‖ m)) mod n
      const challenge = taggedHash('BIP0340/challenge', [encode32(rX), encode32(pX), message]);
      const e = mod(BigInt('0x' + bytesToHex(challenge)), n);

      const s = mod(k + ff.mul(e, d, n), n);
      const signature = { r: rX, s };

      // The signer checks its own work.
      if (!schnorr.verify(params, pX, message, signature)) {
        throw new RustPanic('the signature did not verify');
      }

      void p;
      return signature;
    },

    /** Verifies a signature. */
    verify(params, publicKey, message, signature) {
      const p = params.curve.p;
      const n = params.order;
      const messageBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;

      const pPoint = schnorr.liftX(params, publicKey);
      if (pPoint === null) return false;
      const pX = pPoint.x;

      if (signature.r >= p || signature.s >= n) return false;

      const challenge = taggedHash('BIP0340/challenge', [encode32(signature.r), encode32(pX), messageBytes]);
      const e = mod(BigInt('0x' + bytesToHex(challenge)), n);

      const sG = ec.multiply(params.curve, signature.s, params.generator);
      const eP = ec.multiply(params.curve, e, pPoint);
      const negEP = schnorr.negate(params, eP);

      // `EllipticCurve::add` refuses to add a point to itself, and here the
      // two terms can be equal: when s·G = −e·P the sum is a doubling, not
      // an error. When they are reflections instead, `add` returns the
      // identity and the signature simply fails to verify.
      const rPoint = ptEq(sG, negEP)
        ? ec.double(params.curve, sG)
        : ec.add(params.curve, sG, negEP);

      if (rPoint === IDENTITY) return false;
      return schnorr.hasEvenY(rPoint) && rPoint.x === signature.r;
    },
  };

  global.ECC = {
    mod,
    modPow,
    gcd,
    isPrime,
    factorize,
    factorizeText,
    RustPanic,
    assert,
    ff,
    IDENTITY,
    pt,
    ptEq,
    ptCode,
    ptText,
    ptNeg,
    ec,
    traceMultiply,
    traceAdd,
    traceDouble,
    ecdsa,
    sha256,
    sha256Bytes,
    bytesToHex,
    hexToBigInt,
    taggedHash,
    encode32,
    hexToBytes,
    schnorr,
    rsView,
    escapeHtml,
  };
}(window));
