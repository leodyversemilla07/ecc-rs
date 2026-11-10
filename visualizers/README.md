# Visualizers

Interactive pages that show the mathematics behind this crate.

**Live site:** <https://leodyversemilla07.github.io/ecc-rs/>

The site is served from the repository's `gh-pages` branch, whose root is a copy
of this folder. GitHub Pages is configured (Settings → Pages) to build from
that branch with the `/` folder as the site root, so the hub page is served
from the root of the project site.

| Page | Covers |
| --- | --- |
| [`index.html`](index.html) | the hub page |
| [`finite-field.html`](finite-field.html) | `ecc/src/finite_field.rs` — the arithmetic on F<sub>p</sub> |
| [`point-arithmetic.html`](point-arithmetic.html) | `ecc/src/elliptic_curve.rs` and `ecc/src/point.rs` — the group law |
| [`ecdsa.html`](ecdsa.html) | `ecdsa/src/lib.rs` — key generation, signing, verification |

There is no build step. Open any page in a browser, or serve the folder:

```sh
python -m http.server --directory visualizers
```

## Publishing

After changing anything here, rebuild and push the `gh-pages` branch:

```sh
node visualizers/assets/publish.mjs
```

The script copies this folder to the root of a fresh `gh-pages` branch and
force-pushes it. GitHub Pages picks the change up within a minute or two.

## How the pages stay honest

Three mechanisms, all of them checked into this repository.

**1. The Rust source shown on the pages is generated, not typed in.**
[`assets/sync-rs-source.mjs`](assets/sync-rs-source.mjs) reads the `.rs` files
and writes [`assets/rust-source.js`](assets/rust-source.js), which contains the
full text of each file plus the line range of every function. The pages
highlight the range of the function they are currently running.

```sh
node visualizers/assets/sync-rs-source.mjs
```

Run it after changing any `.rs` file. It fails loudly if a symbol it expects
to find has moved.

**2. The arithmetic is a re-implementation, not a lookup table.**
[`assets/ecc.js`](assets/ecc.js) re-implements `FiniteField`,
`EllipticCurve` and `Ecdsa` in JavaScript, including their `assert!`s — a
failing assertion throws a `RustPanic`, which the pages render as "the program
panics here". All field arithmetic uses `BigInt`, so the 256-bit secp256k1
parameters are exact.

**3. The re-implementation is checked against the crate.**
Two Rust examples print the crate's answers for a large set of inputs:

- [`ecc/examples/parity_dump_ecc.rs`](../ecc/examples/parity_dump_ecc.rs) — every
  field operation for eleven primes, every point addition and doubling for
  five curves, and 40 scalar multiplications each.
- [`ecdsa/examples/parity_dump_ecdsa.rs`](../ecdsa/examples/parity_dump_ecdsa.rs) —
  every key pair and nonce on the teaching curve, including tampered
  verifications.

Together that is more than 300,000 cases, compared panic-for-panic: where the
Rust code panics on invalid input, the JavaScript throws, and the diff expects
the same marker on both sides. That is how a genuine behaviour of the crate —
`Ecdsa::verify` panics when `u₁·G` and `u₂·Q` happen to be the same point,
which happens for about one nonce in nineteen on a curve as small as the
teaching one — was found.

[`assets/parity-check.mjs`](assets/parity-check.mjs) recomputes the same cases
in JavaScript and diffs the two:

```sh
cargo run --release --example parity_dump_ecc -p ecc
cargo run --release --example parity_dump_ecdsa -p ecdsa
node visualizers/assets/parity-check.mjs
```

The dump files land in `target/` and are not committed. The script also accepts
`--run-rust` to run the two cargo commands itself.

## Design

The pages are instrument panels rather than a card grid: a narrow control rail
on the left, a wide canvas on the right, hairline rules instead of shadows, and
a monospace read-out for every number. Dark is the default; the light theme is
a blueprint variant. The whole system is one file,
[`assets/app.css`](assets/app.css), driven by CSS custom properties.

## Layout

```text
visualizers/
  index.html              hub page
  finite-field.html       F_p arithmetic
  point-arithmetic.html   the group law
  ecdsa.html              signatures
  .nojekyll               tells GitHub Pages to serve the files verbatim
  assets/
    app.css               the design system
    ecc.js                the JavaScript mirror of the crate
    rust-source.js        generated snapshot of the Rust sources
    sync-rs-source.mjs    regenerates rust-source.js
    parity-check.mjs      diffs the JavaScript against the crate
    publish.mjs           rebuilds and pushes the gh-pages branch
```
