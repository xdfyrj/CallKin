// Controlled negative for the F7 rescue rule.
//
// Two *different* generic functions, each instantiated over the same two-variant
// axis:
//
//   left<A0>   left<A1>      -> one source origin
//   right<A0>  right<A1>     -> a different source origin
//
// Given fragments {left<A0>, left<A1>} and {right<A0>, right<A1>}, F7 sees a
// complete and bijective 2 x 2:
//
//   axis 1   left / right
//   axis 2   A0 / A1
//
// Axis 2 varies inside each fragment. Axis 1 does not: it only tells the two
// fragments apart, which is exactly the mistake `StandardSink::context` and
// `matched` produced on the real binary. The rescue rule must therefore refuse
// this merge with `axis_without_internal_fragment_support`.
//
// `left` and `right` deliberately call the same `common_marker` and the same
// A-dependent callee shape, so their relation colour matches and a
// `same_prior_color` bridge exists. That makes the relation-bridge condition
// pass on its own, which is the point: this fixture proves the bridge alone
// cannot stop a false merge.

use std::hint::black_box;

trait Axis {
    fn callee(x: u64) -> u64;
}

struct A0;
struct A1;

impl Axis for A0 {
    #[inline(never)]
    fn callee(x: u64) -> u64 {
        x.wrapping_mul(0x9E37_79B9).wrapping_add(0x00A0_0001)
    }
}

impl Axis for A1 {
    #[inline(never)]
    fn callee(x: u64) -> u64 {
        x.wrapping_mul(0x85EB_CA6B).wrapping_sub(0x00A1_0001)
    }
}

// Called by both kernels, so neither side gets a caller-specific callee that
// would split the relation colour on its own.
#[inline(never)]
fn common_marker(x: u64, salt: u64) -> u64 {
    x.rotate_left(7) ^ salt.wrapping_mul(0x0101_0101)
}

// Only the salt differs, which keeps identical-code folding from merging the
// two kernels while leaving their call relation identical.
#[inline(never)]
fn left<A: Axis>(x: u64) -> u64 {
    let marked = common_marker(x, 0x0000_1EF7);
    A::callee(marked)
}

#[inline(never)]
fn right<A: Axis>(x: u64) -> u64 {
    let marked = common_marker(x, 0x0000_2167);
    A::callee(marked)
}

fn main() {
    let seed = black_box(0x0123_4567_89AB_CDEFu64);
    let mut acc = 0u64;

    acc ^= left::<A0>(seed);
    acc ^= left::<A1>(seed);
    acc ^= right::<A0>(seed);
    acc ^= right::<A1>(seed);

    println!("{}", black_box(acc));
}
