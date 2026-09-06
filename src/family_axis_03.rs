// Controlled fixture for F7.3 anonymous variation axes.
//
// Three generic kernels over the same two trait axes:
//
//   complete<A, B>    all 2 x 3 combinations are called      -> 6 instances
//   incomplete<A, B>  A1 with B2 is never referenced anywhere -> 5 instances
//   same_axis<A>      two callsites that both depend on A     -> 2 instances
//
// Monomorphization collects the concrete combinations that are actually used
// before codegen units are partitioned, so never naming `incomplete::<A1, B2>`
// is what keeps it out of the binary. No dead branch, function pointer table or
// vtable mentions it.
//
// Every kernel and every concrete callee is `#[inline(never)]`, each callee
// carries its own salt so identical-code folding cannot merge two of them, and
// every result reaches `black_box`, so the five wanted instances of
// `incomplete` cannot be optimized away either.

use std::hint::black_box;

trait AxisA {
    fn step(x: u64) -> u64;
    fn other(x: u64) -> u64;
}

trait AxisB {
    fn step(x: u64) -> u64;
}

struct A0;
struct A1;
struct B0;
struct B1;
struct B2;

impl AxisA for A0 {
    #[inline(never)]
    fn step(x: u64) -> u64 {
        x.wrapping_mul(0x9E37_79B9).wrapping_add(0x00A0_0001)
    }
    #[inline(never)]
    fn other(x: u64) -> u64 {
        x.rotate_left(7) ^ 0x00A0_0002
    }
}

impl AxisA for A1 {
    #[inline(never)]
    fn step(x: u64) -> u64 {
        x.wrapping_mul(0x85EB_CA6B).wrapping_sub(0x00A1_0001)
    }
    #[inline(never)]
    fn other(x: u64) -> u64 {
        x.rotate_right(11) ^ 0x00A1_0002
    }
}

impl AxisB for B0 {
    #[inline(never)]
    fn step(x: u64) -> u64 {
        x.wrapping_add(0x00B0_0001).rotate_left(3)
    }
}

impl AxisB for B1 {
    #[inline(never)]
    fn step(x: u64) -> u64 {
        x.wrapping_sub(0x00B1_0001).rotate_left(13)
    }
}

impl AxisB for B2 {
    #[inline(never)]
    fn step(x: u64) -> u64 {
        x.wrapping_mul(0x00B2_0001).rotate_right(5)
    }
}

// One call slot varies with A only, the other with B only.
#[inline(never)]
fn complete<A: AxisA, B: AxisB>(x: u64) -> u64 {
    let a = A::step(x);
    let b = B::step(a);
    (a ^ b).wrapping_add(0x0C0C_0C0C)
}

// Same shape, different constants and a different combining operation, so this
// kernel can never be folded onto `complete`.
#[inline(never)]
fn incomplete<A: AxisA, B: AxisB>(x: u64) -> u64 {
    let a = A::step(x);
    let b = B::step(a);
    a.wrapping_add(b) ^ 0x1111_1111
}

// Two varying call slots that split the members the same way: one axis, not two.
#[inline(never)]
fn same_axis<A: AxisA>(x: u64) -> u64 {
    let p = A::step(x);
    let q = A::other(p);
    (p ^ q).wrapping_mul(0x2222_2223)
}

fn main() {
    let seed = black_box(0x0123_4567_89AB_CDEFu64);
    let mut acc = 0u64;

    acc ^= complete::<A0, B0>(seed);
    acc ^= complete::<A0, B1>(seed);
    acc ^= complete::<A0, B2>(seed);
    acc ^= complete::<A1, B0>(seed);
    acc ^= complete::<A1, B1>(seed);
    acc ^= complete::<A1, B2>(seed);

    acc ^= incomplete::<A0, B0>(seed);
    acc ^= incomplete::<A0, B1>(seed);
    acc ^= incomplete::<A0, B2>(seed);
    acc ^= incomplete::<A1, B0>(seed);
    acc ^= incomplete::<A1, B1>(seed);
    // incomplete::<A1, B2> is deliberately absent.

    acc ^= same_axis::<A0>(seed);
    acc ^= same_axis::<A1>(seed);

    println!("{}", black_box(acc));
}
