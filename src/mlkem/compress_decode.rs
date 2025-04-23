use core::iter::zip;

use crate::mlkem::Q;

use super::rq::Rq;



// only works for x >= 0
pub(crate) fn compress_unsigned(x: u16, d: usize) -> u16 {
    const BarrettParam: u32 = ((1u64 << 32) / (Q as u64)) as u32;
    // y = x * 2^d
    let y = (x as u32) << d;

    // the higher 32 bits of BarrettParam * y
    let (_, mut quo) = u32::widening_mul(BarrettParam, y);
    let r = y - quo * Q as u32;

    let halfq = (Q / 2) as u32;
    let halfq_and_q = (Q + Q / 2) as u32;

    quo += (halfq.wrapping_sub(r) >> 31) & 1;
    quo += (halfq_and_q.wrapping_sub(r) >> 31) & 1;

    (quo & ((1 << d) - 1)) as u16
}


// Z_q -> Z_{2^d}
// x |-> round(2^d/q * x) mod 2^d
// Assume any x, use barrett reduction.
// Note: if y = x + nq, then
//    round(2^d * y/q) mod 2^d
//  = round(2^d*x/q + n*2^d) mod 2^d
//  = round(2^d*x/q)
#[inline]
pub(crate) fn compress(x: i16, d: usize) -> u16 {
    const BarrettParam: i32 = ((1u64 << 32) / (Q as u64)) as i32;
    // y = x * 2^d
    let y = (x as i32) << d;

    // the higher 32 bits of BarrettParam * y
    let (_, mut quo) = i32::widening_mul(BarrettParam, y);
    let r = y - quo * Q as i32;

    const neg_halfq: i32 = -((Q - 1) / 2) as i32;
    const halfq: i32 = (Q / 2) as i32;
    const halfq_and_q: i32 = (Q + Q / 2) as i32;
    quo -= 1;
    quo += (neg_halfq.wrapping_sub(r) >> 31) & 1;
    quo += (halfq.wrapping_sub(r) >> 31) & 1;
    quo += (halfq_and_q.wrapping_sub(r) >> 31) & 1;

    (quo & ((1 << d) - 1)) as u16
}


#[inline]
pub(crate) fn decompress(y: u16, d: usize) -> i16 {
    let x = (Q as u32 * y as u32) + (1 << (d - 1));
    (x >> d) as i16
}

// d = 1,4,5,10,11
#[inline]
pub(crate) fn compress_and_encode(b: &mut [u8], f: &[i16; 256], d: usize) {
    match d {
        1 => compress_and_encode1(b, f),
        4 => compress_and_encode4(b, f),
        10 => compress_and_encode10(b, f),
        _ => compress_and_encode_generic(b, f, d),
    }
}

#[inline]
pub(crate) fn decode_and_decompress(f: &mut [i16; 256], b: &[u8], d: usize) {
    match d {
        1 => decode_and_decompress1(f, b),
        4 => decode_and_decompress4(f, b),
        10 => decode_and_decompress10(f, b),
        _ => decode_and_decompress_generic(f, b, d),
    }
}

#[inline]
pub(crate) fn compress_and_encode_vecs(b: &mut [u8], v: &[Rq], d: usize) {
    for (f, b) in zip(v, b.chunks_exact_mut(32 * d)) {
        compress_and_encode(b, &f.coeffs, d);
    }
}

#[inline]
pub(crate) fn decode_and_decompress_vecs(v: &mut [Rq], b: &[u8], d: usize) {
    for (f, b) in zip(v, b.chunks_exact(32 * d)) {
        decode_and_decompress(&mut f.coeffs, b, d);
    }
}

// General case for ByteEncode_i(Compress_i(.)) and Decompress_i(Decode_i(.))

// b should have length 32*d
fn compress_and_encode_generic(b: &mut [u8], f: &[i16; 256], d: usize) {
    debug_assert!(b.len() == 32 * d);

    let mut bi = 0;
    let mut fi = 0;
    let mut buf: u64 = 0;
    let mut buf_len = 0;
    while fi < 256 {
        // read
        while buf_len <= 64 - d && fi < 256 {
            let c = compress(f[fi], d);
            fi += 1;
            buf |= (c as u64) << buf_len;
            buf_len += d;
        }

        // write
        while buf_len >= 8 {
            b[bi] = buf as u8;
            buf >>= 8;
            bi += 1;
            buf_len -= 8;
        }
    }
}

pub(crate) fn decode_and_decompress_generic(f: &mut [i16; 256], b: &[u8], d: usize) {
    debug_assert!(b.len() == 32 * d);

    let mask = (1 << d) - 1;

    let mut fi = 0;
    let mut buf: u64 = 0;
    let mut buf_len = 0;
    // read
    for chunk in b.chunks_exact(8) {
        let c = u64::from_le_bytes(chunk.try_into().unwrap());
        let x = ((c << buf_len) | buf) & mask;
        f[fi] = decompress(x as u16, d);
        fi += 1;

        buf = c >> (d - buf_len);
        
        buf_len = buf_len + 64 - d;
        while buf_len >= d {
            f[fi] = decompress((buf & mask) as u16, d);
            fi += 1;
            buf >>= d;
            buf_len -= d;
        }
    }
}

pub(crate) fn compress_and_encode5(b: &mut [u8; 256 * 5 / 8], f: &[i16; 256]) {
    compress_and_encode_generic(b, f, 5);
}

pub(crate) fn decode_and_decompress5(f: &mut [i16; 256], b: &[u8; 256 * 5 / 8]) {
    decode_and_decompress_generic(f, b, 5);
}

pub(crate) fn compress_and_encode11(b: &mut [u8; 256 * 11 / 8], f: &[i16; 256]) {
    compress_and_encode_generic(b, f, 11);
}

pub(crate) fn decode_and_decompress11(f: &mut [i16; 256], b: &[u8; 256 * 11 / 8]) {
    decode_and_decompress_generic(f, b, 11);
}

// ByteEncode_i(Compress_i(.)) and Decompress_i(Decode_i(.)) for special i = 1,4,10.

// b = ByteEncode1(Compress1(f))
// Note Compress1 maps
//  [0, (q-1)/2] -> 0
//  [(q+1)/2, q) -> 1
#[inline]
pub(crate) fn compress_and_encode1(b: &mut [u8], f: &[i16; 256]) {
    debug_assert!(b.len() == 32);
    for (bi, f) in zip(b, f.chunks_exact(8)) {
        *bi = 0;
        for i in 0..8 {
            // let fi = ((f[i] << 2) + Q) / (2 * Q) & 1;
            let fi = compress(f[i], 1);
            *bi |= (fi << i) as u8;
        }
    }
}

// decompress1(y) = round(q*y/2), thus:
// decompress1(0) = 0;
// decompress1(1) = round(q/2) = [q/2 + 1/2] = (q+1)/2;
#[inline]
pub(crate) fn decode_and_decompress1(f: &mut [i16; 256], b: &[u8]) {
    debug_assert!(b.len() == 32);

    const half_q: i16 = (Q + 1) / 2;
    for (b, f) in zip(b, f.chunks_exact_mut(8)) {
        for i in 0..8 {
            let bit = (*b >> i) & 1;
            f[i] = !((bit as i16) - 1) & half_q;
        }
    }
}

#[inline]
pub(crate) fn compress_and_encode4(b: &mut [u8], f: &[i16; 256]) {
    debug_assert!(b.len() == 32 * 4);

    const half_q: i16 = (Q - 1) / 2;
    for (b, f) in zip(b, f.chunks_exact(2)) {
        *b = (compress(f[0], 4) | compress(f[1], 4) << 4) as u8;
    }
}

#[inline]
pub(crate) fn decode_and_decompress4(f: &mut [i16; 256], b: &[u8]) {
    debug_assert!(b.len() == 32 * 4);

    for (b, f) in zip(b, f.chunks_exact_mut(2)) {
        f[0] = decompress((*b & 0b1111) as u16, 4);
        f[1] = decompress((*b >> 4) as u16, 4) as i16;
    }
}

// 4 coeffs to 5 bytes
#[inline]
pub(crate) fn compress_and_encode10(b: &mut [u8], f: &[i16; 256]) {
    debug_assert!(b.len() == 32 * 10);

    const half_q: i16 = (Q - 1) / 2;
    for (b, f) in zip(b.chunks_exact_mut(5), f.chunks_exact(4)) {
        let x = (compress(f[0], 10) as u64)
            | (compress(f[1], 10) as u64) << 10
            | (compress(f[2], 10) as u64) << 20
            | (compress(f[3], 10) as u64) << 30;
        b[0] = (x >> 0) as u8;
        b[1] = (x >> 8) as u8;
        b[2] = (x >> 16) as u8;
        b[3] = (x >> 24) as u8;
        b[4] = (x >> 32) as u8;
    }
}

#[inline]
pub(crate) fn decode_and_decompress10(f: &mut [i16; 256], b: &[u8]) {
    debug_assert!(b.len() == 32 * 10);

    for (b, f) in zip(b.chunks_exact(5), f.chunks_exact_mut(4)) {
        let x =
            (b[0] as u64) << 0 | (b[1] as u64) << 8 | (b[2] as u64) << 16 | (b[3] as u64) << 24 | (b[4] as u64) << 32;
        f[0] = decompress(((x >> 0) & 0b11_1111_1111) as u16, 10) as i16;
        f[1] = decompress(((x >> 10) & 0b11_1111_1111) as u16, 10) as i16;
        f[2] = decompress(((x >> 20) & 0b11_1111_1111) as u16, 10) as i16;
        f[3] = decompress(((x >> 30) & 0b11_1111_1111) as u16, 10) as i16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Z_q -> Z_{2^d}
    // x |-> round(2^d/q * x) mod 2^d
    fn compress_nieve(x: i16, d: usize) -> u16 {
        let x = x % 3329;
        let x = if x < 0 { x + 3329 } else { x };
        let x = x as u32;

        let y = (x << (d + 1)) + 3329;
        let y = y / (2 * 3329);
        let y = y % (1 << d);
        y as u16
    }

    #[test]
    fn test_compress() {
        const d: usize = 10;

        for x in -8 * Q..8 * Q {
            let a = compress(x, d);
            let b  = compress_nieve(x, d);
            if a != b{
                println!("compress({x}) = {a}, compress_nieve({x}) = {b}");
            }
            if x >= 0{
                let c = compress_unsigned(x as u16, d);
                if b != c{
                    println!("compress_unsigned({x}) = {c}, compress_nieve({x}) = {b}");
                }
            }
        }
    }

    #[test]
    fn test_compress_decompress() {
        const d: usize = 10;
        //compress(decompress(y)) == y for y in [0, 2^d).
        for y in 0..(1 << d) {
            assert_eq!(y, compress(decompress(y, d), d));
        }
    }

    #[test]
    fn test_compress_and_encode1() {
        let mut rng = rand::rng();
        let b: [u8; 32] = rng.random();
        let mut bb = [0; 32];

        let mut f = [0; 256];

        decode_and_decompress1(&mut f, &b);
        compress_and_encode1(&mut bb, &f);

        assert_eq!(b, bb);
    }

    #[test]
    fn test_compress_and_encode() {
        let mut rng = rand::rng();
        let mut b = [0; 320];
        let mut bb = [0; 320];

        let mut f = [0; 256];
        for i in 0..256 {
            f[i] = rng.random_range(0..Q);
        }

        compress_and_encode10(&mut b, &f);
        compress_and_encode_generic(&mut bb, &f, 10);

        assert_eq!(b, bb);
    }

    #[test]
    fn test_decode_and_decompress() {
        let mut rng = rand::rng();
        let b: [u8; 320] = rng.random();

        let mut f = [0; 256];
        let mut g = [0; 256];

        decode_and_decompress10(&mut f, &b);
        decode_and_decompress10(&mut g, &b);

        assert_eq!(f, g);
    }

    extern crate test;
    use rand::Rng;
    use test::Bencher;

    use crate::mlkem::compress_decode::compress;
    #[bench]
    fn bench_barrett(b: &mut Bencher) {
        b.iter(|| {
            // 5.13 ns
            test::black_box(compress(1234, 10));

            // test::black_box(compress_nieve::<10>(1234));
        });
    }

    #[bench]
    fn bench_compress(b: &mut Bencher) {
        const d: usize = 10;

        let mut y = 0;
        b.iter(|| {
            // 5.13 ns
            test::black_box({
                for x in 0..8 * Q {
                    y += compress_unsigned(x as u16, d);
                    y += compress(x, d);
                }
            });
        });
    }
}
