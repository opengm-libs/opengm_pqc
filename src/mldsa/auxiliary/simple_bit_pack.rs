use core::{cmp::min, iter::zip};

use crate::mldsa::rq::Rq;

#[inline]
pub(crate) fn simple_bit_pack(v: &mut [u8], w: &Rq, bitlen: usize) {
    // println!("simple_bit_pack_generic bitlen: {bitlen}");
    match bitlen {
        3 => simple_bit_pack3(v, w),
        4 => simple_bit_pack4(v, w),
        6 => simple_bit_pack6(v, w),
        10 => simple_bit_pack10(v, w),
        13 => simple_bit_pack13(v, w),
        _ => {
            // used for bit_pack, BITLEN = 18,20,43
            // debug_assert!( bitlen == 18 || bitlen == 20);
            simple_bit_pack_generic(v, w, bitlen);
        }
    }
}

#[inline]
pub(crate) fn simple_bit_unpack(w: &mut Rq, v: &[u8], bitlen: usize) {
    // println!("simple_bit_unpack_generic bitlen: {bitlen}");
    match bitlen{
        3 => simple_bit_unpack3(w, v),
        4 => simple_bit_unpack4(w, v),
        6 => simple_bit_unpack6(w, v),
        10 => simple_bit_unpack10(w, v),
        13 => simple_bit_unpack13(w, v),
        _ => {
            // used for bit_pack, BITLEN = 13,18,20
            // debug_assert!( bitlen == 18 || bitlen == 20);
            simple_bit_unpack_generic(w, v, bitlen);
        }
    }
}

// append to z the output byte string of length 32*bitlen(b).
// b in N and w in R such that coefficients of w are all in [0, b],
// NOTE: the same with byteEncode in ML-KEM
pub(crate) fn simple_bit_pack_generic(z: &mut [u8], w: &Rq, d: usize) {
    debug_assert!(z.len() >= 32 * d);

    let mut tail = 0u64;
    let mut taillen = 0;
    let mut i = 0;
    let mut zi = 0;
    while i < w.coeffs.len() {
        let n = min((64 - taillen as usize) / d, 256 - i);
        for j in 0..n {
            tail |= (w.coeffs[i + j] as u64) << taillen;
            taillen += d;
        }
        i += n;
        while taillen >= 8 {
            z[zi] = tail as u8;
            zi += 1;
            tail >>= 8;
            taillen -= 8;
        }
    }
}

// v.len() = 32 * bitlen(b)
pub(crate) fn simple_bit_unpack_generic(w: &mut Rq, v: &[u8], d: usize) {
    debug_assert!(v.len() >= 32 * d);

    let mask = (1u64 << d) - 1;

    let mut idx = 0;
    let mut tail = 0;
    let mut taillen = 0;

    for v in v[..32*d].chunks_exact(8) {
        // 0 <= taillen < d
        let b = u64::from_le_bytes(v.try_into().unwrap());

        // handle the tail
        tail = tail | (b << taillen); // only lower d bits count
        w.coeffs[idx] = (tail & mask) as i32;
        idx += 1;

        // now the left in b
        tail = b >> (d - taillen);
        taillen = 64 - (d - taillen);
        while taillen >= d {
            w.coeffs[idx] = (tail & mask) as i32;
            idx += 1;
            tail >>= d;
            taillen -= d;
        }
    }
}

// bitlen(b) = 4;
pub(crate) fn simple_bit_pack4(z: &mut [u8], w: &Rq) {
    debug_assert!(z.len() == 32 * 4);
    for (z, w) in zip(z, w.coeffs.chunks_exact(2)) {
        *z = (w[0] as u8) | ((w[1] as u8) << 4)
    }
}

// v.len() = 32 * bitlen(b)
pub(crate) fn simple_bit_unpack4(w: &mut Rq, v: &[u8]) {
    debug_assert!(v.len() >= 32 * 4);

    for (w, v) in zip(w.coeffs.chunks_exact_mut(2), v) {
        let v = *v;
        w[0] = (v & 0xf) as i32;
        w[1] = ((v >> 4) & 0xf) as i32;
    }
}

// bitlen(b) = 4;
pub(crate) fn simple_bit_pack6(v: &mut [u8], w: &Rq) {
    debug_assert!(v.len() >= 32 * 6);
    for (v, w) in zip(v.chunks_exact_mut(3), w.coeffs.chunks_exact(4)) {
        let x = (w[0] as u32) | ((w[1] as u32) << 6) | ((w[2] as u32) << 12) | ((w[3] as u32) << 18);
        v[0] = x as u8;
        v[1] = (x >> 8) as u8;
        v[2] = (x >> 16) as u8;
    }
}

// v.len() = 32 * bitlen(b)
pub(crate) fn simple_bit_unpack6(w: &mut Rq, v: &[u8]) {
    debug_assert!(v.len() >= 32 * 6);

    for (w, v) in zip(w.coeffs.chunks_exact_mut(4), v.chunks_exact(3)) {
        let x = ((v[0] as u32) | (v[1] as u32) << 8 | (v[2] as u32) << 16) as i32;
        w[0] = x & 0x3f;
        w[1] = (x >> 6) & 0x3f;
        w[2] = (x >> 12) & 0x3f;
        w[3] = (x >> 18) & 0x3f;
    }
}

// bitlen(b) = 4;
pub(crate) fn simple_bit_pack10(v: &mut [u8], w: &Rq) {
    debug_assert!(v.len() >= 32 * 10);
    for (v, w) in zip(v.chunks_exact_mut(5), w.coeffs.chunks_exact(4)) {
        let x = (w[0] as u64) | ((w[1] as u64) << 10) | ((w[2] as u64) << 20) | ((w[3] as u64) << 30);
        v[0] = x as u8;
        v[1] = (x >> 8) as u8;
        v[2] = (x >> 16) as u8;
        v[3] = (x >> 24) as u8;
        v[4] = (x >> 32) as u8;
    }
}

// v.len() = 32 * bitlen(b)
pub(crate) fn simple_bit_unpack10(w: &mut Rq, v: &[u8]) {
    debug_assert!(v.len() >= 32 * 10);

    for (w, v) in zip(w.coeffs.chunks_exact_mut(4), v.chunks_exact(5)) {
        let x = (v[0] as u64) | (v[1] as u64) << 8 | (v[2] as u64) << 16 | (v[3] as u64) << 24 | (v[4] as u64) << 32;
        w[0] = (x & 0x3ff) as i32;
        w[1] = ((x >> 10) & 0x3ff) as i32;
        w[2] = ((x >> 20) & 0x3ff) as i32;
        w[3] = ((x >> 30) & 0x3ff) as i32;
    }
}

// bitlen(b) = 4;
pub(crate) fn simple_bit_pack3(v: &mut [u8], w: &Rq) {
    debug_assert!(v.len() >= 32 * 3);
    for (v, w) in zip(v.chunks_exact_mut(3), w.coeffs.chunks_exact(8)) {
        let x = (w[0] as u64)
            | ((w[1] as u64) << 3)
            | ((w[2] as u64) << 6)
            | ((w[3] as u64) << 9)
            | ((w[4] as u64) << 12)
            | ((w[5] as u64) << 15)
            | ((w[6] as u64) << 18)
            | ((w[7] as u64) << 21);
        v[0] = x as u8;
        v[1] = (x >> 8) as u8;
        v[2] = (x >> 16) as u8;
    }
}

// v.len() = 32 * bitlen(b)
pub(crate) fn simple_bit_unpack3(w: &mut Rq, v: &[u8]) {
    debug_assert!(v.len() >= 32 * 3);

    for (w, v) in zip(w.coeffs.chunks_exact_mut(8), v.chunks_exact(3)) {
        let x = (v[0] as u32) | (v[1] as u32) << 8 | (v[2] as u32) << 16;
        w[0] = (x & 0x7) as i32;
        w[1] = ((x >> 3) & 0x7) as i32;
        w[2] = ((x >> 6) & 0x7) as i32;
        w[3] = ((x >> 9) & 0x7) as i32;
        w[4] = ((x >> 12) & 0x7) as i32;
        w[5] = ((x >> 15) & 0x7) as i32;
        w[6] = ((x >> 18) & 0x7) as i32;
        w[7] = ((x >> 21) & 0x7) as i32;
    }
}

// bitlen(b) = 4;
pub(crate) fn simple_bit_pack13(v: &mut [u8], w: &Rq) {
    debug_assert!(v.len() >= 32 * 13);
    for (v, w) in zip(v.chunks_exact_mut(13), w.coeffs.chunks_exact(8)) {
        let x = (w[0] as u64) | ((w[1] as u64) << 13) | ((w[2] as u64) << 26) | ((w[3] as u64) << 39);
        v[0] = x as u8;
        v[1] = (x >> 8) as u8;
        v[2] = (x >> 16) as u8;
        v[3] = (x >> 24) as u8;
        v[4] = (x >> 32) as u8;
        v[5] = (x >> 40) as u8;
        let y =
            (x >> 48) | ((w[4] as u64) << 4) | ((w[5] as u64) << 17) | ((w[6] as u64) << 30) | ((w[7] as u64) << 43);
        v[6] = y as u8;
        v[7] = (y >> 8) as u8;
        v[8] = (y >> 16) as u8;
        v[9] = (y >> 24) as u8;
        v[10] = (y >> 32) as u8;
        v[11] = (y >> 40) as u8;
        v[12] = (y >> 48) as u8;
    }
}

// v.len() = 32 * bitlen(b)
pub(crate) fn simple_bit_unpack13(w: &mut Rq, v: &[u8]) {
    debug_assert!(v.len() >= 32 * 13);

    for (w, v) in zip(w.coeffs.chunks_exact_mut(8), v.chunks_exact(13)) {
        let x = u64::from_le_bytes((&v[..8]).try_into().unwrap());
        let y = (u32::from_le_bytes((&v[8..12]).try_into().unwrap()) as u64) | ((v[12] as u64) << 32);
        w[0] = (x & 0x1fff) as i32;
        w[1] = ((x >> 13) & 0x1fff) as i32;
        w[2] = ((x >> 26) & 0x1fff) as i32;
        w[3] = ((x >> 39) & 0x1fff) as i32;

        let y = (y << 12) | ( (x>>52) & 0xfff);
        w[4] = ((y >> 0) & 0x1fff) as i32;
        w[5] = ((y >> 13) & 0x1fff) as i32;
        w[6] = ((y >> 26) & 0x1fff) as i32;
        w[7] = ((y >> 39) & 0x1fff) as i32;
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use crate::mldsa::{auxiliary::simple_bit_pack::simple_bit_unpack, rq::Rq};

    use super::simple_bit_pack;

    #[test]
    fn test_simple_bit_pack() {
        let mut rng = rand::rng();
        const b: usize = 13;

        let mut f = Rq::default();
        let mut g = Rq::default();
        for i in 0..f.coeffs.len() {
            f[i] = rng.random_range(0..(1i32 << b) - 1);
        }

        let mut z = [0; 32 * b];

        simple_bit_pack(&mut z, &f, b);
        simple_bit_unpack(&mut g, &z,b);

        assert_eq!(f, g);
    }
}
