use core::{
    iter::zip,
    ops::{Index, IndexMut},
};

use super::{auxiliary::*, reduce::{mod_q, mods_q, mont_mul}, N, Q};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rq {
    pub(crate) coeffs: [i32; N],
}

impl Default for Rq {
    fn default() -> Self {
        Self { coeffs: [0; N] }
    }
}

impl Index<usize> for Rq {
    type Output = i32;

    fn index(&self, index: usize) -> &Self::Output {
        return &self.coeffs[index];
    }
}
impl IndexMut<usize> for Rq {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        return &mut self.coeffs[index];
    }
}

impl Rq {
    #[inline]
    pub(crate) fn bytes(&self) -> [u8; 512] {
        let mut b = [0; 512];
        self.bytes_inplace(&mut b);
        b
    }

    #[inline]
    pub(crate) fn bytes_inplace(&self, b: &mut [u8; 256 * 2]) {
        b.copy_from_slice(unsafe { self.coeffs.align_to::<u8>().1 });
    }

    #[inline]
    pub(crate) fn new_from_bytes(b: &[u8; 256 * 2]) -> Self {
        let mut f = Rq::default();
        f.coeffs.copy_from_slice(unsafe { b.align_to::<i32>().1 });
        f
    }

    #[inline]
    pub(crate) fn from_bytes(&mut self, b: &[u8; 256 * 2]) {
        self.coeffs.copy_from_slice(unsafe { b.align_to::<i32>().1 });
    }

    // pub fn ntt(&mut self) {
    //     ntt(&mut self.coeffs);
    // }

    // pub fn ntt_inverse(&mut self) {
    //     ntt_inverse(&mut self.coeffs);
    // }

    pub fn add_assign(&mut self, rhs: &Self) {
        for (x, y) in zip(&mut self.coeffs, rhs.coeffs) {
            *x += y;
        }
    }

    pub fn add(&mut self,lhs: &Self, rhs: &Self) {
        for (z, (x, y)) in zip(&mut self.coeffs, zip(lhs.coeffs, rhs.coeffs)) {
            *z = x + y;
        }
    }

    pub fn sub_assign(&mut self, rhs: &Self) {
        for (x, y) in zip(&mut self.coeffs, rhs.coeffs) {
            *x -= y;
        }
    }

    pub fn sub(&mut self, lhs: &Self, rhs: &Self) {
        for (z, (x, y)) in zip(&mut self.coeffs, zip(lhs.coeffs, rhs.coeffs)) {
            *z = x - y;
        }
    }

    // Notes for the NTT and NTT inverse.
    // To compute NTT^-1( NTT(a) * NTT(b)), a, b in Rq,
    // we DO NOT need to transform a,b to Montgomery domain first and
    // transform back after NTT^-1. For the resons:
    // 1. The zetas are multiplied 2^32 mod q, thus we use montMul(z,.) in NTT
    //    just canceled the 2^32.
    // 2. The coefficients of NTT(a) * NTT(b) is montMul(ai, bi) = ai * bi / 2^32 mod q.
    // 3. The last for loop in NTT^-1, instead of (Montgomery) multiply 256^-1 mod q,
    //    we (Montgomery) multiply 2^64*256^-1 mod q, thus the result of NTT^-1
    //    cancelled the (2^32)^-1. We just got the wanted result( not in the Montgomery domain).
    // The Montgomery factors are precomputed in zetas and the 2^64*256^-1 mod q.

    // Do the NTT use montMul.
    // Assume f has inf norm < 2q, in Mont domain
    // The out f has inf norm < 8*2q = 16q < 2^31*q
    pub fn ntt(&mut self) {
        let coeff = &mut self.coeffs;

        let mut m = 0;
        let mut length = 128;
        while length >= 1 {
            let mut start = 0;
            while start < 256 {
                m += 1;
                let z: i32 = zetasMont[m];
                for j in start..start + length {
                    // z = zeta_i * 2^32, the montMul canceled the 2^32.
                    let t = mont_mul(z, coeff[j + length]);
                    coeff[j + length] = coeff[j] - t;
                    coeff[j] = coeff[j] + t;
                }
                start += 2 * length
            }
            length >>= 1
        }
    }

    // (s.ntt().mul(t.ntt()).ntt_inverse() = s * t
    pub(crate) fn ntt_inverse(&mut self) {
        let coeff = &mut self.coeffs;

        let mut m = 256;
        let mut length = 1;
        while length < 256 {
            let mut start = 0;
            while start < 256 {
                m -= 1;
                let zeta = Q-zetasMont[m];
                for j in start..start + length {
                    let t = coeff[j];
                    coeff[j] = t + coeff[j + length];
                    coeff[j + length] = t - coeff[j + length];
                    coeff[j + length] = mont_mul(zeta, coeff[j + length]);
                }
                start += 2 * length
            }
            length <<= 1
        }

        // Instead of mul 256^-1 mod q, we mul 41978 = 2^64/256 mod q.
        for c in coeff {
            *c = mont_mul(*c, 41978);
        }
    }

    // s.ntt().ntt_inverse_raw() = s
    pub(crate) fn ntt_inverse_raw(&mut self) {
        let coeff = &mut self.coeffs;

        let mut m = 256;
        let mut length = 1;
        while length < 256 {
            let mut start = 0;
            while start < 256 {
                m -= 1;
                let zeta = Q-zetasMont[m];
                for j in start..start + length {
                    let t = coeff[j];
                    coeff[j] = t + coeff[j + length];
                    coeff[j + length] = t - coeff[j + length];
                    coeff[j + length] = mont_mul(zeta, coeff[j + length]);
                }
                start += 2 * length
            }
            length <<= 1
        }

        // Instead of mul 256^-1 mod q, we mul 41978 = 2^32/256 mod q.
        for c in coeff {
            *c = mont_mul(*c, 16382);
        }
    }

    // self = self * rhs / R
    pub(crate) fn mul_assign(&mut self, rhs: &Rq) {
        for (a, b) in zip(&mut self.coeffs, rhs.coeffs) {
            *a = mont_mul(*a, b);
        }
    }

    // self = lhs * rhs / R
    pub(crate) fn mul(&mut self, lhs: &Rq, rhs: &Rq) {
        for i in 0..N {
            self.coeffs[i] = mont_mul(lhs.coeffs[i], rhs.coeffs[i]);
        }
    }

    // f += g * h for f != g,h
    pub(crate) fn add_mul(&mut self, g: &Rq, h: &Rq) {
        for (f, (g, h)) in zip(&mut self.coeffs, zip(g.coeffs, h.coeffs)) {
            *f += mont_mul(g, h);
        }
    }

    // reduce any i16 to [0,q)
    // pub fn reduce(&mut self) {
    //     for i in 0..self.coeffs.len() {
    //         self.coeffs[i] = reduce_to_positive(reduce_i16(self.coeffs[i]));
    //     }
    // }

    // The reduce functions.

    // reduce to [0,q) with |self| < nq
    // max(n) is 8.
    // pub fn reduce_once<const n: usize>(&mut self) {
    //     for i in 0..self.coeffs.len() {
    //         for _ in 0..n {
    //             self.coeffs[i] = reduce_once(self.coeffs[i]);
    //         }
    //     }
    // }

    // pub fn reduce_q(&mut self) {
    //     for i in 0..self.coeffs.len() {
    //         self.coeffs[i] = reduce_i16(self.coeffs[i]);
    //     }
    // }

    // pub fn reduce_to_positive(&mut self) {
    //     for i in 0..self.coeffs.len() {
    //         self.coeffs[i] = reduce_to_positive(self.coeffs[i]);
    //     }
    // }

    // f += w dot v
    pub(crate) fn add_dot_mul<const k: usize>(&mut self, w: &[Rq; k], v: &[Rq; k]) {
        for i in 0..k {
            self.add_mul(&w[i], &v[i])
        }
    }

    // f = w dot v
    pub(crate) fn dot_mul<const k: usize>(&mut self, w: &[Rq; k], v: &[Rq; k]) {
        self.mul(&w[0], &v[0]);
        for i in 1..k {
            self.add_mul(&w[i], &v[i]);
        }
    }

    #[inline]
    pub(crate) fn to_low_bits<const gamma2: usize>(&mut self) {
        for i in 0..N {
            self.coeffs[i] = low_bits::<gamma2>(self.coeffs[i])
        }
    }

    #[inline]
    pub(crate) fn low_bits<const gamma2: usize>(&self) -> Self {
        let mut res = Rq::default();
        for i in 0..N {
            res.coeffs[i] = low_bits::<gamma2>(self.coeffs[i])
        }
        res
    }

    // reduce the coeffs to [0,q)
    pub(crate) fn mod_q(&mut self) {
        for c in &mut self.coeffs{
            *c = mod_q(*c);
        }
        
    }

    // reduce the coeffs to [-(q-1)/2, (q-1)/2]
    pub(crate) fn mods_q(&mut self) {
        for c in &mut self.coeffs{
            *c = mods_q(*c);
        }
    }

    // returns the maximum coeff of self: |self|_inf
    // assume self is mods_q, i.e., the coeffs in range [-(q-1)/2, (q-1)/2]
    pub(crate) fn norm(&self) -> i32 {
        let mut m = 0;
        for c in self.coeffs{
            if c.abs() > m{
                m = c.abs();
            }
        }
        m
    }
}

// zetasMont[i] = zeta^BitRev8(i) * 2^32 mod q in Montgomery domain
const zetasMont: [i32; 256] = [
    0, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468, 1826347, 2353451, 8021166, 6288512, 3119733, 5495562,
    3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868, 6262231, 4520680,
    6980856, 5102745, 1757237, 8360995, 4010497, 280005, 2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901,
    3915439, 4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150, 6736599, 3505694,
    4558682, 3507263, 6239768, 6779997, 3699596, 811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196, 7122806, 1939314, 4296819, 7380215,
    5190273, 5223087, 4747489, 126922, 3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370, 7709315,
    7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987, 5037034, 264944, 508951, 3097992, 44288, 7280319,
    904516, 3958618, 4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561, 189548, 4827145, 3159746,
    6529015, 5971092, 8202977, 1315589, 1341330, 1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448,
    3839961, 2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955, 266997, 2434439, 7144689, 3513181,
    4860065, 4621053, 7183191, 5187039, 900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917, 7725090,
    5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579, 342297, 286988, 5942594, 4108315, 3437287, 5038140,
    1735879, 203044, 2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974, 4613401, 1250494, 2635921,
    4832145, 5386378, 1869119, 1903435, 7329447, 7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115,
    6417775, 7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241, 6533464,
    5796124, 4656147, 594136, 4603424, 6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531, 7173032, 5196991,
    162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310, 5341501, 3523897, 3866901, 269760, 2213111, 7404533,
    1717735, 472078, 7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524, 5441381, 6144432, 7959518,
    6094090, 183443, 7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782,
];
