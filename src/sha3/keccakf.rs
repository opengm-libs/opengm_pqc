
#[inline]
pub(crate) fn keccak_f1600(a: &mut [u64; 25]) {
    keccak_f1600_generic(a);
}


/*
rho shifts after pi:

25 39  3 10 43         8 18  1  6 25
55 20 36 44  6   pi   45 61 28 20  3
28 27  0  1 62  --->  21 14  0 44 43
56 14 18  2 61        41  2 62 55 39
21  8 41 45 15        15 56 27 36 10
*/
const rho :[u32; 25] = [ 
    0,  44, 43, 21, 14,  
    28, 20,  3, 45, 61, 
    1,  6,  25,  8, 18,  
    27, 36, 10, 15, 56, 
    62, 55, 39, 41,  2, 
];



/*
Keccak permutation round.
13 14 10 11 12     19 20  1  7 13      13 19 20  1  7
8  9  5  6  7  pi  16 22  3  9 10  ad.  3  9 10 16 22  <- adjusts to align
3  4  0  1  2  =>  18 24  0  6 12  =>  18 24  0  6 12
23 24 20 21 22     15 21  2  8 14       8 14 15 21  2
18 19 15 16 17     17 23  4  5 11      23  4  5 11 17


Note the order of the states a will change after the permutation, and repeats every 4 rounds:
13 14 10 11 12       13 19 20  1  7      13  4 15  6 22      13 24  5 16  2
 8  9  5  6  7  rd.   3  9 10 16 22      18  9 20 11  2      23  9 15  1 12
 3  4  0  1  2  =>   18 24  0  6 12  =>  23 14  0 16  7  =>   8 19  0 11 22  =>
23 24 20 21 22        8 14 15 21  2       3 19  5 21 12      18  4 10 21  7
18 19 15 16 17       23  4  5 11 17       8 24 10  1 17       3 14 20  6 17

13 14 10 11 12 
 8  9  5  6  7 
 3  4  0  1  2  => ...
23 24 20 21 22 
18 19 15 16 17 
*/
#[rustfmt::skip]
macro_rules! round {
    (
        $a13:expr, $a14:expr, $a10:expr, $a11:expr, $a12:expr,
        $a8:expr,  $a9:expr,  $a5:expr,  $a6:expr,  $a7:expr,
        $a3:expr,  $a4:expr,  $a0:expr,  $a1:expr,  $a2:expr,
        $a23:expr, $a24:expr, $a20:expr, $a21:expr, $a22:expr,
        $a18:expr, $a19:expr, $a15:expr, $a16:expr, $a17:expr,
        $rci:expr,
     ) => {{
        let mut bc0 = $a0 ^ $a5 ^ $a10 ^ $a15 ^ $a20;
        let mut bc1 = $a1 ^ $a6 ^ $a11 ^ $a16 ^ $a21;
        let mut bc2 = $a2 ^ $a7 ^ $a12 ^ $a17 ^ $a22;
        let mut bc3 = $a3 ^ $a8 ^ $a13 ^ $a18 ^ $a23;
        let mut bc4 = $a4 ^ $a9 ^ $a14 ^ $a19 ^ $a24;
        let d0 = bc4 ^ bc1.rotate_left(1);
        let d1 = bc0 ^ bc2.rotate_left(1);
        let d2 = bc1 ^ bc3.rotate_left(1);
        let d3 = bc2 ^ bc4.rotate_left(1);
        let d4 = bc3 ^ bc0.rotate_left(1);

        bc0 = ($a0 ^ d0).rotate_left(rho[0]);
        bc1 = ($a6 ^ d1).rotate_left(rho[1]);
        bc2 = ($a12 ^ d2).rotate_left(rho[2]);
        bc3 = ($a18 ^ d3).rotate_left(rho[3]);
        bc4 = ($a24 ^ d4).rotate_left(rho[4]);

        $a0 = bc0 ^ (bc2 & !bc1) ^ $rci;
        $a6 = bc1 ^ (bc3 & !bc2);
        $a12 = bc2 ^ (bc4 & !bc3);
        $a18 = bc3 ^ (bc0 & !bc4);
        $a24 = bc4 ^ (bc1 & !bc0);

        bc0 = ($a3 ^ d3).rotate_left(rho[5]);
        bc1 = ($a9 ^ d4).rotate_left(rho[6]);
        bc2 = ($a10 ^ d0).rotate_left(rho[7]);
        bc3 = ($a16 ^ d1).rotate_left(rho[8]);
        bc4 = ($a22 ^ d2).rotate_left(rho[9]);
        $a10 = bc0 ^ (bc2 & !bc1);
        $a16 = bc1 ^ (bc3 & !bc2);
        $a22 = bc2 ^ (bc4 & !bc3);
        $a3 = bc3 ^ (bc0 & !bc4);
        $a9 = bc4 ^ (bc1 & !bc0);

        bc0 = ($a1 ^ d1).rotate_left(rho[10]);
        bc1 = ($a7 ^ d2).rotate_left(rho[11]);
        bc2 = ($a13 ^ d3).rotate_left(rho[12]);
        bc3 = ($a19 ^ d4).rotate_left(rho[13]);
        bc4 = ($a20 ^ d0).rotate_left(rho[14]);
        $a20 = bc0 ^ (bc2 & !bc1);
        $a1 = bc1 ^ (bc3 & !bc2);
        $a7 = bc2 ^ (bc4 & !bc3);
        $a13 = bc3 ^ (bc0 & !bc4);
        $a19 = bc4 ^ (bc1 & !bc0);

        bc0 = ($a4 ^ d4).rotate_left(rho[15]);
        bc1 = ($a5 ^ d0).rotate_left(rho[16]);
        bc2 = ($a11 ^ d1).rotate_left(rho[17]);
        bc3 = ($a17 ^ d2).rotate_left(rho[18]);
        bc4 = ($a23 ^ d3).rotate_left(rho[19]);
        $a5 = bc0 ^ (bc2 & !bc1);
        $a11 = bc1 ^ (bc3 & !bc2);
        $a17 = bc2 ^ (bc4 & !bc3);
        $a23 = bc3 ^ (bc0 & !bc4);
        $a4 = bc4 ^ (bc1 & !bc0);

        bc0 = ($a2 ^ d2).rotate_left(rho[20]);
        bc1 = ($a8 ^ d3).rotate_left(rho[21]);
        bc2 = ($a14 ^ d4).rotate_left(rho[22]);
        bc3 = ($a15 ^ d0).rotate_left(rho[23]);
        bc4 = ($a21 ^ d1).rotate_left(rho[24]);
        $a15 = bc0 ^ (bc2 & !bc1);
        $a21 = bc1 ^ (bc3 & !bc2);
        $a2 = bc2 ^ (bc4 & !bc3);
        $a8 = bc3 ^ (bc0 & !bc4);
        $a14 = bc4 ^ (bc1 & !bc0);
    }};
}


//The round constants in the l(iota) step.
const rc: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];



// keccak_f1600_generic applies the Keccak permutation.
#[rustfmt::skip]
#[inline]
pub(crate) fn keccak_f1600_generic(a: &mut [u64; 25]) {
    let mut i = 0;

    while i < 24 {
        round!(
            a[13], a[14], a[10], a[11], a[12],
            a[ 8], a[ 9], a[ 5], a[ 6], a[ 7],
            a[ 3], a[ 4], a[ 0], a[ 1], a[ 2],
            a[23], a[24], a[20], a[21], a[22],
            a[18], a[19], a[15], a[16], a[17],
            rc[i],
        );

        round!(
            a[13], a[19], a[20], a[ 1], a[ 7], 
            a[ 3], a[ 9], a[10], a[16], a[22], 
            a[18], a[24], a[ 0], a[ 6], a[12], 
            a[ 8], a[14], a[15], a[21], a[ 2], 
            a[23], a[ 4], a[ 5], a[11], a[17], 
            rc[i+1],
        );
       
        round!(
            a[13], a[ 4], a[15], a[ 6], a[22], 
            a[18], a[ 9], a[20], a[11], a[ 2], 
            a[23], a[14], a[ 0], a[16], a[ 7], 
            a[ 3], a[19], a[ 5], a[21], a[12], 
            a[ 8], a[24], a[10], a[ 1], a[17], 
            rc[i+2],
        );
        
        round!(
            a[13], a[24], a[ 5], a[16], a[ 2], 
            a[23], a[ 9], a[15], a[ 1], a[12], 
            a[ 8], a[19], a[ 0], a[11], a[22], 
            a[18], a[ 4], a[10], a[21], a[ 7], 
            a[ 3], a[14], a[20], a[ 6], a[17], 
            rc[i+3],
        );

        i += 4;
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_f1600() {
        #[rustfmt::skip] 
        let mut a = [
            0xcd25c9aa9c22d1e6, 0x5d2815e979da73fa, 0x1e746c8cfd54a79a, 0xf849ba2f516492d3, 0x7b6ef1e35fffa9bf,
            0xff12997dbf1b6c66, 0xdb498a1113513789, 0x94689cca0c63613a, 0xa084aff53c74f579, 0x42996c6cf5f52f11,
            0x15d8acef879b9c81, 0x44a325fa72215e5f, 0x7bcdb855a6a2ef26, 0x9189e554c243651b, 0x38c6b646d0499345,
            0x5dd24b659828953a, 0x2a36e7979983d093, 0x6b8b06d64b50acb1, 0x0ca1c056f544b689, 0xb82360c9f02ccb50,
            0x2c2c187e8f8dbebc, 0x8f6ea3e166241d5f, 0xec2f5316c8e1e7f1, 0x04238fa15328bd6c, 0x540846b170a6caab];

        #[rustfmt::skip] 
        let expect = [
            0xd1a01f52115bd04e, 0x1852aaa3595f4965, 0x6711075ed42c8d51, 0xe5179d1e6860aaed, 0x7289039971e84c20,
            0x1b1837777868cc6a, 0xed130bf6fad9cee6, 0xb294bb3610a842b7, 0x2c5ce0512f0b41b1, 0xb4c2c2bd74d2f083,
            0xdd705016436e7aa6, 0xbf56bd811bd7a163, 0xdf0a3f5951f76147, 0xdbe4447f6a0fde54, 0xcd633fe862fd91ad,
            0xb632d3bc4aba1f1f, 0x570cb1205d6ece1f, 0x4dfcbbb8e1365098, 0x0ac0bc60706647ff, 0x448ad600736fe26d,
            0x54dad331bd86439e, 0xd0adec8d1e445830, 0xa5ec13798e8ebefc, 0xdabe5557d7a810d6, 0x0bf35b673accb38b];

        keccak_f1600_generic(&mut a);

        assert_eq!(a, expect);
    }
}
