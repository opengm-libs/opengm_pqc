/// Computes `a + b + carry`, returning the result along with the new carry. 64-bit version.
/// Carry = 0 or 1
#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: bool) -> (u64, bool) {
    a.carrying_add(b, carry)
}

/// Computes `a - (b + borrow)`, returning the result along with the new borrow. 64-bit version.
/// The returned borrow is 1 if a < b+borrow, 0 otherwise.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: bool) -> (u64, bool) {
    a.borrowing_sub(b, borrow)
}

/// Computes `a + (b * c) + carry`, returning the result along with the new carry.
#[inline(always)]
pub const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}
