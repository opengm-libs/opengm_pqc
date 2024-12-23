#[cfg(target_arch = "aarch64")]
use core::arch::asm;

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn tick_counter() -> u64 {

    let tick_counter: u64;
    unsafe {
        asm!(
            "mrs x0, cntvct_el0",
            out("x0") tick_counter
        );
    }
    tick_counter
}

/// Returns a frequency of tick counter in hertz (Hz)
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn frequency() -> u64 {
    let counter_frequency: u64;
    unsafe {
        asm!(
            "mrs x0, cntfrq_el0",
            out("x0") counter_frequency
        );
    }
    counter_frequency
}