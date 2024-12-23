pub mod uint192;
pub mod u64_arith;
pub mod primitive;
pub mod prime;


pub trait GetMSBCount {
    /// returns how many bits self takes
    fn get_msb_count(self)-> u32;
}

impl GetMSBCount for u64{
    #[inline]
    fn get_msb_count(self)-> u32 {
        64 - self.leading_zeros()
    }
}

impl GetMSBCount for &u64{
    #[inline]
    fn get_msb_count(self)-> u32 {
        (*self).get_msb_count()
    }
}
impl GetMSBCount for &[u64]{
    fn get_msb_count(self)-> u32{
        for (i,v) in self.iter().enumerate().rev(){
            if *v != 0{
                return i as u32*64 + v.get_msb_count();
            }
        }
        0
    }
}

#[test]
fn test_get_msb_count() {
    assert_eq!(0.get_msb_count(), 0);
    assert_eq!(1.get_msb_count(), 1);
    assert_eq!(7.get_msb_count(), 3);
    assert_eq!([0,0,0].get_msb_count(), 0);
    assert_eq!([1,0,0].get_msb_count(), 1);
    assert_eq!([0,1,0].get_msb_count(), 65);
    assert_eq!([0,0,1].get_msb_count(), 129);
}
