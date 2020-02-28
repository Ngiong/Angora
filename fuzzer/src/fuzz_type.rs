use std::fmt;

#[derive(Clone, Copy)]
pub enum FuzzType {
    ExploreFuzz,
    ExploitFuzz,
    CmpFnFuzz,
    LenFuzz,
    AFLFuzz,
    OtherFuzz,
}

pub const FUZZ_TYPE_NUM: usize = FuzzType::OtherFuzz as usize + 1;
static FUZZ_TYPE_NAME: [&str; FUZZ_TYPE_NUM] =
    ["Explore", "Exploit", "CmpFn", "Len", "AFL", "Other"];

impl Default for FuzzType {
    fn default() -> Self {
        FuzzType::OtherFuzz
    }
}

impl FuzzType {
    pub fn index(&self) -> usize {
        *self as usize
    }
}

pub fn get_fuzz_type_name(i: usize) -> String {
    FUZZ_TYPE_NAME[i].to_string()
}

impl fmt::Display for FuzzType {
  fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result {
    match self {
      FuzzType::ExploreFuzz => {write!(f, "Explore")},
      FuzzType::ExploitFuzz => {write!(f, "Exploit")},
      FuzzType::CmpFnFuzz => {write!(f, "CmpFn")},
      FuzzType::LenFuzz => {write!(f, "Len")},
      FuzzType::AFLFuzz => {write!(f, "AFL")},
      FuzzType::OtherFuzz => {write!(f, "Other")},
    }
  }
}
