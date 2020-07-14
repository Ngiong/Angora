use angora_common::config;
//use std::ops::Deref;

pub unsafe fn get_rel_func_list(target_funcid : usize, func_rel_map : *mut usize, func_num : usize) -> Vec<u8> {
  if func_rel_map.is_null() {return vec![];}
 
  let target_index = (target_funcid * func_num + target_funcid) as isize;
  let target_run : f32 = *func_rel_map.offset(target_index) as f32;
  let mut res = vec![0u8; func_num / 8 + 1];
  let baseidx = (target_funcid * func_num) as isize;
  for i in 0..func_num {
    if (*func_rel_map.offset(baseidx + i as isize) as f32 / target_run) > config::FUNC_REL_HIGH_THRESHOLD {
      res[i/8] = res[i/8] | (1 << (i % 8));
    }
  };
  res
}
