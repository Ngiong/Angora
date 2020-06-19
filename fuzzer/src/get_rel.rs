use angora_common::config;
use std::ops::Deref;

pub fn get_rel_func_list(target_funcid : usize, func_rel_map : &Box<[Box<[usize]>]>) -> Vec<usize> {
  if func_rel_map.len() == 0 { return vec![];}
 
  let target_run = func_rel_map[target_funcid][target_funcid];
  let mut res = vec![];
  for i in 0..func_rel_map.len() {
    if ((func_rel_map.deref()[target_funcid].deref()[i] as f32) / (target_run as f32)) > config::FUNC_REL_HIGH_THRESHOLD {
      res.push(i);
    }
  };
  res
}
