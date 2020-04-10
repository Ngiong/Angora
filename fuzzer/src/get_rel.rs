
use std::collections::HashSet;
use angora_common::config;


pub fn get_rel_func_list(target_cmpid : u32, func_cmp_map : &Vec<Vec<u32>>, func_rel_map : &Vec<Vec<u32>>) -> Vec<usize> {
  if func_rel_map.len() ==0 {return vec![];}
  let mut cur_func = 0;
  for (i,f) in func_cmp_map.iter().enumerate() {
    if f.contains(&target_cmpid) { cur_func = i; break; }
  }
  
  let rels = &func_rel_map[cur_func];
  let target_run = rels[cur_func];
  let mut res = vec![];
  for (i, v) in rels.iter().enumerate() {
    if ((*v as f32) / (target_run as f32)) > config::FUNC_REL_HIGH_THRESHOLD {
      res.push(i);
    }
  };
  res
}

pub fn get_rel_cmp_set(target_cmpid : u32, func_cmp_map : &Vec<Vec<u32>>, func_rel_map : &Vec<Vec<u32>>) -> HashSet<u32> {
  if func_rel_map.len() == 0 {return HashSet::new()};
  let rel_list = get_rel_func_list(target_cmpid, func_cmp_map, func_rel_map);
  let mut res = HashSet::new();

  for rel_func in rel_list {
    for c in &func_cmp_map[rel_func] {
      res.insert(*c);
    }
  } 
  res
}
