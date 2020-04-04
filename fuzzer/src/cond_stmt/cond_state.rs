use crate::{cond_stmt::CondStmt, mut_input::offsets::*, stats};
use runtime::logger::get_log_data;
use std::fmt;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use std::path::{Path, PathBuf};
use crate::depot::Depot;
use angora_common::{config, defs, tag::TagSeg};
use rand::{thread_rng, Rng};
use std;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondState {
    Offset,
    OffsetOpt,
    OffsetAll,
    OffsetAllEnd,
    OffsetFunc,
    OffsetRelFunc,

    OneByte,
    Unsolvable,
    Deterministic,
    Timeout,
}

impl Default for CondState {
    fn default() -> Self {
        CondState::Offset
    }
}

impl CondStmt {
    pub fn is_time_expired(&self) -> bool {
      if (self.state.is_det() || self.state.is_one_byte()) && !self.is_first_time() { true } else {
        match self.state {
          CondState::Offset => { self.cur_state_fuzz_times >= config::STATE_LONG_FUZZ_TIME[0] },
          CondState::OffsetOpt => { self.cur_state_fuzz_times >= config::STATE_LONG_FUZZ_TIME[1] },
          CondState::OffsetAll => { self.cur_state_fuzz_times >= config::STATE_LONG_FUZZ_TIME[2] },
          CondState::OffsetFunc => { self.cur_state_fuzz_times >= config::STATE_LONG_FUZZ_TIME[3] },
          _ => {false}  //onebyte,unsolvable,timeout,offsetallend
        }
      }
    }
}

impl CondState {
    pub fn is_initial(&self) -> bool {
        self == &Default::default() || self.is_one_byte()
    }

    pub fn is_det(&self) -> bool {
        match self {
            CondState::Deterministic => true,
            _ => false,
        }
    }

    pub fn is_one_byte(&self) -> bool {
        match self {
            CondState::OneByte => true,
            _ => false,
        }
    }

    pub fn is_end(&self) -> bool {
        match self {
           CondState::OffsetAllEnd => true,
           _ => false,
        }
    }

    pub fn is_unsolvable(&self) -> bool {
        match self {
            CondState::Unsolvable => true,
            _ => false,
        }
    }

    pub fn is_timeout(&self) -> bool {
        match self {
            CondState::Timeout => true,
            _ => false,
        }
    }
}

impl fmt::Display for CondState {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
    match self {
      CondState::Offset => { write!(f, "Offset")},
      CondState::OffsetOpt => {write!(f, "OffsetOpt")},
      CondState::OffsetAll => {write!(f, "OffsetAll")},
      CondState::OffsetAllEnd => {write!(f, "OffsetAllEnd")},
      CondState::OffsetFunc => {write!(f, "OffsetFunc")},
      CondState::OffsetRelFunc => {write!(f, "OffsetRelFunc")}, 
      CondState::OneByte => {write!(f, "OneByte")},
      CondState::Unsolvable => {write!(f, "Unsolvable")},
      CondState::Deterministic => {write!(f, "Det")},
      CondState::Timeout => {write!(f, "Timeout")},
    }
  }
}

pub trait NextState {
    fn next_state(&mut self, depot : &Arc<Depot>, local_stat : &mut stats::LocalStats, taint_dir : &PathBuf,
                    func_cmp_map : &HashMap<u32, Vec<u32>>,
                    func_rel_map : &HashMap<u32, HashMap<u32, u32>>);
    fn to_offsets_opt(&mut self);
    fn to_offsets_all(&mut self);
    fn to_offsets_all_end(&mut self);
    fn to_det(&mut self);
    fn to_offsets_func(&mut self,depot : &Arc<Depot>, local_stats : &mut stats::LocalStats, taint_dir : &PathBuf, func_cmp_map : &HashMap<u32, Vec<u32>>);
    fn to_offsets_rel_func(&mut self, depot : &Arc<Depot>,
                                      local_stats : &mut stats::LocalStats,
                                      taint_dir : &PathBuf,
                                      func_cmp_map : &HashMap<u32, Vec<u32>>,
                                      func_rel_map : &HashMap<u32, HashMap<u32, u32>>);
    fn to_unsolvable(&mut self);
    fn to_timeout(&mut self);
    fn get_random_offsets( input_len : u32, extend_len : u32) -> Vec<TagSeg>; 
}

impl NextState for CondStmt {
    fn next_state(&mut self, depot : &Arc<Depot>,
                             local_stats : &mut stats::LocalStats,
                             taint_dir : &PathBuf,
                             func_cmp_map : &HashMap<u32, Vec<u32>>,
                             func_rel_map : &HashMap<u32, HashMap<u32, u32>>) {
        self.cur_state_fuzz_times = 0;
        match self.state {
            CondState::Offset => {
                if self.offsets_opt.len() > 0 {
                    self.to_offsets_opt();
                } else {
                    self.to_det();
                }
            },
            CondState::OneByte => {
                if self.offsets_opt.len() > 0 {
                    self.to_offsets_opt();
                } else {
                    self.to_offsets_func(depot, local_stats, taint_dir, func_cmp_map);
                   //self.to_unsolvable();
                }
            },
            CondState::OffsetOpt => {
                self.to_offsets_all();
            },
            CondState::OffsetAll => {
                self.to_det();
            },
            CondState::Deterministic => {
                self.to_offsets_func(depot, local_stats, taint_dir, func_cmp_map);
            },
            CondState::OffsetFunc => {
                  self.to_offsets_rel_func(depot, local_stats, taint_dir, func_cmp_map, func_rel_map);
            },
            _ => {},
        }
    }

    fn to_offsets_opt(&mut self) {
        self.state = CondState::OffsetOpt;
        std::mem::swap(&mut self.offsets, &mut self.offsets_opt);
    }

    fn to_offsets_all(&mut self) {
        self.state = CondState::OffsetAll;
        self.offsets = merge_offsets(&self.offsets, &self.offsets_opt);
    }

    fn to_det(&mut self) {
        self.state = CondState::Deterministic;
    }

    fn to_offsets_all_end(&mut self) {
        debug!("to_all_end");
        self.state = CondState::OffsetAllEnd;
    }

    fn get_random_offsets(input_len : u32, extend_len : u32) -> Vec<TagSeg> {
      let sel_prob : f32 = (input_len as f32 ) / (extend_len as f32);
      let mut selected = vec![];
      let mut rng = thread_rng();
      for i in 0..input_len  {
        let x : f32 = rng.gen();
        if x < sel_prob {
          selected.push(TagSeg {sign : false, begin : i, end : i + 1});
        }
      }
      selected
    }
    
    fn to_offsets_func(&mut self, depot : &Arc<Depot>, local_stats : &mut stats::LocalStats, taint_dir : &PathBuf, func_cmp_map : &HashMap<u32, Vec<u32>>) {
        let before_size = self.get_offset_len() + self.get_offset_opt_len();
        let start_time = Instant::now();
        self.state = CondState::OffsetFunc;
        if func_cmp_map.len() == 0 { return; }
        let mut cmp_list : Vec<u32> = Vec::new();
        //get the list of cmps in the same function
        for (_k, v) in func_cmp_map {
          if v.contains(&self.base.cmpid) { cmp_list = v.clone(); break; }
        }
        let taint_file_path = taint_dir.clone().join(format!("taints_{}", self.base.belong));
        let taint_file = Path::new(&taint_file_path);
        let log_data = match get_log_data(taint_file) {
          Ok(s) => {s},
          Err(_) => {panic!("Can't get log data : cmpid : {}, belong: {}", self.base.cmpid, self.base.belong)},
        };
        let mut new_offsets = vec![];
        let mut lb_set = HashSet::new();
        for cond_base in log_data.cond_list.iter() {
          if cmp_list.contains(&cond_base.cmpid) {
            lb_set.insert(cond_base.lb1);
            lb_set.insert(cond_base.lb2);
          }
        };
        for lb in lb_set {
          match &log_data.tags.get(&lb) {
            Some(o) => {
              new_offsets = merge_offsets(&new_offsets,&o);
            },
            None => {},
          };
        };
        if config::FUNC_REL_RANDOM {
          let extend_len = offset_len(&new_offsets) - before_size;
          let input_len = depot.get_input_buf(self.base.belong as usize).len() as u32;
          let new_random_offset = Self::get_random_offsets(input_len, extend_len);
          self.offsets = merge_offsets(&self.offsets, &new_random_offset);
        } else {
          self.offsets = new_offsets;
        }
        self.ext_offset_size = self.get_offset_len() + self.get_offset_opt_len() - before_size;
        local_stats.func_time += start_time.elapsed().into();
    }
 
    fn to_offsets_rel_func(&mut self, depot : &Arc<Depot>,
                                      local_stats : &mut stats::LocalStats,
                                      taint_dir : &PathBuf,
                                      func_cmp_map : &HashMap<u32, Vec<u32>>,
                                      func_rel_map : &HashMap<u32, HashMap<u32, u32>>){
        let before_size = self.get_offset_len() + self.get_offset_opt_len();
        let start_time = Instant::now();
        if func_cmp_map.len() == 0 {return ;}
        let mut cmp_list : Vec<u32> = Vec::new();
        let mut cmp_func : u32 = 0;
        //get func which contains the cmp.
        for (k, v) in func_cmp_map {
          if v.contains(&self.base.cmpid) {cmp_func = *k; break; }
        }
        //get cmp list of rel func
        let rels : &HashMap<u32, u32> = match func_rel_map.get(&cmp_func) { Some(h) => h, None => return () };
        let mut rel_list : Vec<(u32, u32)> = Vec::new();
        let mut target_runs = 0;
        for (k, v) in rels{
           rel_list.push((*k, *v));
           if *k == cmp_func { target_runs = *v;}
        }
        rel_list.retain(|x| (x.1 as f64 / target_runs as f64) > config::FUNC_REL_HIGH_THRESHOLD);
        self.state = CondState::OffsetRelFunc;

        for (rel_func, _rel) in rel_list {
          let mut rel_cmp_list = func_cmp_map.get(&rel_func).unwrap().clone();
          cmp_list.append(&mut rel_cmp_list);
        }
        let taint_file_path = taint_dir.clone().join(format!("taints_{}", self.base.belong));
        let taint_file = Path::new(&taint_file_path);
        let log_data = get_log_data(taint_file).ok().unwrap();
        let mut new_offsets = vec![];
        let mut lb_set = HashSet::new();
        for cond_base in log_data.cond_list.iter() {
          if cmp_list.contains(&cond_base.cmpid) {
            lb_set.insert(cond_base.lb1);
            lb_set.insert(cond_base.lb2);
          }
        };
        for lb in lb_set {
          match &log_data.tags.get(&lb) {
            Some(o) => {
              new_offsets = merge_offsets(&new_offsets,&o);
            },
            None => {},
          };
        };
        if config::FUNC_REL_RANDOM {
          let extend_len = offset_len(&new_offsets) - before_size;
          let input_len = depot.get_input_buf(self.base.belong as usize).len() as u32;
          let new_random_offset = Self::get_random_offsets(input_len, extend_len);
          self.offsets = merge_offsets(&self.offsets, &new_random_offset);
        } else {
          self.offsets = new_offsets;
        }
        let after_size = self.get_offset_len() + self.get_offset_opt_len();
        self.ext_offset_size_rel = after_size - before_size;
        if self.ext_offset_size_rel == 0 { warn!("0 size rel extension");}
        local_stats.func_time += start_time.elapsed().into();
    }

    fn to_unsolvable(&mut self) {
        debug!("to unsovable");
        self.state = CondState::Unsolvable;
    }

    fn to_timeout(&mut self) {
        debug!("to timeout");
        self.speed = defs::SLOW_SPEED;
        self.state = CondState::Timeout;
    }
}
