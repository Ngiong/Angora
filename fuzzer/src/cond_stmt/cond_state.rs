use crate::{cond_stmt::CondStmt, mut_input::offsets::*, stats, get_rel::get_rel_func_list};
use runtime::logger::get_log_data;
use std::fmt;
use std::sync::Arc;
use std::collections::HashSet;
use std::time::Instant;
use std::path::{Path, PathBuf};
use std::ops::Deref;
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
          CondState::OffsetRelFunc => { self.cur_state_fuzz_times >= config::STATE_LONG_FUZZ_TIME[4]},
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
                  func_rel_map : &Box<[Box<[usize]>]>);
    fn to_offsets_opt(&mut self);
    fn to_offsets_all(&mut self);
    fn to_offsets_all_end(&mut self);
    fn to_det(&mut self);
    fn to_offsets_func(&mut self, depot : &Arc<Depot>,
                                  local_stats : &mut stats::LocalStats,
                                  taint_dir : &PathBuf,
                                  func_rel_map : &Box<[Box<[usize]>]>);
    fn to_offsets_rel_func(&mut self, depot : &Arc<Depot>,
                                      local_stats : &mut stats::LocalStats,
                                      taint_dir : &PathBuf,
                                      func_rel_map : &Box<[Box<[usize]>]>);
    fn to_unsolvable(&mut self);
    fn to_timeout(&mut self);
    fn to_next_belong(&mut self, taint_dir : &PathBuf);
    fn get_random_offsets( input_len : u32, extend_len : u32) -> Vec<TagSeg>; 
}

impl NextState for CondStmt {
    fn next_state(&mut self, depot : &Arc<Depot>,
                             local_stats : &mut stats::LocalStats,
                             taint_dir : &PathBuf,
                             func_rel_map : &Box<[Box<[usize]>]>) {
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
                } else if config::BYTE_EXT_FUNC_REL || config::BYTE_EXT_RANDOM {
                    self.to_offsets_func(depot, local_stats, taint_dir, func_rel_map);
                } else if config::TC_SEL_FUNC_REL || config::TC_SEL_RANDOM {
                    self.to_next_belong(taint_dir);
                } else {
                   self.to_unsolvable();
                }
            },
            CondState::OffsetOpt => {
                self.to_offsets_all();
            },
            CondState::OffsetAll => {
                self.to_det();
            },
            CondState::Deterministic => {
                if config::BYTE_EXT_FUNC_REL || config::BYTE_EXT_RANDOM {
                  self.to_offsets_func(depot, local_stats, taint_dir,  func_rel_map);
                } else if config::TC_SEL_FUNC_REL || config::TC_SEL_RANDOM {
                  self.to_next_belong(taint_dir);
                } else {
                  self.to_offsets_all_end();
                }
            },
            CondState::OffsetFunc => {
                  self.to_offsets_rel_func(depot, local_stats, taint_dir, func_rel_map);
            },
            CondState::OffsetRelFunc => {
               if config::TC_SEL_FUNC_REL || config::TC_SEL_RANDOM {
                  self.to_next_belong(taint_dir);
               } else {
                  self.to_offsets_all_end();
               }
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
    
    fn to_offsets_func(&mut self, depot : &Arc<Depot>, local_stats : &mut stats::LocalStats,
                       taint_dir : &PathBuf, func_rel_map : &Box<[Box<[usize]>]>) {
        let before_size = self.get_offset_len() + self.get_offset_opt_len();
        let start_time = Instant::now();
        self.state = CondState::OffsetFunc;
        if func_rel_map.len() == 0 { return; }
        let cur_func = self.base.belong_func;

        let taint_file_path = taint_dir.clone().join(format!("taints_{}", self.base.belong));
        let taint_file = Path::new(&taint_file_path);
        let log_data = match get_log_data(taint_file) {
          Ok(s) => {s},
          Err(_) => {
            error!("Can't get log data : cmpid : {}, belong: {}", self.base.cmpid, self.base.belong);
            return;
          },
        };

        let mut new_offsets = vec![];
        let mut lb_set = HashSet::new();
        for cond_base in log_data.cond_list.iter() {
          if cond_base.belong_func == cur_func {
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
        if config::BYTE_EXT_RANDOM {
          let extend_len = offset_len(&new_offsets) - before_size;
          let input_len = depot.get_input_buf(self.base.belong as usize).len() as u32;
          let new_random_offset = Self::get_random_offsets(input_len, extend_len);
          self.offsets = merge_offsets(&self.offsets, &new_random_offset);
        } else {
          self.offsets = new_offsets;
        }
        let ext_size = self.get_offset_len() + self.get_offset_opt_len() - before_size;
        self.ext_offset_size += ext_size;
        local_stats.func_time += start_time.elapsed().into();
        if ext_size == 0 {self.next_state(depot,local_stats, taint_dir, func_rel_map);}; 
    }
 
    fn to_offsets_rel_func(&mut self, depot : &Arc<Depot>,
                                      local_stats : &mut stats::LocalStats,
                                      taint_dir : &PathBuf,
                                      func_rel_map : &Box<[Box<[usize]>]>){

        self.state = CondState::OffsetRelFunc;
        let before_size = self.get_offset_len() + self.get_offset_opt_len();
        let start_time = Instant::now();
        if func_rel_map.deref().len() == 0 {return ;}

        let rel_func_list = get_rel_func_list(self.base.belong_func as usize, func_rel_map);
   
        let taint_file_path = taint_dir.clone().join(format!("taints_{}", self.base.belong));
        let taint_file = Path::new(&taint_file_path);

        let log_data = match get_log_data(taint_file) {
          Ok(s) => {s},
          Err(_) => {
            error!("Can't get log data : cmpid : {}, belong: {}", self.base.cmpid, self.base.belong);
            return;
          },
        };
        let mut new_offsets = vec![];
        let mut lb_set = HashSet::new();
        for cond_base in log_data.cond_list.iter() {
          if rel_func_list.contains(& (cond_base.belong_func as usize)) {
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
        if config::BYTE_EXT_RANDOM {
          let extend_len = offset_len(&new_offsets) - before_size;
          let input_len = depot.get_input_buf(self.base.belong as usize).len() as u32;
          let new_random_offset = Self::get_random_offsets(input_len, extend_len);
          self.offsets = merge_offsets(&self.offsets, &new_random_offset);
        } else {
          self.offsets = new_offsets;
        }
        let after_size = self.get_offset_len() + self.get_offset_opt_len();
        self.ext_offset_size_rel += after_size - before_size;
        local_stats.func_time += start_time.elapsed().into();
        if (after_size - before_size) == 0 {self.next_state(depot,local_stats,taint_dir, func_rel_map);}
    }

    fn to_next_belong(&mut self, taint_dir : &PathBuf) {
      self.executed_belongs.insert(self.base.belong);
      let next_belong = if config::TC_SEL_RANDOM || config::TC_SEL_FUNC_REL {
                          let mut nb = None;
                          for frs in &self.func_rel_score {
                            if !self.executed_belongs.contains(&frs.1) {
                              nb = Some(frs.1);
                              break;
                            }
                          };
                          match nb {
                            Some(b) => {b},
                            None => {return;}
                          }
                        } else {
                          panic!("to_next_belong called with unproper configuration!");
                        };

      let taint_file_path = taint_dir.clone().join(format!("taints_{}", next_belong));
      let taint_file = Path::new(&taint_file_path);
      let log_data = match get_log_data(taint_file) {
        Ok(s) => {s},
        Err(_) => { error!("Can't get log data : cmpid : {}, belong: {}", self.base.cmpid, next_belong);
          return;
        },
      };
      let mut new_offsets = vec![];
      match &log_data.tags.get(&self.base.lb1) {
        Some(o) => {new_offsets = merge_offsets(&new_offsets, &o);},
        None => {},
      };
      match &log_data.tags.get(&self.base.lb2) {
        Some(o) => {new_offsets = merge_offsets(&new_offsets, &o);},
        None => {},
      };
      self.belong_changed += 1;
      if new_offsets.len() == 0 {
        self.executed_belongs.insert(next_belong);
        self.to_next_belong(taint_dir);
      } else {
        self.offsets = new_offsets;
        let mut cond_index = None;
        for (i, cb) in log_data.cond_list.iter().enumerate() {
          if cb.cmpid == self.base.cmpid {
            cond_index = Some(i);
            break;
          }
        };
        self.variables =  if let Some(idx) = cond_index {
          if let Some(args) = &log_data.magic_bytes.get(&idx){
            [&args.1[..], &args.0[..]].concat()
          } else {vec![]}
        } else { vec![] };
        self.state = CondState::Offset;
      };
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
