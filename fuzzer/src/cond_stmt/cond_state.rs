use crate::{cond_stmt::CondStmt, mut_input::offsets::*};
use std::fmt;
use std::sync::Arc;
use std::collections::HashMap;
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
        ((self.state.is_det() || self.state.is_one_byte()) && !self.is_first_time())
            || self.cur_fuzz_times >= config::LONG_FUZZ_TIME
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
    fn next_state(&mut self, depot : &Arc<Depot>, func_cmp_map : &HashMap<String, Vec<u32>>,
                    func_rel_map : &HashMap<String, HashMap<String, u32>>);
    fn to_offsets_opt(&mut self);
    fn to_offsets_all(&mut self);
    fn to_offsets_all_end(&mut self);
    fn to_det(&mut self);
    fn to_offsets_func(&mut self,depot : &Arc<Depot>, func_cmp_map : &HashMap<String, Vec<u32>>);
    fn to_offsets_rel_func(&mut self, depot : &Arc<Depot>, func_cmp_map : &HashMap<String, Vec<u32>>,
                                      func_rel_map : &HashMap<String, HashMap<String, u32>>);
    fn to_unsolvable(&mut self);
    fn to_timeout(&mut self);
    fn random_select(&mut self, depot : &Arc<Depot>);
    fn to_next_input(&mut self, func_cmp_map : &HashMap<String, Vec<u32>>,
                               func_rel_map : &HashMap<String, HashMap<String,u32>>);
    fn belongs_prioritize(&mut self, func_cmp_map : &HashMap<String, Vec<u32>>,
                               func_rel_map : &HashMap<String, HashMap<String,u32>>);
}

impl NextState for CondStmt {
    fn next_state(&mut self, depot : &Arc<Depot>, func_cmp_map : &HashMap<String, Vec<u32>>,
                             func_rel_map : &HashMap<String, HashMap<String, u32>>) {
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
                    self.to_offsets_func(depot, func_cmp_map);
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
                self.to_offsets_func(depot, func_cmp_map);
            },
            CondState::OffsetFunc => {
                if config::RANDOM_SELECT {
                  self.random_select(depot);
                } else {
                  self.to_offsets_rel_func(depot, func_cmp_map, func_rel_map);
                }
            },
            CondState::OffsetRelFunc => {
                self.to_offsets_all_end();
            },
            CondState::OffsetAllEnd => {
                self.to_next_input(func_cmp_map, func_rel_map);
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
    
    fn to_offsets_func(&mut self, depot : &Arc<Depot>, func_cmp_map : &HashMap<String, Vec<u32>>) {
        let before_size = self.get_offset_len() + self.get_offset_opt_len();
        self.state = CondState::OffsetFunc;
        if !config::REL_ALL &&
             (!config::REL_HIGH || config::RANDOM_SELECT || func_cmp_map.len() == 0) { return; }
        let mut cmp_list : Vec<u32> = Vec::new();
        //get function which contain target cmp
        for (_k, v) in func_cmp_map {
          if v.contains(&self.base.cmpid) { cmp_list = v.clone(); break; }
        }
        let q = match depot.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {warn!("Mutex poisoned!"); poisoned.into_inner()}};
        let iter = q.iter();
        for (i, _p) in iter {
          if self.base.belong != i.base.belong {continue;}
          if cmp_list.contains(&i.base.cmpid) {
            self.offsets = merge_offsets(&self.offsets, &i.offsets);
            self.offsets = merge_offsets(&self.offsets, &i.offsets_opt);
          }
        }
        let after_size = self.get_offset_len() + self.get_offset_opt_len();
        self.ext_offset_size = after_size - before_size;
    }
   
    fn to_next_input (&mut self,func_cmp_map : &HashMap<String, Vec<u32>>,
                                      func_rel_map : &HashMap<String, HashMap<String, u32>>) {
      if !config::PRIORITIZE { return ; }
      let new_belong = match self.belongs.peek(){
        Some((_, 0))  => {
          self.belongs_prioritize(func_cmp_map, func_rel_map);
          self.belongs.peek().expect("can't get belongs").0.clone()
        },
        Some ((b, _)) => {b.clone()},
        None => {(0,0,vec![], vec![])},
      };
      if new_belong.2.len() == 0 { return; }
      self.belongs.change_priority(&new_belong, 0);
      self.base.belong = new_belong.0;
      self.offsets = new_belong.2.clone();
      self.cur_fuzz_times = 0;
      self.state = CondState::Offset;
    }

    fn belongs_prioritize(&mut self, func_cmp_map : &HashMap<String, Vec<u32>>,
                               func_rel_map : &HashMap<String, HashMap<String,u32>>) {
      let mut cmp_list : Vec<u32> = Vec::new();
      let mut cmp_func : String = String::new();
      //get func which contains the cmp.
      for (k, v) in func_cmp_map {
        if v.contains(&self.base.cmpid) {cmp_func = k.clone(); break; }
      }
      //get cmp list of rel func
      let rels : &HashMap<String, u32> = match func_rel_map.get(&cmp_func) { Some(h) => h, None => return () };
      let mut rel_list : Vec<(String, u32)> = Vec::new();
      let mut target_runs = 0;
      for (k, v) in rels{
         rel_list.push((k.clone(), *v));
         if *k == cmp_func { target_runs = *v;}
      }
      rel_list.retain(|x| x.1 > 0);
      if !config::REL_ALL{
        if config::REL_HIGH {
          rel_list.retain(|x| (x.1 as f64 / target_runs as f64) > config::FUNC_REL_HIGH_THRESHOLD);
        } else {
          rel_list.retain(|x| (x.1 as f64 / target_runs as f64) < config::FUNC_REL_LOW_THRESHOLD);
        }
      }
      for (rel_func, _rel) in rel_list {
        let mut rel_cmp_list = func_cmp_map.get(&rel_func).unwrap().clone();
        cmp_list.append(&mut rel_cmp_list);
      }
      for (old_belong, p) in self.belongs.iter_mut(){
        if old_belong.1 == 0 {
          let mut common_list = cmp_list.clone();
          common_list.retain(|x| old_belong.3.contains(&x));
          old_belong.1 = ((common_list.len() as f32) / (old_belong.3.len() as f32) * 1000.0) as u32;
        };
        *p = old_belong.1;
      }
    }
 
    fn to_offsets_rel_func(&mut self, depot : &Arc<Depot>, func_cmp_map : &HashMap<String, Vec<u32>>,
                                      func_rel_map : &HashMap<String, HashMap<String, u32>>){
        let before_size = self.get_offset_len() + self.get_offset_opt_len();
        self.state = CondState::OffsetRelFunc;
        if func_cmp_map.len() == 0 {return ; }
        let mut cmp_list : Vec<u32> = Vec::new();
        let mut cmp_func : String = String::new();
        //get func which contains the cmp.
        for (k, v) in func_cmp_map {
          if v.contains(&self.base.cmpid) {cmp_func = k.clone(); break; }
        }
        //get cmp list of rel func
        let rels : &HashMap<String, u32> = match func_rel_map.get(&cmp_func) { Some(h) => h, None => return () };
        let mut rel_list : Vec<(String, u32)> = Vec::new();
        let mut target_runs = 0;
        for (k, v) in rels{
           rel_list.push((k.clone(), *v));
           if *k == cmp_func { target_runs = *v;}
        }
        rel_list.retain(|x| x.1 > 0);
        if !config::REL_ALL{
          if config::REL_HIGH {
            rel_list.retain(|x| (x.1 as f64 / target_runs as f64) > config::FUNC_REL_HIGH_THRESHOLD);
          } else {
            rel_list.retain(|x| (x.1 as f64 / target_runs as f64) < config::FUNC_REL_LOW_THRESHOLD);
          }
        }
        for (rel_func, _rel) in rel_list {
          let mut rel_cmp_list = func_cmp_map.get(&rel_func).unwrap().clone();
          cmp_list.append(&mut rel_cmp_list);
        }
        let mut new_offset = vec![];
        let q = match depot.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {warn!("Mutex poisoned!"); poisoned.into_inner()}
        };
        for (i, _p) in q.iter() {
          if cmp_list.contains(&i.base.cmpid) {
            for ((_bid2, _, boffset2,_), _) in i.belongs.iter(){
              new_offset = merge_offsets(&new_offset, boffset2);
            }
          }
        }
        self.offsets = merge_offsets(&self.offsets, &new_offset);
        let after_size = self.get_offset_len() + self.get_offset_opt_len();
        self.ext_offset_size_rel = after_size - before_size;
    }

    fn random_select(&mut self, depot : &Arc<Depot>){
      let mut new_offset = vec![];
      self.state = CondState::OffsetRelFunc;
      let before_size = self.get_offset_len() + self.get_offset_opt_len();
      let buf_len = depot.get_input_buf(self.base.belong as usize).len();
      for _i in 0..config::RANDOM_SIZE {
        let random_off :u32 = thread_rng().gen_range(0, buf_len) as u32;
        let random_byte = vec![TagSeg {sign : false, begin : random_off, end : random_off+1,}];
        new_offset = merge_offsets(&new_offset, &random_byte);
      } 
      self.offsets = merge_offsets(&self.offsets, &new_offset);
      let after_size = self.get_offset_len() + self.get_offset_opt_len();
      self.ext_offset_size_rel = after_size - before_size;
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
