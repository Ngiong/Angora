use super::CondState;
use crate::fuzz_type::FuzzType;
use angora_common::{cond_stmt_base::CondStmtBase, defs, tag::TagSeg};
use std::hash::{Hash, Hasher};

#[derive(Debug, Default, Clone)]
pub struct CondStmt {
    pub base: CondStmtBase,
    pub offsets: Vec<TagSeg>,
    pub offsets_opt: Vec<TagSeg>,
    pub variables: Vec<u8>,

    pub speed: u32,
    pub is_desirable: bool, // non-convex
    pub is_consistent: bool,
    pub fuzz_times: usize,
    pub state: CondState,
    pub num_minimal_optima: usize,
    pub linear: bool,

    pub belongs : Vec<(u32,Vec<TagSeg>)>, // (input id, offset)
    pub cur_input_fuzz_times : usize,
}

impl PartialEq for CondStmt {
    fn eq(&self, other: &CondStmt) -> bool {
        self.base == other.base
    }
}

impl Eq for CondStmt {}

impl Hash for CondStmt {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.base.cmpid.hash(state);
        self.base.context.hash(state);
        self.base.order.hash(state);
    }
}

impl CondStmt {
    pub fn new() -> Self {
        let cond_base = Default::default();
        Self {
            base: cond_base,
            offsets: vec![],
            offsets_opt: vec![],
            variables: vec![],
            speed: 0,
            is_consistent: true,
            is_desirable: true,
            fuzz_times: 0,
            state: CondState::default(),
            num_minimal_optima: 0,
            linear: false,
            belongs : vec![],
            cur_input_fuzz_times : 0,
        }
    }

    pub fn from(cond_base: CondStmtBase) -> Self {
        let mut cond = Self::new();
        cond.base = cond_base;
        cond
    }

    pub fn get_fuzz_type(&self) -> FuzzType {
        match self.base.op {
            defs::COND_AFL_OP => FuzzType::AFLFuzz,
            defs::COND_LEN_OP => FuzzType::LenFuzz,
            defs::COND_FN_OP => FuzzType::CmpFnFuzz,
            _ => {
                if self.base.is_explore() {
                    FuzzType::ExploreFuzz
                } else if self.base.is_exploitable() {
                    FuzzType::ExploitFuzz
                } else {
                    FuzzType::OtherFuzz
                }
            },
        }
    }
    pub fn get_offset_len(&self) -> u32 {
      let mut len = 0;
      for i in 0..self.offsets.len() {
        let end = self.offsets[i].end;
        let bgn = self.offsets[i].begin;
        let diff = if end > bgn {end - bgn} else { 0} ;
        len += diff;
      }
      len
    }

    pub fn get_offset_opt_len(&self) -> u32 {
      let mut len = 0;
      for i in 0..self.offsets_opt.len() {
        let end = self.offsets_opt[i].end;
        let bgn = self.offsets_opt[i].begin;
        let diff = if end > bgn {end - bgn} else { 0} ;
        len += diff;
      }
      len
    }

    pub fn is_tainted(&self) -> bool {
        self.offsets.len() > 0
    }

    pub fn is_bool(&self) -> bool {
        (self.base.may_be_bool() && !self.is_desirable) || (self.base.op & defs::COND_BOOL_MASK) > 0
    }

    pub fn mark_as_done(&mut self) {
        self.base.condition = defs::COND_DONE_ST;
        //self.clear();
    }

    pub fn clear(&mut self) {
        self.offsets = vec![];
        self.offsets_opt = vec![];
        self.variables = vec![];
    }

    pub fn is_discarded(&self) -> bool {
        self.is_done() || self.state.is_unsolvable() || self.state.is_timeout()
    }

    pub fn is_first_time(&self) -> bool {
        self.fuzz_times == 1
    }

    pub fn get_afl_cond(id: usize, speed: u32, edge_num: usize) -> Self {
        let mut afl_cond = Self::new();
        afl_cond.speed = speed;
        afl_cond.base.op = defs::COND_AFL_OP;
        afl_cond.base.cmpid = id as u32;
        afl_cond.base.context = 0;
        afl_cond.base.order = 0;
        afl_cond.base.arg1 = edge_num as u64;
        afl_cond
    }

    pub fn is_done(&self) -> bool {
        self.base.is_done()
    }

    pub fn append_input(&mut self, cond : &mut CondStmt){
      if cond.offsets.len() != 0 {
        self.belongs.push((cond.base.belong, cond.offsets.clone()));
      }
      self.belongs.append(&mut cond.belongs);
    }

    pub fn next_input(&mut self){
      if self.belongs.len() > 0 {
        self.belongs.push((self.base.belong, self.offsets.clone()));
        let (new_input, new_off) = self.belongs.remove(0);
        self.base.belong = new_input;
        self.offsets = new_off.clone();
      }
    }
}
