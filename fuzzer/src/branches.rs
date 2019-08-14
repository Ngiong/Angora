use crate::executor::StatusType;
use angora_common::{config::BRANCHES_SIZE, shm::SHM};
use std::{
    self,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};
use std::collections::HashMap;
#[cfg(feature = "unstable")]
use std::intrinsics::unlikely;

#[allow(dead_code)]
pub type BranchBuf = [u8; BRANCHES_SIZE];
pub type BranchBuf2 = [u8; BRANCHES_SIZE * 2];
#[cfg(target_pointer_width = "32")]
type BranchEntry = u32;
#[cfg(target_pointer_width = "64")]
type BranchEntry = u64;
#[cfg(target_pointer_width = "32")]
const ENTRY_SIZE: usize = 4;
#[cfg(target_pointer_width = "64")]
const ENTRY_SIZE: usize = 8;

//default memory setting
//type BranchBufPlus = [BranchEntry; BRANCHES_SIZE / ENTRY_SIZE];
type BranchBufPlus2 = [BranchEntry; BRANCHES_SIZE * 2 / ENTRY_SIZE];

// Map of bit bucket
// [1], [2], [3], [4, 7], [8, 15], [16, 31], [32, 127], [128, infinity]
static COUNT_LOOKUP: [u8; 256] = [
    0, 1, 2, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
];

macro_rules! cast {
    ($ptr:expr) => {{
        unsafe { std::mem::transmute($ptr) }
    }};
}

pub struct GlobalBranches {
    virgin_branches: RwLock<Box<BranchBuf>>,
    tmouts_branches: RwLock<Box<BranchBuf>>,
    crashes_branches: RwLock<Box<BranchBuf>>,
    virgin_blocks : RwLock<Box<BranchBuf>>,
    density: AtomicUsize,
}

impl GlobalBranches {
    pub fn new() -> Self {
        Self {
            virgin_branches: RwLock::new(Box::new([255u8; BRANCHES_SIZE])),
            tmouts_branches: RwLock::new(Box::new([255u8; BRANCHES_SIZE])),
            crashes_branches: RwLock::new(Box::new([255u8; BRANCHES_SIZE])),
            virgin_blocks : RwLock::new(Box::new([255u8; BRANCHES_SIZE])),
            density: AtomicUsize::new(0),
        }
    }

    pub fn get_density(&self) -> f32 {
        let d = self.density.load(Ordering::Relaxed);
        (d * 10000 / BRANCHES_SIZE) as f32 / 100.0
    }
}

pub struct Branches {
    global: Arc<GlobalBranches>,
    trace: SHM<BranchBuf2>,
}

impl Branches {
    pub fn new(global: Arc<GlobalBranches>) -> Self {
        let trace = SHM::<BranchBuf2>::new();
        Self { global, trace }
    }

    pub fn clear_trace(&mut self) {
        self.trace.clear();
    }

    pub fn get_id(&self) -> i32 {
        self.trace.get_id()
    }

    fn get_path(&self) -> (Vec<(usize, u8)>, Vec<usize>) {
        let mut path = Vec::<(usize, u8)>::new();
        let mut blocks = Vec::<usize>::new();
        let buf_plus: &BranchBufPlus2 = cast!(&*self.trace);
        let buf: &BranchBuf2 = &*self.trace;
        for (i, &v) in buf_plus.iter().enumerate() {
            macro_rules! run_loop { () => {{
                let base = i * ENTRY_SIZE;
                for j in 0..ENTRY_SIZE {
                    let idx = base + j;
                    let new_val = buf[idx];
                    if new_val > 0 {
                        if idx < BRANCHES_SIZE {
                          path.push((idx, COUNT_LOOKUP[new_val as usize]));
                        } else {
                          blocks.push(idx - BRANCHES_SIZE);
                        }
                    }
                }
            }}}
            #[cfg(feature = "unstable")]
            {
                if unsafe { unlikely(v > 0) } {
                    run_loop!()
                }
            }
            #[cfg(not(feature = "unstable"))]
            {
                if v > 0 {
                    run_loop!()
                }
            }
        }
        // debug!("count branch table: {}", path.len());
        (path, blocks)
    }

    pub fn get_func(&mut self, func_map : &HashMap<String, Vec<(usize, bool)>>) -> Vec<String> {
      let mut functions : Vec<String> = Vec::new();
      let (_path, blocks) = self.get_path();
      for bb in blocks{
        let mut found = false;
        for (k, v) in func_map {
          for v2 in v {
            if bb == v2.0 {
              found = true;
              functions.push(k.clone());
              break;
            }
          }
          if found {break;}
        }
      }
      functions 
    }

    pub fn has_new(&mut self, status: StatusType) -> (bool, bool, usize, Vec<usize>) {
        let gb_map = match status {
            StatusType::Normal => &self.global.virgin_branches,
            StatusType::Timeout => &self.global.tmouts_branches,
            StatusType::Crash => &self.global.crashes_branches,
            _ => {
                return (false, false, 0, vec![]);
            },
        };
        let bb_map = &self.global.virgin_blocks;

        let (path, blocks) = self.get_path();
        let edge_num = path.len();

        let mut to_write = vec![];
        let mut to_bb_write = vec![];
        let mut has_new_edge = false;
        let mut num_new_edge = 0;
        {
            // read only
            let gb_map_read = gb_map.read().unwrap();
            for &br in &path {
                let gb_v = gb_map_read[br.0];

                if gb_v == 255u8 {  //never touched edge (branch)
                    num_new_edge += 1;
                }

                if (br.1 & gb_v) > 0 {
                    to_write.push((br.0, gb_v & (!br.1)));
                }
            }
            let bb_map_read = bb_map.read().unwrap();
            for &bb in &blocks {
                let bb_v = bb_map_read[bb];
                if bb_v == 255u8 {
                  to_bb_write.push(bb);
                }
            }
        }

        if num_new_edge > 0 {
            if status == StatusType::Normal {
                // only count virgin branches
                self.global
                    .density
                    .fetch_add(num_new_edge, Ordering::Relaxed);
            }
            has_new_edge = true;
        }

        if !to_bb_write.is_empty() {
           let mut bb_map_write = bb_map.write().unwrap();
              for &bb in &to_bb_write {
                 bb_map_write[bb] = 1;
              }
        }

        if to_write.is_empty() {
            return (false, false, edge_num, to_bb_write);
        }

        {
            // write
            let mut gb_map_write = gb_map.write().unwrap();
            for &br in &to_write {
                gb_map_write[br.0] = br.1;
            }
        }

        (true, has_new_edge, edge_num, to_bb_write)
    }
}

impl std::fmt::Debug for Branches {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn branch_empty() {
        let global_branches = Arc::new(GlobalBranches::new());
        let mut br = Branches::new(global_branches);
        assert_eq!(br.has_new(StatusType::Normal), (false, false, 0));
        assert_eq!(br.has_new(StatusType::Timeout), (false, false, 0));
        assert_eq!(br.has_new(StatusType::Crash), (false, false, 0));
    }

    #[test]
    #[ignore]
    fn branch_find_new() {
        let global_branches = Arc::new(GlobalBranches::new());
        let mut br = Branches::new(global_branches);
        assert_eq!(br.has_new(StatusType::Normal), (false, false, 0));
        {
            let trace = &mut br.trace;
            trace[4] = 1;
            trace[5] = 1;
            trace[8] = 3;
        }
        let (path, _blocks) = br.get_path();
        assert_eq!(path.len(), 3);
        assert_eq!(path[2].1, COUNT_LOOKUP[3]);
        assert_eq!(br.has_new(StatusType::Normal), (true, true, 3));
    }
}
