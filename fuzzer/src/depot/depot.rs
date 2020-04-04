use super::*;
use crate::{cond_stmt::CondStmt, executor::StatusType};
use rand;
use std::{
    fs,
    io::prelude::*,
    mem,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    collections::HashMap,
};
use angora_common::config;
// https://crates.io/crates/priority-queue
use priority_queue::PriorityQueue;

pub struct Depot {
    pub queue: Mutex<PriorityQueue<CondStmt, QPriority>>,
    pub num_inputs: AtomicUsize,
    pub num_hangs: AtomicUsize,
    pub num_crashes: AtomicUsize,
    pub dirs: DepotDir,
}

impl Depot {
    pub fn new(in_dir: PathBuf, out_dir: &Path) -> Self {
        Self {
            queue: Mutex::new(PriorityQueue::new()),
            num_inputs: AtomicUsize::new(0),
            num_hangs: AtomicUsize::new(0),
            num_crashes: AtomicUsize::new(0),
            dirs: DepotDir::new(in_dir, out_dir),
        }
    }

    fn save_input(
        status: &StatusType,
        buf: &Vec<u8>,
        num: &AtomicUsize,
        cmpid: u32,
        dir: &Path,
        belong : u32,
    ) -> usize {
        let id = num.fetch_add(1, Ordering::Relaxed);
        trace!(
            "Find {} th new {:?} input by fuzzing {}.",
            id,
            status,
            cmpid
        );
        let new_path = 
          match status {
            StatusType::Normal => {get_file_name(dir, id, 0, 0)},
            _ => {get_file_name(dir, id, cmpid, belong)}
          };
        let mut f = fs::File::create(new_path.as_path()).expect("Could not save new input file.");
        f.write_all(buf)
            .expect("Could not write seed buffer to file.");
        f.flush().expect("Could not flush file I/O.");
        id
    }

    pub fn save(&self, status: StatusType, buf: &Vec<u8>, cmpid: u32, belong : u32) -> usize {
        match status {
            StatusType::Normal => {
                Self::save_input(&status, buf, &self.num_inputs, cmpid, &self.dirs.inputs_dir, belong)
            },
            StatusType::Timeout => {
                Self::save_input(&status, buf, &self.num_hangs, cmpid, &self.dirs.hangs_dir, belong)
            },
            StatusType::Crash => Self::save_input(
                &status,
                buf,
                &self.num_crashes,
                cmpid,
                &self.dirs.crashes_dir,
                belong,
            ),
            _ => 0,
        }
    }

    pub fn empty(&self) -> bool {
        self.num_inputs.load(Ordering::Relaxed) == 0
    }

    pub fn next_random(&self) -> usize {
        rand::random::<usize>() % self.num_inputs.load(Ordering::Relaxed)
    }

    pub fn get_input_buf(&self, id: usize) -> Vec<u8> {
        let path = get_file_name(&self.dirs.inputs_dir, id, 0, 0);
        read_from_file(&path)
    }

    pub fn get_entry(&self) -> Option<(CondStmt, QPriority)> {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };
        // pick highest prioirty one.
        q.peek()
            .and_then(|x| Some((x.0.clone(), x.1.clone())))
            .and_then(|x| {
                if !x.1.is_done() {
                    let q_inc = x.1.inc(x.0.base.op);
                    q.change_priority(&(x.0), q_inc);
                }
                Some(x)
            })
    }

    pub fn add_entries(&self, conds: Vec<CondStmt>, func_rel_map : &HashMap<u32, HashMap<u32, u32>>, func_cmp_map : &HashMap<u32, Vec<u32>>) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };
        let conds_size = conds.len();
        for mut cond in conds {
            if cond.is_desirable {
                if let Some(v) = q.get_mut(&cond) {
                  //the COND aleady exists in the queue
                    if !v.0.is_done() {
                        // If existed one and our new one has two different conditions,
                        // this indicate that it is explored.
                        // different condition -> different then/else condition -> explored!
                        if v.0.base.condition != cond.base.condition {
                            v.0.mark_as_done();
                            q.change_priority(&cond, QPriority::done());
                        } else {
                            // Existed, but the new one are better
                            // If the cond is faster than the older one,
                            // we prefer the faster one.
                            let swap = if config::MUTATE_TC_SELECT {
                              let mut cmp_list = vec![];
                              let mut cmp_func : u32 = 0;
                              for (k, v) in func_cmp_map{
                                if v.contains(&cond.base.cmpid) {cmp_func = *k; break;}
                              };
                              let rels : &HashMap<u32, u32> = match func_rel_map.get(&cmp_func) { Some(h) => h, None => return () };
                              let mut rel_list : Vec<(u32, u32)> = Vec::new();
                              let mut target_runs = 0;
                              for (k, v) in rels{
                                rel_list.push((*k, *v));
                                if *k == cmp_func { target_runs = *v;}
                              }
                              rel_list.retain(|x| (x.1 as f64 / target_runs as f64) > config::FUNC_REL_HIGH_THRESHOLD);
                              for (rel_func, _rel) in rel_list {
                                let mut rel_cmp_list = func_cmp_map.get(&rel_func).unwrap().clone();
                                cmp_list.append(&mut rel_cmp_list);
                              };
                              let func_rel_score = cmp_list.len() / conds_size;
                              cond.func_rel_score = func_rel_score;
                              func_rel_score > v.0.func_rel_score
                            } else { v.0.speed > cond.speed };
                            if swap {
                                mem::swap(v.0, &mut cond);
                                let priority = QPriority::init(cond.base.op);
                                q.change_priority(&cond, priority);
                            }
                        }
                    }
                } else { //no same branch
                    let priority = QPriority::init(cond.base.op);
                    q.push(cond, priority);
                }
            }
        }
    }

    pub fn update_entry(&self, cond: CondStmt) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };
        if let Some(v) = q.get_mut(&cond) {
            v.0.clone_from(&cond);
        } else {
            warn!("Update entry: can not find this cond");
        }
        if cond.is_discarded() {
            q.change_priority(&cond, QPriority::done());
        }
    }
}
