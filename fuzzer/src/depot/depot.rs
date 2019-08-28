use super::*;
use crate::{cond_stmt::CondStmt, executor::StatusType};
use rand;
use std::{
    fs,
    fs::OpenOptions,
    io::prelude::*,
    mem,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
// https://crates.io/crates/priority-queue
use angora_common::config;
use priority_queue::PriorityQueue;
use std::collections::HashMap;
//use std::collections::HashSet;

pub struct Depot{
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
    ) -> usize {
        let id = num.fetch_add(1, Ordering::Relaxed);
        trace!(
            "Find {} th new {:?} input by fuzzing {}.",
            id,
            status,
            cmpid
        );
        let new_path = get_file_name(dir, id);
        let mut f = fs::File::create(new_path.as_path()).expect("Could not save new input file.");
        f.write_all(buf)
            .expect("Could not write seed buffer to file.");
        f.flush().expect("Could not flush file I/O.");
        id
    }

    pub fn save(&self, status: StatusType, buf: &Vec<u8>, cmpid: u32) -> usize {
        match status {
            StatusType::Normal => {
                Self::save_input(&status, buf, &self.num_inputs, cmpid, &self.dirs.inputs_dir)
            },
            StatusType::Timeout => {
                Self::save_input(&status, buf, &self.num_hangs, cmpid, &self.dirs.hangs_dir)
            },
            StatusType::Crash => Self::save_input(
                &status,
                buf,
                &self.num_crashes,
                cmpid,
                &self.dirs.crashes_dir,
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
        let path = get_file_name(&self.dirs.inputs_dir, id);
        read_from_file(&path)
    }

    pub fn get_entry(&self, _rels: &Vec<(String, u32)>, _func_cmp_map : &HashMap<String, Vec<u32>>) -> Option<(CondStmt, QPriority)> {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };
        /*
        //prioritize with func relevance.
        let mut cmp_set : HashSet<u32> = HashSet::new();
        if !rels.is_empty(){
          for k in rels{
            let cmp_func_list = func_cmp_map.get(&k.0).unwrap();
            for v in cmp_func_list{
              cmp_set.insert(*v);
            }
          }
          let iter = q.iter();
          let mut highest : Option<(CondStmt, QPriority)>= None;
          for (i, p) in iter {
            let thr = QPriority(config::FUNC_TARGET_PRIORITY_THREASHOLD);
            if *p < thr {continue;}
            if cmp_set.contains(&i.base.cmpid){
              highest = match highest { 
                Some ((i2, p2)) => {if p2 < *p {Some((i.clone(), p.clone()))} else { Some((i2, p2))}},
                None => {Some((i.clone(), p.clone()))}
              }
            }
          }
          if let Some ((clone_i, clone_p)) = highest {
            if !clone_p.is_done(){
              let q_inc = clone_p.inc(clone_i.base.op);
              q.change_priority(&(clone_i), q_inc);
            }
            return Some((clone_i, clone_p));
          }
        }
        */
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

    pub fn add_entries(& self, conds: Vec<CondStmt>) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };

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
                            // If the cond is faster than the older one, we prefer the faster,
                            if v.0.speed > cond.speed {
                                //cond.append_input(v.0);
                                mem::swap(v.0, &mut cond);
                                let priority = QPriority::init(cond.base.op);
                                q.change_priority(&cond, priority);
                            } else {
                               //v.0.append_input(&mut cond);
                            }
                        }
                    }
                } else {
                    let priority = QPriority::init(cond.base.op);
                    q.push(cond, priority);
                }
            }
        }
    }

    pub fn update_entry(& self, cond: CondStmt) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };
        if let Some(v) = q.get_mut(&cond) {
            v.0.clone_from(&cond);
            if v.0.cur_input_fuzz_times > config::INPUT_FUZZ_MAX_TIME {
              v.0.cur_input_fuzz_times = 0;
              //v.0.next_input();
            }
        } else {
            warn!("Update entry: can not find this cond");
        }
        if cond.is_discarded() {
            q.change_priority(&cond, QPriority::done());
        }
    }

  pub fn log(&self, o_dir : &Path) {
      let conds_dir : PathBuf = o_dir.parent().unwrap().join("conds");
      let mkdir = match fs::create_dir(&conds_dir) { Ok(_) => true, Err(_) => false};
      let mut logid = 0;
      if !mkdir { loop {
        let filename = format!("conds_log_{}.csv", logid);
        let filepath : PathBuf = conds_dir.join(filename);
        if !filepath.exists() {break; } else { logid += 1;}
      }}
      let log_file_name = conds_dir.join(format!("conds_log_{}.csv", logid));
      let mut log_file = OpenOptions::new().write(true).create(true)
                            .open(log_file_name).expect("can't open conds log");
      let firstline = format!("cmpid,context,belong,condition,state,# of offsets,total offset len,#belongs,fuzz_times,priority");
      if let Err(_) = writeln!(log_file, "{}", firstline) {eprintln!("can't write condslog");}
      let q = match self.queue.lock() { Ok(g) => g, Err(p) => { p.into_inner()}};
      let iter = q.iter();
      for (i, p) in iter {
        let condinfo = format!("{},{},{},{},{},{},{},{},{},{}",i.base.cmpid,i.base.context,i.base.belong,i.base.condition,i.state,i.offsets.len(),i.get_offset_len(),i.belongs.len(),i.fuzz_times,p);
        if let Err(_) = writeln!(log_file, "{}", condinfo) {eprintln!("can't write condslog");}
      }
    }
}
