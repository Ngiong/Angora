use crate::{
    branches::GlobalBranches, command::CommandOpt, cond_stmt::NextState, depot::Depot,
    executor::Executor, fuzz_type::FuzzType, search::*, stats,
};
use angora_common::config;
use rand::prelude::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::{collections::HashMap, fs::{OpenOptions,File}, io::Write};

pub fn fuzz_loop(
    running: Arc<AtomicBool>,
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    global_stats: Arc<RwLock<stats::ChartStats>>,
    func_cmp_map : HashMap<String, Vec<u32>>,
) {
    let search_method = cmd_opt.search_method;
    let out_dir_path : PathBuf = cmd_opt.tmp_dir.clone();
    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        global_stats.clone(),
    );
    let mut func_list_log  = OpenOptions::new().write(true).append(true).create(true).open(out_dir_path.as_path().parent().unwrap().join("tc_func.csv")).expect("Can't open funclist");
    if let Err(_) = writeln!(func_list_log, "tcid, funcs") {eprintln!("can't write funclist");}
    let mut func_rel_map : HashMap<String, HashMap<String, u32>> = HashMap::new();
    for k in func_cmp_map.keys() {
      let mut tmp_map = HashMap::new();
      for k2 in func_cmp_map.keys() {
        tmp_map.insert(k2.clone(), 0);
      }
      func_rel_map.insert(k.clone(), tmp_map);
    }
    let mut num_cal_input = 0;
    let mut num_file = 0;
    while running.load(Ordering::Relaxed) {
        get_relevance (&depot.dirs.inputs_dir, &mut executor, &mut func_list_log,
                                         &func_cmp_map, &mut num_file, &mut func_rel_map, &mut num_cal_input, out_dir_path.as_path());
        let entry = match depot.get_entry() {
            Some(e) => e,
            None => break,
        };
        debug!("cond : {} / priority : {}", entry.0.base.cmpid, entry.1);

        let mut cond = entry.0;
        let priority = entry.1;

        if priority.is_done() {
            break;
        }

        if cond.is_done() {
            depot.update_entry(cond);
            continue;
        }

        trace!("{:?}", cond);

        let belong_input = cond.base.belong as usize;

        let buf = depot.get_input_buf(belong_input);

        {
            let fuzz_type = cond.get_fuzz_type();
            let handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf);
            match fuzz_type {
                FuzzType::ExploreFuzz => {
                    if handler.cond.is_time_expired() {
                      //If it is not the first time, move to next state
                        handler.cond.next_state(&depot, &func_cmp_map, &func_rel_map);
                    }
                    if handler.cond.state.is_one_byte() { //Only one byte to fuzz for this condition.
                        OneByteFuzz::new(handler).run();
                    } else if handler.cond.state.is_det() { //bitflip on each bit.
                        DetFuzz::new(handler).run();
                    } else {
                        match search_method {
                            SearchMethod::Gd => {  //Gradient
                                GdSearch::new(handler).run(&mut thread_rng());
                            },
                            SearchMethod::Random => {
                                RandomSearch::new(handler).run();
                            },
                            SearchMethod::Cbh => {
                                CbhSearch::new(handler).run();
                            },
                            SearchMethod::Mb => {
                                MbSearch::new(handler).run();
                            },
                        }
                    }
                },
                FuzzType::ExploitFuzz => {
                    if handler.cond.state.is_one_byte() {
                        let mut fz = OneByteFuzz::new(handler);
                        fz.run();
                        fz.handler.cond.to_unsolvable(); // to skip next time
                    } else {
                        ExploitFuzz::new(handler).run();
                    }
                },
                FuzzType::AFLFuzz => {
                    AFLFuzz::new(handler).run();
                },
                FuzzType::LenFuzz => {
                    LenFuzz::new(handler).run();
                },
                FuzzType::CmpFnFuzz => {
                    FnFuzz::new(handler).run();
                },
                FuzzType::OtherFuzz => {
                    warn!("Unknown fuzz type!!");
                },
            }
        }

        depot.update_entry(cond);
    }
}

pub fn get_relevance(input_path : &Path, executor : & mut Executor, funclist_f : &mut File,
                   func_cmp_map : &HashMap<String, Vec<u32>>, num_file : &mut u32,
                   func_rel_map : &mut HashMap<String, HashMap<String, u32>>, num_input : &mut u32, o_dir : &Path) {
  let inputs = input_path.read_dir().expect("input_dir call failed");
  let mut num_executed = 0;
  for input in inputs {
    if let Ok(entry) = input {
      let path = &entry.path();
      if path.is_file(){
        let idnum = match &path.file_name().expect("can't get file_name").to_str().expect("can't get str of path")[3..].parse::<u32>() {
                    Ok(res) => *res, Err(_) => 0};
        if idnum < *num_input {continue;}
        //let buf = read_from_file(path);
        //executor.run_sync(&buf);
        let mut func_list : Vec<String> = executor.get_func(func_cmp_map, path);
        func_list.sort_unstable();
        func_list.dedup(); 
        if config::DEBUG_IO {
          if let Err(_) = write!(funclist_f, "{},",idnum) {eprintln!("can't write 2");}
          for f1 in &func_list{
            if let Err(_) = write! (funclist_f, "{},", f1) {eprintln!("can't write 3");}
          }
          if let Err(_) = writeln! (funclist_f, "") {eprintln!("can't write 3");}
        }
        for f1 in &func_list{
          for f2 in &func_list{
            *func_rel_map.get_mut(f1).expect("can't get mut from func_rel_map").get_mut(f2).expect("can't get mut from func_rel_map") += 1;
          }
        }
        num_executed += 1;
      }
    }
  }
  *num_input += num_executed;
  //print all relevance, not necessary for normal run.
  if config::DEBUG_IO && (num_executed > 0) {
    let rel_dir : PathBuf = o_dir.parent().unwrap().join("rels");
    let mkdir = match fs::create_dir(&rel_dir) { Ok(_) => true, Err(_) => false};
    let mut rel_all_file = OpenOptions::new().write(true).create(true)
                              .open( rel_dir.join(format!("rel_all_{}.csv",num_file))).expect("can't open rel_all_file"); 
    *num_file += 1;
    if let Err(_) = write!(rel_all_file, ",") {eprintln!("can't write in rel_all.csv");}
    let mut func_list = Vec::<String>::new(); 
    for (f1, _rel1) in func_rel_map.iter() { 
      func_list.push(f1.clone());
    }
    for f1 in &func_list {
      if let Err(_) = write!(rel_all_file, "{},", f1) {eprintln!("can't write 1")}
    }
    if let Err(_) = writeln!(rel_all_file, "") {eprintln!("can't write 1")}
    for f1 in &func_list {
      if let Err(_) = write!(rel_all_file, "{},", f1) {eprintln!("can't write 1")}
      for f2 in &func_list {
        if let Err(_) = write!(rel_all_file, "{},", func_rel_map.get(f1).unwrap().get(f2).unwrap()) {eprintln!("can't write 1")}
      }
      if let Err(_) = writeln!(rel_all_file, "") {eprintln!("can't write 1")}
    }
  }
}
