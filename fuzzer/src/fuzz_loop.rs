use crate::{
    branches::GlobalBranches, command::CommandOpt, cond_stmt::NextState, depot::Depot,
    executor::Executor, fuzz_type::FuzzType, search::*, stats,
};
use angora_common::config;
use rand::{prelude::*, distributions::WeightedIndex};
//use rand::seq::SliceRandom;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{collections::HashMap, fs::{OpenOptions,File}, io::Write};
use crate::depot::file::read_from_file;

pub fn fuzz_loop(
    running: Arc<AtomicBool>,
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    global_stats: Arc<RwLock<stats::ChartStats>>,
    func_map : HashMap<String, Vec<(usize, bool)>>,
    func_map2 : HashMap<String, Vec<u32>>,
) {
    let search_method = cmd_opt.search_method;
    let out_dir_path : PathBuf = cmd_opt.tmp_dir.clone();
    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        global_stats.clone(),
        func_map.clone(),
    );
    let mut func_list_log  = OpenOptions::new().write(true).append(true).create(true).open(out_dir_path.as_path().parent().unwrap().join("tc_func.csv")).expect("Can't open funclist");
    if let Err(_) = writeln!(func_list_log, "tcid, funcs") {eprintln!("can't write funclist");}
    
    let target_funcs : Vec<(String, u32)> = vec![];
    let mut func_rel_map : HashMap<String, HashMap<String, u32>> = HashMap::new();
    for k in func_map.keys() {
      let mut tmp_map = HashMap::new();
      for k2 in func_map.keys() {
        tmp_map.insert(k2.clone(), 0);
      }
      func_rel_map.insert(k.clone(), tmp_map);
    }
    let mut num_cal_input = 0;
    //let mut func_exec = config::FUNC_TARGET_NUMBER_OF_COND;
    let mut new_target :String = String::new();
    //let mut cov : f64;
    //let mut num_node : usize;
    let mut depot_rec_time = Instant::now();

    while running.load(Ordering::Relaxed) {
        if config::DEBUG_IO && (depot_rec_time.elapsed() >= Duration::from_secs(60 * 10)) {
             depot.log(out_dir_path.as_path()); depot_rec_time = Instant::now();
        }
/*
        if func_exec >= config::FUNC_TARGET_NUMBER_OF_COND {
          let res = get_target_random(&executor);
          new_target = res.0;
          cov = res.1;
          num_node = res.2;
          debug!("new target : {}, cov : {}/{}", new_target, cov,num_node);
          if (func_map.len() > 0 && !new_target.is_empty()) &&
                (target_funcs.len() < 1 || new_target != target_funcs.get(0).expect("can't get first elem from target_funcs").0){
            target_funcs = get_relevance (new_target, &depot.dirs.inputs_dir, &mut executor, &mut func_list_log,
                                         &func_map, &mut func_rel_map, &mut num_cal_input, out_dir_path.as_path(), cov);
          }
          debug!("calculated input : {}", num_cal_input);
          func_exec = 0;
        } else {
          func_exec += 1;
        }
*/
         get_relevance (new_target.clone(), &depot.dirs.inputs_dir, &mut executor, &mut func_list_log,
                                         &func_map, &mut func_rel_map, &mut num_cal_input, out_dir_path.as_path(), 0.0);
        let entry = match depot.get_entry(&target_funcs, &func_map2) {
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

        /*
        if config::ENABLE_PREFER_FAST_COND && cond.base.op == defs::COND_AFL_OP {
            let mut rng = thread_rng();
            let speed_ratio = depot.get_speed_ratio(belong_input);
            if speed_ratio > 1 {
                // [2, 3] -> 2
                // [4, 7] -> 3
                // [7, 15] -> 4
                // [16, ..] -> 5
                let weight = ((speed_ratio + 1) as f32).log2().ceil() as u32;
                if !rng.gen_weighted_bool(weight) {
                    continue;
                }
            }
        }
        */

        let buf = depot.get_input_buf(belong_input);

        {
            let fuzz_type = cond.get_fuzz_type();
            let handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf);
            match fuzz_type {
                FuzzType::ExploreFuzz => {
                    if handler.cond.is_time_expired() {
                      //If it is not the first time, move to next state
                        handler.cond.next_state(&depot, &func_map2, &func_rel_map);
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

#[allow(dead_code)]
pub fn get_target(ex : & Executor) -> (String, f64, usize) {
  let mut target : String = String::new();
  let mut mincov : f64 = 100.0;
  let mut min_num_node = 0;
  for (k, elem) in &ex.func_map { //hashmap <String, Vec<(usize, bool)>>
    let num_node = elem.len();
    let mut num_cov = 0;
    for v in elem {
      if v.1 == true {num_cov += 1;}
    }
    let cov : f64 = num_cov as f64 / num_node as f64;
    if cov > 0.0 && mincov > cov {
      mincov = cov;
      min_num_node = num_node;
      target = k.clone();
    }
  }
  (target, mincov, min_num_node)
}

#[allow(dead_code)]
pub fn get_target_uniform_random(ex : & Executor) -> (String, f64, usize) {
  let mut funcs = Vec::new(); 
  for (k, _elem) in &ex.func_map {
    funcs.push(k.clone());
  }
   //pick uniformly random
  let mut loop_idx = 0;
  loop {
    let target : String = if let Some(strin) = funcs.choose(&mut rand::thread_rng()){strin.to_string()} else {return ("".to_string(), 0.0, 0);};
    let blocks = ex.func_map.get(&target).expect("Can't get target from map");
    let num_node = blocks.len();
    let mut num_cov = 0;
    for b in blocks{
      if b.1 == true {num_cov += 1;}
    }
    let cov : f64 = num_cov as f64 / num_node as f64;
    if cov > 0.0 {
      return (target, cov, num_node);
    } 
    loop_idx += 1;
    if loop_idx > config::FUNC_CHOOSE_LOOP_MAX {
      return ("".to_string(), 0.0, 0);
    }
  } 
}

pub fn get_target_random(ex : & Executor) -> (String, f64, usize) {
  let mut rev_covs = Vec::new();
  let mut funcs = Vec::new();
  for (k, elem) in &ex.func_map{
    let num_node = elem.len();
    let mut num_cov = 0;
    for v in elem {
      if v.1 == true {num_cov += 1;}
    }
    let cov : f64 = num_cov as f64 / num_node as f64;
    if cov > 0.0 {
      rev_covs.push( ((1.0 -cov) * 1000.0) as u32);
      funcs.push ((k.clone(),num_node));
    }
  }
  if funcs.len() == 0 { return ("".to_string(), 0.0, 0);}
  let mut rng = rand::thread_rng();
  let wc = WeightedIndex::new(&rev_covs).unwrap();
  let tar_idx = wc.sample(&mut rng);
  ((&funcs)[tar_idx].0.clone(), -(rev_covs[tar_idx] as f64 / 1000.0 - 1.0), (&funcs)[tar_idx].1)
}
pub fn get_relevance(_new_target : String, input_path : &Path, executor : & mut Executor, funclist_f : &mut File,
                   func_map : &HashMap<String, Vec<(usize, bool)>>,
                   func_rel_map : &mut HashMap<String, HashMap<String, u32>>, num_input : &mut u32, o_dir : &Path, _cov : f64) {// -> Vec<(String, u32)> {
  let inputs = input_path.read_dir().expect("input_dir call failed");
  let mut num_executed = 0;
  for input in inputs {
    if let Ok(entry) = input {
      let path = &entry.path();
      if path.is_file(){
        let idnum = match &path.file_name().expect("can't get file_name").to_str().expect("can't get str of path")[3..].parse::<u32>() {
                    Ok(res) => *res, Err(_) => 0};
        if idnum < *num_input {continue;}
        let buf = read_from_file(path);
        executor.run_sync(&buf);
        let mut func_list : Vec<String> = executor.branches.get_func(func_map);
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
    let mut recid = 0;
    if !mkdir {loop {
      let filename = format!("rel_all_{}.csv", recid);
      let filepath = rel_dir.join(filename);
      if !filepath.exists() { break; } else {recid += 1;}
    }}
    let mut rel_all_file = OpenOptions::new().write(true).create(true)
                              .open( rel_dir.join(format!("rel_all_{}.csv",recid))).expect("can't open rel_all_file"); 
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

  /*
  let mut rels : Vec <(String, u32)> = Vec::new();
  let target_rels : &HashMap<String, u32> = func_rel_map.get(&new_target).expect("can't get new target from func_rel_map");
  let mut target_runs = 0;
  for (k, v) in target_rels{
    rels.push((k.clone(), *v));
    if *k == new_target { target_runs = *v; }
  }
  if target_runs != 0 {
    rels.retain(|x| (x.1 as f64 / target_runs as f64) > config::FUNC_REL_THRESHOLD);
  }

  
  // log relevant fucntions 
  if config::DEBUG_IO {
    let mut rel_file = OpenOptions::new().write(true).append(true).create(true).open(o_dir.parent().unwrap().join("rels.csv")).expect("Can't open rels.log file");
    if (*num_input - num_executed) == 0 {
      if let Err(_) = writeln!(rel_file,"input id,# of input,target,cov,target,max_rel,rel_funcs") { eprintln!("Can't write in rels.log file");} 
    }
    let mut rel_str = String::new();
    rel_str.push_str(&(*num_input - num_executed).to_string());
    rel_str.push_str(",");
    rel_str.push_str(&num_executed.to_string());
    rel_str.push_str(",");
    rel_str.push_str(&new_target);
    rel_str.push_str(",");
    rel_str.push_str(&format!("{:.2}",cov));
    rel_str.push_str(",");
    for elem in &rels{
      rel_str.push_str(&elem.0);
      rel_str.push_str(",");
      rel_str.push_str(&(&elem.1.to_string()));
      rel_str.push_str(",");
    }
    if let Err(_) = writeln!(rel_file,"{}",rel_str) { eprintln!("Can't write in rels.log file");}
  } */
  //rels
}
