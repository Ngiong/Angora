use crate::{
    branches::GlobalBranches, command::CommandOpt, cond_stmt::NextState, depot::Depot,
    executor::Executor, fuzz_type::FuzzType, search::*, stats,
};
//use angora_common::config;
use rand::prelude::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

pub fn fuzz_loop(
    running: Arc<AtomicBool>,
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    global_stats: Arc<RwLock<stats::ChartStats>>,
    func_cmp_map : Vec<Vec<u32>>,
    func_id_map : Vec<String>,
    cid : usize,
) {
    let search_method = cmd_opt.search_method;
    let mut func_rel_map : Vec<Vec<u32>> = vec![];
    for _i in 0..func_cmp_map.len() {
      let mut tmp_vec = vec![];
      for _j in 0..func_cmp_map.len() {
        tmp_vec.push(0);
      }
      func_rel_map.push(tmp_vec);
    };

    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        global_stats.clone(),
        func_rel_map,
        func_cmp_map,
        func_id_map,
        cid,
    );
    

    while running.load(Ordering::Relaxed) {
        let entry = match depot.get_entry() {
            Some(e) => e,
            None => break,
        };

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

        cond.belong_len = buf.len();

        {
            let fuzz_type = cond.get_fuzz_type();
            let handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf);
            match fuzz_type {
                FuzzType::ExploreFuzz => {
                    if handler.cond.is_time_expired() {
                      //If it is not the first time, move to next state
                        handler.cond.next_state(&depot, &mut handler.executor.local_stats, &handler.executor.cmd.taint_dir,
                                                        &handler.executor.func_cmp_map, &handler.executor.func_rel_map);
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

