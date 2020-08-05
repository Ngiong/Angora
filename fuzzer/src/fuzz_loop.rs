use crate::{
    branches::GlobalBranches, command::CommandOpt, cond_stmt::NextState, depot::Depot,
    executor::Executor, fuzz_type::FuzzType, search::*, stats,
};
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
) {
    let search_method = cmd_opt.search_method;
    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        global_stats.clone(),
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
        let (program_opts, buf) = parse_buf(&buf);

        {
            let fuzz_type = cond.get_fuzz_type();
            let handler = SearchHandler::new(running.clone(), &mut executor, &mut cond, buf);
            match fuzz_type {
                FuzzType::ExploreFuzz => {
                    if handler.cond.is_time_expired() {
                        handler.cond.next_state();
                    }
                    if handler.cond.state.is_one_byte() {
                        OneByteFuzz::new(handler, &program_opts).run();
                    } else if handler.cond.state.is_det() {
                        DetFuzz::new(handler, &program_opts).run();
                    } else {
                        match search_method {
                            SearchMethod::Gd => {
                                GdSearch::new(handler, &program_opts).run(&mut thread_rng());
                            },
                            SearchMethod::Random => {
                                RandomSearch::new(handler, &program_opts).run();
                            },
                            SearchMethod::Cbh => {
                                CbhSearch::new(handler, &program_opts).run();
                            },
                            SearchMethod::Mb => {
                                MbSearch::new(handler, &program_opts).run();
                            },
                        }
                    }
                },
                FuzzType::ExploitFuzz => {
                    if handler.cond.state.is_one_byte() {
                        let mut fz = OneByteFuzz::new(handler, &program_opts);
                        fz.run();
                        fz.handler.cond.to_unsolvable(); // to skip next time
                    } else {
                        ExploitFuzz::new(handler, &program_opts).run();
                    }
                },
                FuzzType::AFLFuzz => {
                    AFLFuzz::new(handler, &program_opts).run();
                },
                FuzzType::LenFuzz => {
                    LenFuzz::new(handler, &program_opts).run();
                },
                FuzzType::CmpFnFuzz => {
                    FnFuzz::new(handler, &program_opts).run();
                },
                FuzzType::OtherFuzz => {
                    warn!("Unknown fuzz type!!");
                },
            }
        }

        depot.update_entry(cond);
    }
}

pub fn parse_buf(buf: &Vec<u8>) -> (Vec<String>, Vec<u8>) {
    let mut opt = Vec::new();
    let mut content = Vec::new();
    let mut is_content_state = false;
    for (idx, dbuf) in buf.iter().enumerate() {
        let dbuf = *dbuf;
        if is_content_state {
            content.push(dbuf);
        } else {
            if idx > 0 && dbuf == 0 && buf[idx - 1] == 0 {
                is_content_state = true;
                continue;
            } else if dbuf == 0 && buf[idx + 1] == 0 {
                continue;
            }
            opt.push(dbuf);
        }
    }

    let program_opts = match String::from_utf8(opt) {
        Ok(raw_opt) => {
            let mut result = Vec::new();
            for i in raw_opt.split_whitespace() {
                result.push(String::from(i));
            }
            result
        },
        Err(_) => {
            warn!("Unable to parse program options from buf (fuzz_loop.rs::parse_buf)");
            Vec::new()
        },
    };
    (program_opts, content)
}
