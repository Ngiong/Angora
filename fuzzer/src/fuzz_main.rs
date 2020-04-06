use crate::stats::*;
use angora_common::{defs, config};
use chrono::prelude::Local;
use std::{
    collections::HashMap,
    fs,
    time::{Duration, Instant},
    io::prelude::*,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    thread, time,
};

use crate::{bind_cpu, branches, check_dep, command, depot, executor, fuzz_loop, stats};
use ctrlc;
use libc;
use pretty_env_logger;

pub fn fuzz_main(
    mode: &str,
    in_dir: &str,
    out_dir: &str,
    track_target: &str,
    pargs: Vec<String>,
    num_jobs: usize,
    mem_limit: u64,
    time_limit: u64,
    search_method: &str,
    sync_afl: bool,
    enable_afl: bool,
    enable_exploitation: bool,
    func_cmp_map : Option<&str>
) {
    pretty_env_logger::init();

    let (seeds_dir, angora_out_dir) = initialize_directories(in_dir, out_dir, sync_afl);
    let command_option = command::CommandOpt::new(
        mode,
        track_target,
        pargs,
        &angora_out_dir,
        search_method,
        mem_limit,
        time_limit,
        enable_afl,
        enable_exploitation,
    );
    info!("{:?}", command_option);
    check_dep::check_dep(in_dir, out_dir, &command_option);

    let depot = Arc::new(depot::Depot::new(seeds_dir, &angora_out_dir)); //queue for main fuzz loop
    info!("{:?}", depot.dirs);

    let (func_cmp_map, func_id_map) = get_func_maps (func_cmp_map); 

    record_parameter(&angora_out_dir, &command_option, in_dir);
    let stats = Arc::new(RwLock::new(stats::ChartStats::new(&track_target ,&out_dir, func_cmp_map.len() != 0)));
    let global_branches = Arc::new(branches::GlobalBranches::new());  //To record global path coverage (edge cov?)
    let fuzzer_stats = create_stats_file_and_write_pid(&angora_out_dir);
    let running = Arc::new(AtomicBool::new(true)); //check whether the fuzzing is running
    set_sigint_handler(running.clone());

    let mut executor = executor::Executor::new(
        command_option.specify(0),
        global_branches.clone(),
        depot.clone(),
        stats.clone(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        255
    );

    //put seed in the queue
    depot::sync_depot(&mut executor, running.clone(), &depot.dirs.seeds_dir);

    if depot.empty() {
        error!("Failed to find any branches during dry run.");
        error!("Please ensure that the binary has been instrumented and/or input directory is populated.");
        error!(
            "Please ensure that seed directory - {:?} has any file.",
            depot.dirs.seeds_dir
        );
        panic!();
    }

    let (handles, child_count) = init_cpus_and_run_fuzzing_threads(
        num_jobs,
        &running,
        &command_option,
        &global_branches,
        &depot,
        &stats,
        &func_cmp_map, 
        &func_id_map,
    );
   
    let taint_dir = angora_out_dir.join(defs::TAINTS_DIR);

    let log_file = match fs::File::create(angora_out_dir.join(defs::ANGORA_LOG_FILE)) {
        Ok(a) => a,
        Err(e) => {
            error!("FATAL: Could not create log file: {:?}", e);
            panic!();
        }
    };

    main_thread_sync_and_log(
        log_file,
        out_dir,
        sync_afl,
        running.clone(),
        &mut executor,
        &depot,
        &global_branches,
        &stats,
        child_count,
    );

    for handle in handles {
        if handle.join().is_err() {
            error!("Error happened in fuzzing thread!");
        }
    }
    match fs::remove_dir(&taint_dir) {
       Ok(_) => (),
       Err(e) => warn!("Could not remove the taints dir : {:?}", e),
    }

    match fs::remove_file(&fuzzer_stats) {
        Ok(_) => (),
        Err(e) => warn!("Could not remove fuzzer stats file: {:?}", e),
    };
}


fn get_func_maps (s : Option<&str>) -> (HashMap<u32, Vec<u32>>, HashMap<u32, String>) {
  if s == None {return (HashMap::new(),HashMap::new())}
  let mut ff = fs::File::open(s.unwrap()).expect("File not Found");
  let mut conts = String::new();
  ff.read_to_string(&mut conts).expect("Can't read file");
  let mut func_cmp_map : HashMap<u32, Vec<u32>> = HashMap::new();
  let mut func_id_map : HashMap<u32,String> = HashMap::new();
  let mut cmplist : Vec<u32> = Vec::new();
  let mut funcname = String::new();
  let mut cmpid = String::new();
  let mut func_id = 0;
  let mut stage = 0; // 0 for funcname, 1 for tmp, 2 for cmp
  for c in conts.chars() {
    match &stage {
      0 => { if c == ',' {
               stage = 1;
             } else {
               funcname.push(c);
             }
           },
      1 => { if c == '\n' { stage = 2; } },
      2 => { if c == '\n' {
               stage = 0;
               func_cmp_map.insert(func_id, cmplist);
               func_id_map.insert(func_id,funcname);
               func_id += 1;
               funcname = String::new();
               cmplist = Vec::new();
            } else if c == ',' {
               cmplist.push(cmpid.parse::<u32>().unwrap());
               cmpid = String::new();
            } else {
               cmpid.push(c);
            }
           },
       _ => {panic!();},
    };
  }
  (func_cmp_map, func_id_map)
}


fn initialize_directories(in_dir: &str, out_dir: &str, sync_afl: bool) -> (PathBuf, PathBuf) {
    let angora_out_dir = if sync_afl {
        gen_path_afl(out_dir)
    } else {
        PathBuf::from(out_dir)
    };

    let restart = in_dir == "-";
    if !restart {
        fs::create_dir(&angora_out_dir).expect("Output directory has existed!");
    }

    let out_dir = &angora_out_dir;
    let seeds_dir = if restart {
        let orig_out_dir = out_dir.with_extension(Local::now().to_rfc3339());
        fs::rename(&out_dir, orig_out_dir.clone()).unwrap();
        fs::create_dir(&out_dir).unwrap();
        PathBuf::from(orig_out_dir).join(defs::INPUTS_DIR)
    } else {
        PathBuf::from(in_dir)
    };
    
    let taints_dir = out_dir.join(defs::TAINTS_DIR);
    fs::create_dir(&taints_dir).unwrap();


    (seeds_dir, angora_out_dir)
}

fn gen_path_afl(out_dir: &str) -> PathBuf {
    let base_path = PathBuf::from(out_dir);
    let create_dir_result = fs::create_dir(&base_path);
    if create_dir_result.is_err() {
        warn!("dir has existed. {:?}", base_path);
    }
    base_path.join(defs::ANGORA_DIR_NAME)
}

fn set_sigint_handler(r: Arc<AtomicBool>) {
    ctrlc::set_handler(move || {
        warn!("Ending Fuzzing.");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting SIGINT handler!");
}

fn record_parameter(out_dir: &PathBuf, command : &command::CommandOpt, in_dir : &str) {
  let fuzz_param = out_dir.join("parameters");
  let mut buff = match fs::File::create(&fuzz_param) {
    Ok(a) => a,
    Err(e) => { error!("Could not create param file : {:?}", e); panic!();}
  };
  write!(buff, "out_dir : {}, in_dir : {}, mem_limit : {}, subject: {}, timeout : {}H, func_rel cal tc selection : {}, tc selection with func_rel : {}, tc selection random : {} ",
               out_dir.to_str().unwrap(), in_dir, command.mem_limit, command.main.0,
               config::FUZZ_TIME_OUT / 3600, config::FUNC_REL_TC_SELECT, config::MUTATE_TC_SELECT, config::MUTATE_RANDOM)
         .expect("Could not write to param file");
  writeln!(buff, "").expect("Could not write");
  for s in &command.main.1{
    write!(buff," {}", s).expect("Could not write to param file");
  }
  writeln!(buff,"").expect("Could nout write to param file");
  write!(buff, ", MAP_SIZE : {}, H_THRESHOLD: {}",
         config::MAP_SIZE_POW2, 
         config::FUNC_REL_HIGH_THRESHOLD).expect("Could not write to param file");
}

fn create_stats_file_and_write_pid(angora_out_dir: &PathBuf) -> PathBuf {
    // To be compatible with AFL.
    let fuzzer_stats = angora_out_dir.join("fuzzer_stats");
    let pid = unsafe { libc::getpid() as usize };
    let mut buffer = match fs::File::create(&fuzzer_stats) {
        Ok(a) => a,
        Err(e) => {
            error!("Could not create stats file: {:?}", e);
            panic!();
        }
    };
    write!(buffer, "fuzzer_pid : {}", pid).expect("Could not write to stats file");
    fuzzer_stats
}

fn init_cpus_and_run_fuzzing_threads(
    num_jobs: usize,
    running: &Arc<AtomicBool>,
    command_option: &command::CommandOpt,
    global_branches: &Arc<branches::GlobalBranches>,
    depot: &Arc<depot::Depot>,
    stats: &Arc<RwLock<stats::ChartStats>>,
    func_cmp_map : &HashMap<u32, Vec<u32>>,
    func_id_map : &HashMap<u32, String>,
) -> (Vec<thread::JoinHandle<()>>, Arc<AtomicUsize>) {
    let child_count = Arc::new(AtomicUsize::new(0));
    let mut handlers = vec![];
    let free_cpus = bind_cpu::find_free_cpus(num_jobs);
    let free_cpus_len = free_cpus.len();
    let bind_cpus = if free_cpus_len < num_jobs {
        warn!("The number of free cpus is less than the number of jobs. Will not bind any thread to any cpu.");
        false
    } else {
        true
    };
    for thread_id in 0..num_jobs {
        let c = child_count.clone();
        let r = running.clone();
        let cmd = command_option.specify(thread_id + 1);
        let d = depot.clone();
        let b = global_branches.clone();
        let s = stats.clone();
        let fcmp = func_cmp_map.clone();
        let fid = func_id_map.clone();
        let cid = if bind_cpus { free_cpus[thread_id] } else { 0 };
        let handler = thread::spawn(move || {
            c.fetch_add(1, Ordering::SeqCst);
            if bind_cpus {
                bind_cpu::bind_thread_to_cpu_core(cid);
            }
            fuzz_loop::fuzz_loop(r, cmd, d, b, s, fcmp, fid, cid);
        });
        handlers.push(handler);
    }
    (handlers, child_count)
}

fn main_thread_sync_and_log(
    mut log_file: fs::File,
    out_dir: &str,
    sync_afl: bool,
    running: Arc<AtomicBool>,
    executor: &mut executor::Executor,
    depot: &Arc<depot::Depot>,
    global_branches: &Arc<branches::GlobalBranches>,
    stats: &Arc<RwLock<stats::ChartStats>>,
    child_count: Arc<AtomicUsize>,
) {
    let mut last_explore_num = stats.read().unwrap().get_explore_num();
    let sync_dir = Path::new(out_dir);
    let mut synced_ids = HashMap::new();
    if sync_afl {
        depot::sync_afl(executor, running.clone(), sync_dir, &mut synced_ids);
    }
    if let Err(_) = writeln!(log_file, "time,density,queue,hang,crash,exec_time,one_byte,first,second,merged,det,timeout,unsolvable,func,funcrel,normal_end") {
      eprintln!("can't write angora.log"); }
    let mut sync_counter = 1;
    show_stats(&mut log_file, depot, global_branches, stats);
    let init_time = Instant::now();
    while running.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::from_secs(5));
        if init_time.elapsed() >= Duration::from_secs(config::FUZZ_TIME_OUT.into()) {
          running.store(false, Ordering::SeqCst);
          warn!("Fuzzing End with Timeout");
        }
          //let out_path = Path::new(out_dir);
          //depot.log(&out_path, &mut depot_rec_idx);
        sync_counter -= 1;
        if sync_afl && sync_counter <= 0 {
            depot::sync_afl(executor, running.clone(), sync_dir, &mut synced_ids);
            sync_counter = 12;
        }

        show_stats(&mut log_file, depot, global_branches, stats);
        if Arc::strong_count(&child_count) == 1 {
            let s = stats.read().unwrap();
            let cur_explore_num = s.get_explore_num();
            if cur_explore_num == 0 {
                warn!("There is none constraint in the seeds, please ensure the inputs are vaild in the seed directory, or the program is ran correctly, or the read functions have been marked as source.");
                break;
            } else {
                if cur_explore_num == last_explore_num {
                    info!("Solve all constraints!!");
                    break;
                }
                last_explore_num = cur_explore_num;
            }
        }
    }
}
