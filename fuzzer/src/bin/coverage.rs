extern crate clap;
use clap::{App, Arg};

use libc;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync:: {
        atomic::{compiler_fence, Ordering},
        Arc,
    },
    collections::HashMap,
};
extern crate angora;
extern crate angora_common;

use angora_common::{defs, config};
use angora::depot::file::read_from_file;
use angora::executor::{Forksrv, PipeFd, StatusType};
use angora::{branches, cond_stmt};

struct CommandSmallOpt {
    pub main_bin : String,
    pub main_args : Vec<Vec<String>>,
    pub forksrv_socket_path: Vec<String>,
    pub out_file : String,
    pub mem_limit: u64,
    pub time_limit : u64,
}

impl CommandSmallOpt {
    pub fn new (
        pargs : &str,
        main_bin : &str,
        mem_limit : u64,
        time_limit : u64,
    ) -> Self {

        let tmp : Vec<&str> = pargs.split(":::").collect();
        let mut main_args : Vec<Vec<String>> = vec![];
        for t in tmp {
            main_args.push(t.split(" ").map(String::from).collect::<Vec<String>>());
        }

        //create a tmp dir for socket path
        let shm_dir = Path::new("/dev/shm");
        let tmp_dir : PathBuf = if shm_dir.is_dir() {
            let pid = unsafe {libc::getpid() as usize};
            let dir_name = format!("angora_tmp_{}", pid);
            let tmp_dir = shm_dir.join(dir_name);
            fs::create_dir(&tmp_dir).unwrap();
            tmp_dir.as_path().to_owned()
        } else {
            let tmp_dir = Path::new("/home/cheong/tmp");
            fs::create_dir(&tmp_dir).unwrap();
            tmp_dir.to_owned()
        };

        let forksrv_socket_path = tmp_dir.join("forksrv_socket").to_str().unwrap().to_owned();
        let out_file = tmp_dir.join("cur_input").to_str().unwrap().to_owned();

        Self {
            main_bin : main_bin.to_string(),
            main_args,
            forksrv_socket_path : vec![forksrv_socket_path],
            out_file,
            mem_limit,
            time_limit,
        }
    }

    pub fn specify(&mut self) {

        let mut new_forksrv_socket_path = vec![];

        for i in 0..self.main_args.len() {
            new_forksrv_socket_path.push(format!("{}_{}", self.forksrv_socket_path[0], i));
        }

        for main_arg in self.main_args.iter_mut() {
            for arg in main_arg.iter_mut() {
                if arg == "@@" {
                    *arg = self.out_file.clone();
                }    
            }
        }

        self.forksrv_socket_path = new_forksrv_socket_path;
    }
}

impl Drop for CommandSmallOpt {
    fn drop(&mut self) {
        let shm_dir = Path::new("/dev/shm");
        if shm_dir.is_dir() {
            let pid = unsafe {libc::getpid() as usize};
            let dir_name = format!("angora_tmp_{}", pid);
            let tmp_dir = shm_dir.join(dir_name);
            fs::remove_dir_all(&tmp_dir).unwrap();
        }
    }
}

fn init_coverage(
    in_dir : &str,
    out_file : &str,
    main_bin : &str,
    pargs: &str,
) {

    let mut cmd = CommandSmallOpt::new(
        pargs,
        main_bin,
        config::MEM_LIMIT,
        config::TIME_LIMIT,
    );

    cmd.specify();

    let global_branches = Arc::new(branches::GlobalBranches::new());
    let t_conds = cond_stmt::ShmConds::new();
    let mut branches = branches::Branches::new(global_branches);

    let mut envs = HashMap::new();
    envs.insert(
        defs::ASAN_OPTIONS_VAR.to_string(),
        defs::ASAN_OPTIONS_CONTENT.to_string(),
    );
    envs.insert(
        defs::MSAN_OPTIONS_VAR.to_string(),
        defs::MSAN_OPTIONS_CONTENT.to_string(),
    );
    envs.insert(
        defs::BRANCHES_SHM_ENV_VAR.to_string(),
        branches.get_id().to_string(),
    );
    envs.insert(
        defs::COND_STMT_ENV_VAR.to_string(),
        t_conds.get_id().to_string(),
        
    );
    let mut fd = PipeFd::new(&cmd.out_file);

    let mut forksrvs = vec![];

    for i in 0..cmd.main_args.len() {
        let forksrv = Forksrv::new(
            &cmd.forksrv_socket_path[i],
            &cmd.main_bin,
            &cmd.main_args[i],
            &envs,
            fd.as_raw_fd(),
            false,
            false,
            cmd.time_limit,
            cmd.mem_limit,
        );

        forksrvs.push(forksrv);
    }
    
    let input_dir = Path::new(in_dir);

    let mut file = fs::OpenOptions::new()
    .read(true)
    .append(true)
    .create(true)
    .open(out_file).unwrap();

    for entry in input_dir.read_dir().unwrap() {
        if let Ok(entry) = entry {
            let path = &entry.path();
            if path.is_file() {
                let file_len = fs::metadata(path).unwrap().len() as usize;
                if file_len < config::MAX_INPUT_LEN {
                    let buf = read_from_file(path);
                    fd.write_buf(&buf);

                    for forksrv in &mut forksrvs {
                        compiler_fence(Ordering::SeqCst);

                        let ret_status = forksrv.run();
                        compiler_fence(Ordering::SeqCst);
                        
                        match ret_status {
                            StatusType::Normal => {
                                branches.has_new(StatusType::Normal);
                            },
                            s => {
                                println!("run error! : {:?}", s);
                                //writeln!(file, "0").unwrap();
                                return;
                            }
                        }

                        branches.clear_trace();
                    }
                } else {
                    println!("too long, discarded");
                }
            }
        }
    }

    //println!("cov : {}", branches.get_cov());
    branches.write_cov(&mut file);
}


fn main() {
    let matches = App::new("coverage")
        .arg(Arg::with_name("input_dir")
            .short("i")
            .long("input")
            .value_name("DIR")
            .help("input dir")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("output_file")
            .short("o")
            .long("output")
            .value_name("FILE")
            .help("output file")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("pargs")
            .short("p")
            .help("program arguments")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("executable")
            .short("e")
            .value_name("EXEC")
            .help("exec binary file instrumented with Angora")
            .required(true)
            .takes_value(true))
        .get_matches();

    init_coverage(
        matches.value_of("input_dir").unwrap(),
        matches.value_of("output_file").unwrap(),
        matches.value_of("executable").unwrap(),
        matches.value_of("pargs").unwrap(),
    );
}