use crate::{check_dep, search, tmpfs};
use angora_common::defs;
use std::{
    //env,
    fs::File,
    io::{self, BufRead},
    path::{Path, PathBuf},
    process::Command,
};

static TMP_DIR: &str = "tmp";
static INPUT_FILE: &str = "cur_input";
static FORKSRV_SOCKET_FILE: &str = "forksrv_socket";
static TRACK_FILE: &str = "track";
//static PIN_ROOT_VAR: &str = "PIN_ROOT";

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstrumentationMode {
    LLVM,
    Pin,
}

impl InstrumentationMode {
    pub fn from(mode: &str) -> Self {
        match mode {
            "llvm" => InstrumentationMode::LLVM,
            "pin" => InstrumentationMode::Pin,
            _ => unreachable!(),
        }
    }

    pub fn is_pin_mode(&self) -> bool {
        self == &InstrumentationMode::Pin
    }
}

#[derive(Debug, Clone)]
pub struct CommandOpt {
    pub mode: InstrumentationMode,
    pub main_bin : String,
    pub main_args : Vec<Vec<String>>,
    pub track_bin : String,
    pub track_args : Vec<Vec<String>>,
    pub tmp_dir: PathBuf,
    pub taint_dir : PathBuf,
    pub out_file: String,
    pub forksrv_socket_path: String,
    pub track_path: String,
    pub is_stdin: bool,
    pub search_method: search::SearchMethod,
    pub mem_limit: u64,
    pub time_limit: u64,
    pub is_raw: bool,
    pub uses_asan: bool,
    pub ld_library: String,
    pub enable_afl: bool,
    pub enable_exploitation: bool,
    pub id : usize,
}

impl CommandOpt {
    pub fn new(
        mode: &str,
        track_target: &str,
        pargs: Vec<String>,
        out_dir: &Path,
        search_method: &str,
        mut mem_limit: u64,
        time_limit: u64,
        enable_afl: bool,
        enable_exploitation: bool,
        program_option : Option<&str>,
    ) -> Self {
        let mode = InstrumentationMode::from(mode);
        
        let tmp_dir = out_dir.join(TMP_DIR);
        let taint_dir = out_dir.join(defs::TAINTS_DIR);
        tmpfs::create_tmpfs_dir(&tmp_dir);

        let out_file = tmp_dir.join(INPUT_FILE).to_str().unwrap().to_owned();
        let forksrv_socket_path = tmp_dir
            .join(FORKSRV_SOCKET_FILE)
            .to_str()
            .unwrap()
            .to_owned();

        let track_path = tmp_dir.join(TRACK_FILE).to_str().unwrap().to_owned();

        //let has_input_arg = pargs.contains(&"@@".to_string()) || pargs.contains(&"@@@".to_string());

        let clang_lib = Command::new("llvm-config")
            .arg("--libdir")
            .output()
            .unwrap()
            .stdout;
        let clang_lib = String::from_utf8(clang_lib).unwrap();
        let ld_library = "$LD_LIBRARY_PATH:".to_string() + clang_lib.trim();

        assert_ne!(
            track_target, "-",
            "You should set track target with -t PROM in LLVM mode!"
        );

        let main_bin = pargs[0].clone();
        let uses_asan = check_dep::check_asan(&main_bin);
        if uses_asan && mem_limit != 0 {
            warn!("The program compiled with ASAN, set MEM_LIMIT to 0 (unlimited)");
            mem_limit = 0;
        }
        let track_bin = track_target.to_string();

        let main_args = match program_option {
            Some(filename) => {
                let mut res = vec![];
                let file = File::open(filename).unwrap();
                for line in io::BufReader::new(file).lines() {
                    match line {
                        Ok(mut line) => {
                            if line.len() != 0 {
                                line.retain(|c| c != '\n');
                                let splits : Vec<&str> = line.split(" ").collect();
                                let mut tmp = vec![];
                                for s in splits {
                                    tmp.push(String::from(s));
                                }
                                res.push(tmp);
                            }
                        },
                        _ => {break;}
                    }
                }
                res
            },
            None => {
                let mut tmp = pargs.clone();
                vec![tmp.drain(1..).collect()]
            },
        };

        let track_args = main_args.clone();
        /*
        if mode.is_pin_mode() {
            //TODO
            /*
            let project_bin_dir = env::var(defs::ANGORA_BIN_DIR).expect("Please set ANGORA_PROJ_DIR");
            
            let pin_root =
                env::var(PIN_ROOT_VAR).expect("You should set the environment of PIN_ROOT!");
            let pin_bin = format!("{}/{}", pin_root, "pin");
            track_bin = pin_bin.to_string();
            let pin_tool = Path::new(&project_bin_dir)
                .join("lib")
                .join("pin_track.so")
                .to_str()
                .unwrap()
                .to_owned();

            track_args.push(String::from("-t"));
            track_args.push(pin_tool);
            track_args.push(String::from("--"));
            track_args.push(track_target.to_string());
            track_args.extend(main_args.clone());
            */
        } else {
            track_bin = track_target.to_string();
            track_args = main_args.clone();
        }
        */

        Self {
            mode,
            main_bin : main_bin,
            main_args : main_args,
            track_bin : track_bin,
            track_args : track_args,
            tmp_dir,
            taint_dir,
            out_file: out_file,
            forksrv_socket_path,
            track_path,
            is_stdin: false, // !has_input_arg,
            search_method: search::parse_search_method(search_method),
            mem_limit,
            time_limit,
            uses_asan,
            is_raw: true,
            ld_library,
            enable_afl,
            enable_exploitation,
            id: 0,
        }
    }

    pub fn specify(&self, id: usize) -> Self {
        let mut cmd_opt = self.clone();
        let new_file = format!("{}_{}", &cmd_opt.out_file, id);
        let new_file2 = format!("@{}_{}", &cmd_opt.out_file, id);
        let new_forksrv_socket_path = format!("{}_{}", &cmd_opt.forksrv_socket_path, id);
        let new_track_path = format!("{}_{}", &cmd_opt.track_path, id);
        if !self.is_stdin {
            for main_args in cmd_opt.main_args.iter_mut() {
                for arg in main_args.iter_mut() {
                    if arg == "@@" {
                        *arg = new_file.clone();
                    } else if arg == "@@@" {
                        *arg = new_file2.clone();
                    }
                }
            }
            for track_args in cmd_opt.track_args.iter_mut() {
                for arg in track_args.iter_mut() {
                    if arg == "@@" {
                        *arg = new_file.clone();
                    } else if arg == "@@@" {
                        *arg = new_file2.clone();
                    }
                }
            }
        }
        cmd_opt.out_file = new_file.to_owned();
        cmd_opt.forksrv_socket_path = new_forksrv_socket_path.to_owned();
        cmd_opt.track_path = new_track_path.to_owned();
        cmd_opt.is_raw = false;
        cmd_opt
    }
}

impl Drop for CommandOpt {
    fn drop(&mut self) {
        if self.is_raw {
            tmpfs::clear_tmpfs_dir(&self.tmp_dir);
        }
    }
}
