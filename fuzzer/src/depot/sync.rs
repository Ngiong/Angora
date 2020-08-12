use super::*;
use crate::executor::Executor;
use angora_common::{config, defs};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub fn sync_depot(executor: &mut Executor, running: Arc<AtomicBool>, dir: &Path) {
    executor.local_stats.clear();
    let seed_dir = dir.read_dir().expect("read_dir call failed");
    for entry in seed_dir {
        if let Ok(entry) = entry {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            let path = &entry.path();
            if path.is_file() {
                let file_len =
                    fs::metadata(path).expect("Could not fetch metadata.").len() as usize;
                if file_len < config::MAX_INPUT_LEN {
                    let buf = read_from_file(path);
                    let program_opts = executor.cmd.init_program_opts.clone();
                    executor.run_sync(&buf, &program_opts);

                } else {
                    warn!("Seed discarded, too long: {:?}", path);
                }
            }
        }
    }
    info!("sync {} file from seeds.", executor.local_stats.num_inputs);
    executor.update_log();
}

// Now we are in a sub-dir of AFL's output dir
pub fn sync_afl(
    executor: &mut Executor,
    running: Arc<AtomicBool>,
    sync_dir: &Path,
    sync_ids: &mut HashMap<String, usize>,
) {
    executor.rebind_forksrv();
    executor.local_stats.clear();

    if let Ok(entries) = sync_dir.read_dir() {
        for entry in entries {
            if let Ok(entry) = entry {
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    let file_name = entry.file_name().into_string();
                    if let Ok(name) = file_name {
                        if !name.contains(defs::ANGORA_DIR_NAME) && !name.starts_with(".") {
                            let path = entry_path.join("queue");
                            if path.is_dir() {
                                sync_one_afl_dir(executor, running.clone(), &path, &name, sync_ids);
                            }
                        }
                    }
                }
            }
        }
    }

    let n: usize = executor.local_stats.num_inputs.into();
    info!("sync {} file from AFL.", n);

    executor.update_log();
}

fn get_afl_id(f: &fs::DirEntry) -> Option<usize> {
    let file_name = f.file_name().into_string();
    if let Ok(name) = file_name {
        if name.len() >= 9 {
            let id_str = &name[3..9];
            if let Ok(id) = id_str.parse::<usize>() {
                return Some(id);
            }
        }
    }
    None
}

fn sync_one_afl_dir(
    executor: &mut Executor,
    running: Arc<AtomicBool>,
    sync_dir: &Path,
    sync_name: &str,
    sync_ids: &mut HashMap<String, usize>,
) {
    let min_id = *sync_ids.get(sync_name).unwrap_or(&0);
    let mut max_id = min_id;
    let seed_dir = sync_dir
        .read_dir()
        .expect("read_dir call failed while syncing afl ..");
    for entry in seed_dir {
        if let Ok(entry) = entry {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            let path = &entry.path();
            if path.is_file() {
                if let Some(id) = get_afl_id(&entry) {
                    if id >= min_id {
                        let file_len = fs::metadata(path).unwrap().len() as usize;
                        if file_len < config::MAX_INPUT_LEN {
                            let buf = read_from_file(path);
                            let program_opts = executor.cmd.init_program_opts.clone();
                            executor.run_sync(&buf, &program_opts);
                        }
                        if id > max_id {
                            max_id = id;
                        }
                    }
                }
            }
        }
    }

    sync_ids.insert(sync_name.to_string(), max_id + 1);
}
