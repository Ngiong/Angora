use super::{limit::SetLimit, *};

use crate::{
    branches, command,
    cond_stmt::{self, NextState},
    depot, stats, track,
};
use angora_common::{config, defs};

use std::{
    //ops::{Deref, DerefMut},
    fs,
    //fs::OpenOptions,
    //io::Write,
    collections::{HashMap, HashSet},
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{compiler_fence, Ordering},
        Arc, RwLock,
    },
    mem::size_of,
    alloc::{alloc, dealloc, Layout},
    ptr::null_mut,
    time,
};
use wait_timeout::ChildExt;

pub struct Executor {
    pub cmd: command::CommandOpt,
    pub branches: branches::Branches,
    pub t_conds: cond_stmt::ShmConds,
    envs: HashMap<String, String>,
    forksrv: Option<Forksrv>,
    depot: Arc<depot::Depot>,
    fd: PipeFd,
    tmout_cnt: usize,
    invariable_cnt: usize,
    pub last_f: u64,
    pub has_new_path: bool,
    pub global_stats: Arc<RwLock<stats::ChartStats>>,
    pub local_stats: stats::LocalStats,
    pub func_rel_map : *mut usize,
    pub func_num : usize,
    pub rel_rec_set : HashSet<usize>,
    pub cid : usize,
    pub taint_files : HashSet<u32>,
}

impl Executor {
    pub fn new(
        cmd: command::CommandOpt,
        global_branches: Arc<branches::GlobalBranches>,
        depot: Arc<depot::Depot>,
        global_stats: Arc<RwLock<stats::ChartStats>>,
        func_num : usize,
        cid : usize,
    ) -> Self {
        // ** Share Memory **
        let branches = branches::Branches::new(global_branches);
        let t_conds = cond_stmt::ShmConds::new();

        //println!("t_conds : new SHM, id : {}, ptr : {}", t_conds.get_id(), t_conds.get_ptr());

        // ** Envs **
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
        envs.insert(
            defs::LD_LIBRARY_PATH_VAR.to_string(),
            cmd.ld_library.clone(),
        );

        let fd = pipe_fd::PipeFd::new(&cmd.out_file);
        let forksrv = Some(forksrv::Forksrv::new(
            &cmd.forksrv_socket_path,
            &cmd.main,
            &envs,
            fd.as_raw_fd(),
            cmd.is_stdin,
            cmd.uses_asan,
            cmd.time_limit,
            cmd.mem_limit,
        ));
        


        //let func_rel_map = vec![vec![0; func_num].into_boxed_slice(); func_num].into_boxed_slice();

        unsafe {
            let func_rel_map = if func_num == 0 {
                null_mut()
            } else {
                let layout = Layout::from_size_align(size_of::<usize>() * func_num * func_num, size_of::<usize>()).unwrap();
                alloc(layout) as *mut usize
            };

        Self {
            cmd,
            branches,
            t_conds,
            envs,
            forksrv,
            depot,
            fd,
            tmout_cnt: 0,
            invariable_cnt: 0,
            last_f: defs::UNREACHABLE,
            has_new_path: false,
            global_stats,
            local_stats: Default::default(),
            func_rel_map : func_rel_map,
            func_num : func_num,
            rel_rec_set : HashSet::new(),
            cid : cid,
            taint_files : HashSet::new(),
        }
        }
    }

    pub fn rebind_forksrv(&mut self) {
        {
            // delete the old forksrv
            self.forksrv = None;
        }
        let fs = forksrv::Forksrv::new(
            &self.cmd.forksrv_socket_path,
            &self.cmd.main,
            &self.envs,
            self.fd.as_raw_fd(),
            self.cmd.is_stdin,
            self.cmd.uses_asan,
            self.cmd.time_limit,
            self.cmd.mem_limit,
        );
        self.forksrv = Some(fs);
    }

    // FIXME: The location id may be inconsistent between track and fast programs.
    fn check_consistent(&self, output: u64, cond: &mut cond_stmt::CondStmt) {
        if output == defs::UNREACHABLE
            && cond.is_first_time()
            && self.local_stats.num_exec == 1.into()
            && cond.state.is_initial()
        {
            cond.is_consistent = false;
            //warn!("inconsistent : {:?}", cond);
            //warn!("inconsistent : ");
        }
    }

    fn check_invariable(&mut self, output: u64, cond: &mut cond_stmt::CondStmt) -> bool {
        let mut skip = false;
        if output == self.last_f {
            self.invariable_cnt += 1;
            if self.invariable_cnt >= config::MAX_INVARIABLE_NUM {
                debug!("output is invariable! f: {}", output);
                if cond.is_desirable {
                    cond.is_desirable = false;
                }
                // deterministic will not skip
                if !cond.state.is_det() && !cond.state.is_one_byte() {
                    skip = true;
                }
            }
        } else {
            self.invariable_cnt = 0;
        }
        self.last_f = output;
        skip
    }

    fn check_explored(
        &self,
        cond: &mut cond_stmt::CondStmt,
        _status: StatusType,
        output: u64,
        explored: &mut bool,
    ) -> bool {
        let mut skip = false;
        // If crash or timeout, constraints after the point won't be tracked.
        if output == 0 && !cond.is_done()
        //&& status == StatusType::Normal
        {
            debug!("Explored this condition!");
            skip = true;
            *explored = true;
            cond.mark_as_done();
        }
        skip
    }

    pub fn run_with_cond(
        &mut self,
        buf: &Vec<u8>,
        cond: &mut cond_stmt::CondStmt,
    ) -> (StatusType, u64) {
        self.run_init();
        self.t_conds.set(cond); //cond_stmt::ShmConds
        let mut status = self.run_inner(buf);

        let output = self.t_conds.get_cond_output();
        let mut explored = false;
        let mut skip = false;
        //We don't have to target COND if it has been explored
        skip |= self.check_explored(cond, status, output, &mut explored);
        //We don't have to target COND if we can't change result
        skip |= self.check_invariable(output, cond);
        self.check_consistent(output, cond);

        self.do_if_has_new(buf, status, explored, cond.base.cmpid, cond.base.belong);
        status = self.check_timeout(status, cond);

        if skip {
            status = StatusType::Skip;
        }

        (status, output)
    }

    fn try_unlimited_memory(&mut self, buf: &Vec<u8>, cmpid: u32, belong : u32) -> bool {
        let mut skip = false;
        self.branches.clear_trace();
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
        compiler_fence(Ordering::SeqCst);
        let unmem_status =
            self.run_target(&self.cmd.main, config::MEM_LIMIT_TRACK, self.cmd.time_limit);
        compiler_fence(Ordering::SeqCst);

        // find difference
        if unmem_status != StatusType::Normal {
            skip = true;
            warn!(
                "Behavior changes if we unlimit memory!! status={:?}",
                unmem_status
            );
            // crash or hang
            if self.branches.has_new(unmem_status).0 {
                self.depot.save(unmem_status, &buf, cmpid, belong);
            }
        }
        skip
    }

    fn do_if_has_new(&mut self, buf: &Vec<u8>, status: StatusType, _explored: bool, cmpid: u32, belong : u32) {
        // new edge: one byte in bitmap
        let (has_new_path, has_new_edge, edge_num) = self.branches.has_new(status);

        // measure function block coverzage
        // Vec<usize>
        if has_new_path {
            self.has_new_path = true;
            self.local_stats.find_new(&status);
            let id = self.depot.save(status, &buf, cmpid, belong);
            //belong : id's seed tc
            //id : current tc

            if status == StatusType::Normal {
                self.local_stats.avg_edge_num.update(edge_num as f32);
                let speed = self.count_time();
                let speed_ratio = self.local_stats.avg_exec_time.get_ratio(speed as f32);
                self.local_stats.avg_exec_time.update(speed as f32);

                // Avoid track slow ones
                if (!has_new_edge && speed_ratio > 10 && id > 10) || (speed_ratio > 25 && id > 10) {
                    warn!(
                        "Skip tracking id {}, speed: {}, speed_ratio: {}, has_new_edge: {}",
                        id, speed, speed_ratio, has_new_edge
                    );
                    return;
                }
                let crash_or_tmout = self.try_unlimited_memory(buf, cmpid, belong);
                if !crash_or_tmout {
                    let cond_stmts = self.track(id, buf, speed);
                    if cond_stmts.len() > 0 {
                        unsafe {
                            self.depot.add_entries(&cond_stmts, self.func_rel_map, self.func_num, &mut self.taint_files);
                        }
                        if !self.rel_rec_set.contains(&id) && (self.func_num != 0) {
                          self.get_func_and_record(cond_stmts);
                          self.rel_rec_set.insert(id);
                        }
                        if self.cmd.enable_afl {
                            let tmp = vec![cond_stmt::CondStmt::get_afl_cond(id, speed, edge_num)];
                            unsafe {
                                self.depot
                                .add_entries(&tmp, self.func_rel_map, self.func_num, &mut self.taint_files);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn run(&mut self, buf: &Vec<u8>, cond: &mut cond_stmt::CondStmt) -> StatusType {
        self.run_init();
        let status = self.run_inner(buf);
        self.do_if_has_new(buf, status, false, 0, cond.base.belong);
        self.check_timeout(status, cond)
    }

    pub fn run_sync(&mut self, buf: &Vec<u8>) {
        self.run_init();
        let status = self.run_inner(buf);
        self.do_if_has_new(buf, status, false, 0, 0);
    }

    fn run_init(&mut self) {
        self.has_new_path = false;
        self.local_stats.num_exec.count(); //record # of execution
    }

    fn check_timeout(&mut self, status: StatusType, cond: &mut cond_stmt::CondStmt) -> StatusType {
        let mut ret_status = status;
        if ret_status == StatusType::Error {
            self.rebind_forksrv();
            ret_status = StatusType::Timeout;
        }

        if ret_status == StatusType::Timeout {
            self.tmout_cnt = self.tmout_cnt + 1;
            if self.tmout_cnt >= config::TMOUT_SKIP {
                cond.to_timeout();
                ret_status = StatusType::Skip;
                self.tmout_cnt = 0;
            }
        } else {
            self.tmout_cnt = 0;
        };

        ret_status
    }

    fn run_inner(&mut self, buf: &Vec<u8>) -> StatusType {
        self.write_test(buf);

        //clear a SHM area which recrods each execution ___.
        self.branches.clear_trace();

        compiler_fence(Ordering::SeqCst);
        let ret_status = if let Some(ref mut fs) = self.forksrv {
            fs.run()
        } else {
            self.run_target(&self.cmd.main, self.cmd.mem_limit, self.cmd.time_limit)
        };
        compiler_fence(Ordering::SeqCst);

        ret_status
    }

    fn count_time(&mut self) -> u32 {
        let t_start = time::Instant::now();
        for _ in 0..3 {
            if self.cmd.is_stdin {
                self.fd.rewind();
            }
            if let Some(ref mut fs) = self.forksrv {
                let status = fs.run();
                if status == StatusType::Error {
                    self.rebind_forksrv();
                    return defs::SLOW_SPEED;
                }
            } else {
                self.run_target(&self.cmd.main, self.cmd.mem_limit, self.cmd.time_limit);
            }
        }
        let used_t = t_start.elapsed();
        let used_us = (used_t.as_secs() as u32 * 1000_000) + used_t.subsec_nanos() / 1_000;
        used_us / 3
    }

    fn track(&mut self, id: usize, buf: &Vec<u8>, speed: u32) -> Vec<cond_stmt::CondStmt> {
        let taint_path = self.cmd.taint_dir.clone().join(format!("taints_{}", id));
        let track_path = self.cmd.tmp_dir.join(format!("track_{}",self.cid));
       // info!("try tracking {}", belong);
        self.envs.insert(
            defs::TRACK_OUTPUT_VAR.to_string(),
            //self.cmd.track_path.clone(),
            track_path.to_str().unwrap().to_string(),
        );

        let t_now: stats::TimeIns = Default::default();

        self.write_test(buf);

        compiler_fence(Ordering::SeqCst);
        let ret_status = self.run_target(
            &self.cmd.track,
            config::MEM_LIMIT_TRACK,
            //self.cmd.time_limit *
            config::TIME_LIMIT_TRACK,
        );
        compiler_fence(Ordering::SeqCst);

        if ret_status != StatusType::Normal {
            error!(
                "Crash or hang while tracking! -- {:?},  id: {}",
                ret_status, id
            );
            return vec![];
        }

        let cond_list = track::load_track_data(
            //Path::new(&self.cmd.track_path),
            Path::new(&track_path),
            id as u32,
            speed,
            self.cmd.mode.is_pin_mode(),
            self.cmd.enable_exploitation,
        );
        if config::TC_SEL_FUNC_REL {
          if let Err(_) = fs::copy(&track_path, &taint_path) {
            println!("can't copy taint file");
          }
        }
        self.local_stats.track_time += t_now.into();
        cond_list
    }

    pub fn random_input_buf(&self) -> Vec<u8> {
        let id = self.depot.next_random();
        self.depot.get_input_buf(id)
    }

    fn write_test(&mut self, buf: &Vec<u8>) {
        self.fd.write_buf(buf);
        if self.cmd.is_stdin {
            self.fd.rewind();
        }
    }

    fn run_target(
        &self,
        target: &(String, Vec<String>),
        mem_limit: u64,
        time_limit: u64,
    ) -> StatusType {
        let mut cmd = Command::new(&target.0);
        let mut child = cmd
            .args(&target.1)
            .stdin(Stdio::null())
            .env_clear()
            .envs(&self.envs)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .mem_limit(mem_limit.clone())
            .setsid()
            .pipe_stdin(self.fd.as_raw_fd(), self.cmd.is_stdin)
            .spawn()
            .expect("Could not run target");

        let timeout = time::Duration::from_secs(time_limit);
        let ret = match child.wait_timeout(timeout).unwrap() {
            Some(status) => {
                if let Some(status_code) = status.code() {
                    if (self.cmd.uses_asan && status_code == defs::MSAN_ERROR_CODE)
                        || (self.cmd.mode.is_pin_mode() && status_code > 128)
                    {
                        StatusType::Crash
                    } else {
                        StatusType::Normal
                    }
                } else {
                    StatusType::Crash
                }
            }
            None => {
                // Timeout
                // child hasn't exited yet
                child.kill().expect("Could not send kill signal to child.");
                child.wait().expect("Error during waiting for child.");
                StatusType::Timeout
            }
        };
        ret
    }
    
    pub fn get_func_and_record(&mut self, cond_list : Vec<cond_stmt::CondStmt>) {
      //the set of all executed function
      let mut func_set : HashSet<usize> = HashSet::new();
      for c in cond_list{
        func_set.insert(c.base.belong_func as usize);
      }
      for f1 in &func_set{
        for f2 in &func_set{
           let index = f1 * self.func_num + f2;
           unsafe {
               let indexed_ptr = self.func_rel_map.offset(index as isize);
               *indexed_ptr += 1;
           }
           //self.func_rel_map.deref_mut()[*f1].deref_mut()[*f2] += 1;
        }
      }
    }

    pub fn update_log(&mut self) {
        self.global_stats
            .write()
            .unwrap()
            .sync_from_local(&mut self.local_stats);

        self.t_conds.clear();
        self.tmout_cnt = 0;
        self.invariable_cnt = 0;
        self.last_f = defs::UNREACHABLE;
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        if self.cid != 255 && self.func_num != 0 {
            /*
            let time_path = self.cmd.tmp_dir.as_path().parent().unwrap().join(format!("func_time_{}", self.cid));
            let mut time_file = OpenOptions::new().write(true).create(true)
                    .open(time_path).expect("can't open time_file");
            writeln!(time_file, "Func rel overhead (in millis) : {}",
                self.global_stats.read().unwrap().func_time.0.as_millis()).unwrap();
            info!("dump func rel ..");
            let rel_path = self.cmd.tmp_dir.as_path().parent().unwrap().join("rels");
            fs::create_dir(&rel_path).unwrap_or_else(|_| ());
            let mut rel_all_file = OpenOptions::new().write(true).create(true)
                    .open(rel_path.join(format!("rel_all_{}.csv",self.cid))).expect("can't open rel_all_file");
            
            write!(rel_all_file, ",").unwrap();
            for func_id in 0..self.func_num {
                write!(rel_all_file, "{},", func_id).unwrap();
            }
            writeln!(rel_all_file, "").unwrap();
            for (i, f1) in self.func_rel_map.iter().enumerate() {
                write!(rel_all_file, "{},", i).unwrap();
                for f2 in f1.deref() {
                    write!(rel_all_file, "{},", f2).unwrap();
                }
                writeln!(rel_all_file, "").unwrap();
            }
            */

            unsafe {
                let layout = Layout::from_size_align(size_of::<usize>() * self.func_num * self.func_num, size_of::<usize>()).unwrap();
                dealloc(self.func_rel_map as *mut u8, layout);
            }
        }
    }
}