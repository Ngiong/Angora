use bincode;
use std::path::PathBuf;
use std::fs;
use std::io::{Read, Write};

pub fn read_belongs(belongs_path : PathBuf, cmpid : u32) -> Vec<u32> {
  let file_path = belongs_path.join(format!("belong_{}", cmpid));
  if file_path.is_file() {
    let mut f = fs::File::open(file_path).ok().unwrap();
    let mut res = vec![];
    if let Ok(_) = f.read_to_end(&mut res) {
      bincode::deserialize(&res).unwrap()
    } else {
      warn!("can't read");
      vec![]
    }
  } else {
    warn!("can't find belongs file");
    vec![]
  }
}

pub fn write_belongs(belongs_path : PathBuf, cmpid : u32, new_belong : u32) {
  let file_path = belongs_path.join(format!("belong_{}", cmpid));

  let mut res = if file_path.is_file() {
    read_belongs(belongs_path, cmpid)
  } else {
    if let Err(e) = fs::File::create(file_path.clone()) {
      println!("{}",e);
      warn!("can't create belongs file");
    };
    vec![]
  };

  res.push(new_belong);
  let mut f = fs::OpenOptions::new().write(true).open(file_path).ok().unwrap();

  let encoded = bincode::serialize(&res).unwrap();
  if let Err(e) = f.write_all(&encoded) {
    println!("{}",e);
    warn!("couldn't write");
  }
}
