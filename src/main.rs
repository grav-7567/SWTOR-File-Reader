use std::fmt::format;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, create_dir_all};
use zlib_rs::{InflateConfig, ReturnCode, decompress_slice};
use std::time::Instant;

fn main() {
    let mut hashmap: HashMap<u64, String> = HashMap::new();
    
    let mut now = Instant::now();
    if let Ok(lines) = read_lines("filenames-live.txt") {
        // Consumes the iterator, returns an (Optional) String
        for line in lines.map_while(Result::ok) {
            let path = line.clone();
            let hash = hashlittle2(path.as_bytes().to_vec());
            hashmap.insert(hash, path);
        }
    }
    let mut elapsed_time = now.elapsed();
    println!("Loaded hash table in {:.2} s", elapsed_time.as_secs_f32());

    let assets_path = String::from("D:/projects/rs/slicing_testing");
    let out_root_path = String::from("D:/projects/rs/slicing_testing/out");
    let filetype = ArchiveType::LIVE;

    now = Instant::now();
    let archives = get_archives(assets_path);
    elapsed_time = now.elapsed();
    println!("Fetched archives in {} us", elapsed_time.as_micros());

    now = Instant::now();
    let jobs = get_extraction_candidates(&archives, out_root_path, filetype, hashmap);
    elapsed_time = now.elapsed();
    println!("Fetched extraction candidates in {} ms", elapsed_time.as_millis());

    //distribute jobs
    now = Instant::now();
    let mut completed = 0;
    let mut failed = 0;
    for job in jobs {
        match extract(&archives, job) {
            true =>     { completed += 1; }
            false =>    { failed += 1; }
        }
    }
    elapsed_time = now.elapsed();
    println!("Extracted {} files in {:.2} s. ({} failed extractions).", completed, elapsed_time.as_secs_f32(), failed);
}
#[derive(Clone)]
enum ArchiveType {
    LIVE,
    PTS,
    BETA,
}

struct Job {
    data_offset:        u64,
    compressed_size:    u32,
    compression:        u32,
    asset_path_addr:    usize,
    destination:        PathBuf
}

fn get_archives(assets_path: String) -> Vec<PathBuf> {
    let archivepaths = fs::read_dir(assets_path).expect("Failed to get files in the selected directory. Does this directory exist?");
    
    let mut file_list: Vec<PathBuf> = Vec::new();
    for archivepath in archivepaths {
        let Ok(archivepath) = archivepath else {
            println!("A file in this folder is invalid. Skipping.");
            continue;
        };
        match archivepath.file_type() {
            Ok(typ)   => { 
                if !typ.is_file() { 
                    println!("Skipping a directory or symlink"); // maybe add a config to follow directories and symlinks
                    continue; 
                }
            },
            Err(_)              => {
                println!("A file in this folder is invalid. Skipping.");
                continue;
            }
        }
        let archivepath = archivepath.path();
        if let Some(ext) = archivepath.extension() {
            if !(ext == OsStr::new("tor")) {
                println!("Skipping a file which is not a .tor archive."); // maybe add a config to ignore extension
                continue;
            }
        }
        else {
            println!("Skipping a file without an extension.");
            continue;
        }
        file_list.push(archivepath);
    }
    file_list
}

fn get_extraction_candidates(file_list: &Vec<PathBuf>, out_root_path: String, filetype: ArchiveType, hashmap: HashMap<u64, String>) -> Vec<Job> {
    let mut outputs: Vec<Job> = vec![];

    for (i, file) in file_list.iter().enumerate() {
        let f = File::open(&file);
        let Ok(mut f) = f else {
            println!("A file in this folder cannot be opened. Skipping.");
            continue;
        };

        /*======================================STANDARD TOR ARCHIVE HEADER======================================*\
        | Magic Number  |     Version      |   Endianness   |      Index Offset       |  Capacity   | File Count  |
        |  4D 59 50 00  | ZSTD=06 00 00 00 | BE=43 EC 23 FD | NN NN NN NN NN NN NN NN | NN NN NN NN | NN NN NN NN |
        |  M  Y  P  \0  | ZLIB=05 00 00 00 | LE=unknown     |                         |             |             |
        \*=======================================================================================================*/

        f.seek(SeekFrom::Start(0)).expect("Error reading file.");
        let magicnumber =       _read_u32(&mut f, false);
        let mut version =       _read_u32(&mut f, false);
        let endianness =        _read_u32(&mut f, false);
        let is_bigendian =     verifyheader(magicnumber, &mut version, endianness);
        let mut tableoffset =   _read_u64(&mut f, is_bigendian);
        let _capacity =          _read_u32(&mut f, is_bigendian);
        let _filecount =         _read_u32(&mut f, is_bigendian);

        //LOOP OVER TABLES
        while tableoffset != 0 {
            f.seek(SeekFrom::Start(tableoffset)).expect("Error reading file.");
            let tablecapacity = _read_u32(&mut f, is_bigendian);
            tableoffset = _read_u64(&mut f, is_bigendian);

            //LOOP OVER ENTRIES IN TABLE
            for _ in 0..tablecapacity {
                let mut e_offset =      _read_u64(&mut f, is_bigendian);
                if e_offset == 0 { break; }

                //check for 0x200002 at offset
                let returnpoint =   f.stream_position().unwrap();
                f.seek(SeekFrom::Start(e_offset)).unwrap();
                if _read_u32(&mut f, is_bigendian) == 0x200002 {
                    f.seek(SeekFrom::Start(returnpoint)).unwrap();
                }
                else {
                    println!("Skipping bad/corrupt entry.");
                    continue;
                }

                e_offset +=                  _read_u32(&mut f, is_bigendian) as u64;
                let compressed_size =   _read_u32(&mut f, is_bigendian);
                let _decompressed_size =_read_u32(&mut f, is_bigendian); //Probably never going to use this
                let hash =              _read_u64(&mut f, is_bigendian);
                let _crc =              _read_u32(&mut f, is_bigendian); //should probably do a check on this but not critical
                let compressionmethod = _read_u16(&mut f, is_bigendian);
                let compression = if compressionmethod == 1 {version} else {0};

                //Destination information
                let dest_directory = hashmap.get(&hash);
                let dest_string;
                match dest_directory {
                    Some(d) => { dest_string = format(format_args!("{}",d)); },
                    None => {
                        println!("The file with hash {:016X} does not have a provided name and will be placed in the root directory.", hash);
                        dest_string = format(format_args!("/{}", hash));
                    }
                };
                let intermediate_path = match filetype {
                    ArchiveType::PTS => {"/pts"},
                    ArchiveType::BETA => {"/beta"},
                    ArchiveType::LIVE => {""}
                };
                let dest_directory = format!("{}{}{}", out_root_path, intermediate_path, dest_string);
                

                let entry = Job{
                    data_offset:        e_offset,
                    compressed_size,
                    compression,
                    asset_path_addr:    i,
                    destination:        PathBuf::from(&dest_directory),
                };

                outputs.push(entry);
            }
        }
    }
    return outputs
}

fn extract(files: &Vec<PathBuf>, job: Job) -> bool {
    create_dir_all(&job.destination.parent().unwrap()).unwrap();

    //Open archive
    let mut archive = File::open(&files[job.asset_path_addr]);
    let mut count = 0;
    while archive.is_err() {
        if count>10 {
            println!("Could not open archive.");
            return false
        }
        archive = File::open(&files[job.asset_path_addr]);
        count += 1;
    }
    let mut archive = archive.unwrap();
    archive.seek(SeekFrom::Start(job.data_offset)).unwrap();

    //Create and open destination file
    let mut dest = File::create(&job.destination);
    count = 0;
    while dest.is_err() {
        if count>10 {
            println!("Could not create destination file {}.", &job.destination.display());
            return false
        }
        dest = File::open(&files[job.asset_path_addr]);
        count += 1;
    }
    let mut dest = dest.unwrap();
    
    //Decompress or copy
    let bytesremaining: usize = usize::try_from(job.compressed_size).unwrap();
    match job.compression {
        0 => {
            let mut buf = vec![0; bytesremaining];
            archive.read_exact(&mut buf).unwrap();
            dest.write_all(&mut buf).unwrap();
        }
        5 => {
            let mut compressed = vec![0; bytesremaining];
            archive.read_exact(&mut compressed).unwrap();
            let mut out_buf: Vec<u8> = vec![0];
            let (_, rc) = decompress_slice(&mut out_buf, compressed.as_slice(), InflateConfig::default());
            match rc {
                ReturnCode::Ok => {},
                _ => {println!("Error: {:?}", rc);}
            }
            dest.write_all(&mut out_buf).unwrap();
        }
        6 => {
            let mut compressed = vec![0; bytesremaining];
            archive.read_exact(&mut compressed).unwrap();
            let mut decoder = zstd::stream::Decoder::new(compressed.as_slice()).unwrap();
            io::copy(&mut decoder, &mut dest).unwrap();
        }
        _ => {
            println!("Job Corrupted. Skipping.");
        }
    }

    //If no errors have stopped the job, it's done.
    return true
}

fn verifyheader(magic: u32, ver: &mut u32, end:u32) -> bool{
    match ver {
        5|6 => {
            if end == 0xFD23EC43 {
                if !(magic == 0x50594D) {
                    println!("Unexpected magic number, but endianness and compression version match. Ignoring.");
                }
            }
            else {
                println!("Endianness block may be corrupt, but the archive seems readable. Ignoring");
            }
            false
        },
        0x5000000|0x6000000 => {
            if end == 0xFD23EC43 {
                println!("Endianness block indicates big-endian encoding, but compression version is encoded in little-endian. Assuming little-endian.");
            }
            else {
                println!("Compression version is encoded in little-endian. Encoding for LE endianness block was previously unknown; this is not an error.");
                let bytes = end.to_le_bytes();
                println!("Endianness block (hex): {:02X?} {:02X?} {:02X?} {:02X?}", bytes[0], bytes[1], bytes[2], bytes[3]);
            }
            *ver = *ver >> 24;
            true
        },
        _   => {
            println!("Archive corrupt or unsupported compression version. Aborting");
            panic!();
        }

    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>> where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn _read_u16(filestream: &mut File, is_be: bool) -> u16 {
    let mut buf = [0;2];
    filestream.read_exact(&mut buf).expect("Error reading archive");
    if is_be {
        u16::from_be_bytes(buf)
    }
    else {
        u16::from_le_bytes(buf)
    }
}
fn _read_u32(filestream: &mut File, is_be: bool) -> u32 {
    let mut buf = [0;4];
    filestream.read_exact(&mut buf).expect("Error reading archive");
    if is_be {
        u32::from_be_bytes(buf)
    }
    else {
        u32::from_le_bytes(buf)
    }
}
fn _read_u64(filestream: &mut File, is_be: bool) -> u64 {
    let mut buf = [0;8];
    filestream.read_exact(&mut buf).expect("Error reading archive");
    if is_be {
        u64::from_be_bytes(buf)
    }
    else {
        u64::from_le_bytes(buf)
    }
}

pub trait Hasher {
    
}

fn hashlittle2 (str: Vec<u8>) -> u64 {
    let mut k = &str[..];

    let (mut a, mut b, mut c): (u32, u32, u32) = (0xDEADBEEF + k.len() as u32, 0xDEADBEEF + k.len() as u32, 0xDEADBEEF + k.len() as u32);

    while k.len() > 12 {
        a = a.wrapping_add( (k[00] as u32) + ((k[01] as u32)<<8) + ((k[02] as u32)<<16) + ((k[03] as u32)<<24) );
        b = b.wrapping_add( (k[04] as u32) + ((k[05] as u32)<<8) + ((k[06] as u32)<<16) + ((k[07] as u32)<<24) );
        c = c.wrapping_add( (k[08] as u32) + ((k[09] as u32)<<8) + ((k[10] as u32)<<16) + ((k[11] as u32)<<24) );

        a = a.wrapping_sub(c);
        a ^= c.rotate_left(4);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a);
        b ^= a.rotate_left(6);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b);
        c ^= b.rotate_left(8);
        b = b.wrapping_add(a);

        a = a.wrapping_sub(c);
        a ^= c.rotate_left(16);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a);
        b ^= a.rotate_left(19);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b);
        c ^= b.rotate_left(4);
        b = b.wrapping_add(a);

        k = &k[12..];
    }

    let d = k.len();
    if d >= 12 { c = c.wrapping_add((k[11] as u32)<<24); }
    if d >= 11 { c = c.wrapping_add((k[10] as u32)<<16); }
    if d >= 10 { c = c.wrapping_add((k[9] as u32)<<8);   }
    if d >= 9  { c = c.wrapping_add( k[8] as u32);       }
    if d >= 8  { b = b.wrapping_add((k[7] as u32)<<24);  }
    if d >= 7  { b = b.wrapping_add((k[6] as u32)<<16);  }
    if d >= 6  { b = b.wrapping_add((k[5] as u32)<<8);   }
    if d >= 5  { b = b.wrapping_add( k[4] as u32);       }
    if d >= 4  { a = a.wrapping_add((k[3] as u32)<<24);  }
    if d >= 3  { a = a.wrapping_add((k[2] as u32)<<16);  }
    if d >= 2  { a = a.wrapping_add((k[1] as u32)<<8);   }
    if d >= 1  { a = a.wrapping_add( k[0] as u32);       }
    if d == 0  { return ((c as u64) << 32) + b as u64;   }

    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(24));
    return ((b as u64) << 32) + c as u64;
}