use std::fmt::format;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, create_dir_all};
use std::cmp::min;
use zlib_rs::{InflateConfig, ReturnCode, decompress_slice};

const BUF_SIZE: usize = 81920;

fn main() {
    let mut map = HashMap::new();
    
    if let Ok(lines) = read_lines("D:/projects/rs/slicing/asd.csv") {
        // Consumes the iterator, returns an (Optional) String
        for line in lines.map_while(Result::ok) {
            let hash = format(format_args!("{}{}", &line[0..8], &line[9..17]));
            let hash = u64::from_str_radix(&hash, 16).expect("hash is not base 16");
            let path = format(format_args!("{}", &line[18..line.len()-9]));
            map.insert(hash, path);
        }
    }
    extractfiles(String::from("D:/projects/rs/slicing_testing"), String::from("D:/projects/rs/slicing_testing/out"), ArchiveType::PTS, map);
}
#[derive(Clone)]
enum ArchiveType {
    LIVE,
    PTS,
    BETA,
}

struct Job {
    data_offset:        u64,
    hash:               u64,
    compressed_size:    u32,
    compression:        u32,
    asset_path_addr:    usize,
    game_version:       ArchiveType,
}

fn extractfiles(assetspath: String, outpath: String, filetype: ArchiveType, hashmap: HashMap<u64, String>) -> bool{
    let file_list = get_files(assetspath);

    let mut jobs: Vec<Job> = vec![];
    let mut files: Vec<PathBuf> = vec![];

    for (i, file) in file_list.iter().enumerate() {
        files.push(file.clone());
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
            println!("table offset: {}", tableoffset);
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
                println!("entry offset: {}", e_offset);

                e_offset +=                  _read_u32(&mut f, is_bigendian) as u64;
                let compressed_size =   _read_u32(&mut f, is_bigendian);
                let _decompressed_size =_read_u32(&mut f, is_bigendian); //Probably never going to use this
                let hash =              _read_u64(&mut f, is_bigendian);
                let _crc =              _read_u32(&mut f, is_bigendian); //should probably do a check on this but not critical
                let compressionmethod = _read_u16(&mut f, is_bigendian);
                let compression = if compressionmethod == 1 {version} else {0};

                jobs.push(Job { data_offset: e_offset, hash, compressed_size, compression, asset_path_addr: i, game_version: filetype.clone() });
            }
        }

    }

    //distribute jobs
    let mut completed = 0;
    let mut failed = 0;
    for job in jobs {
        match fun_name(&outpath, &hashmap, &files, job) {
            true =>     { completed += 1; }
            false =>    { failed += 1; }
        }
    }
    println!("Extracted {} files ({} failed extractions).", completed, failed);
    true
}

fn fun_name(outpath: &String, hashmap: &HashMap<u64, String>, files: &Vec<PathBuf>, job: Job) -> bool {
    let dest_directory = hashmap.get(&job.hash);
    let dest_string;
    match dest_directory {
        Some(d) => { dest_string = format(format_args!("{}",d)); },
        None => {
            println!("The file with hash {:016X} does not have a provided name and will be placed in the root directory.", job.hash);
            dest_string = format(format_args!("{}",job.hash));
        }
    };
    let intermediate_path = match job.game_version {
        ArchiveType::PTS => {"/pts"},
        ArchiveType::BETA => {"/beta"},
        ArchiveType::LIVE => {""}
    };
    let dest_directory = format!("{}{}{}", *outpath, intermediate_path, dest_string);
    println!("Destination Directory: {}",dest_directory);
    let dest_directory = Path::new(&dest_directory);
    create_dir_all(dest_directory.parent().unwrap()).unwrap();
    let mut archive = File::open(&files[job.asset_path_addr]);
    let mut count = 0;
    while archive.is_err() {
        if count>10 {
            println!("Could not open source file. ");
            return false
        }
        archive = File::open(&files[job.asset_path_addr]);
        count += 1;
    }
    let mut archive = archive.unwrap();
    let mut dest = File::create(dest_directory);
    count = 0;
    while dest.is_err() {
        if count>10 {
            println!("Could not create destination file {}.", dest_directory.display());
            return false
        }
        dest = File::open(&files[job.asset_path_addr]);
        count += 1;
    }
    let mut dest = dest.unwrap();
    archive.seek(SeekFrom::Start(job.data_offset)).unwrap();
    let mut bytesremaining: usize = usize::try_from(job.compressed_size).unwrap();

    //Open Archive
        
    //Create Destination

    match job.compression {
        0 => {
            while bytesremaining > 0 {
                let mut buf = vec![0; min(BUF_SIZE,bytesremaining)];
                archive.read_exact(&mut buf).unwrap();
                dest.write_all(&mut buf).unwrap();
                bytesremaining = bytesremaining.saturating_sub(BUF_SIZE);
            }
        }
        5 => {
            while bytesremaining > 0 {
                let mut compressed = vec![0; bytesremaining];
                archive.read_exact(&mut compressed).unwrap();
                let mut out_buf = vec![0; bytesremaining];
                let (_, rc) = decompress_slice(&mut out_buf, compressed.as_slice(), InflateConfig::default());
                match rc {
                    ReturnCode::Ok => {},
                    _ => {println!("Error: {:?}", rc);}
                }
                dest.write_all(&mut out_buf).unwrap();
                bytesremaining = bytesremaining.saturating_sub(BUF_SIZE);
            }
        }
        6 => {
            let mut compressed = vec![0; bytesremaining];
            archive.read_exact(&mut compressed).unwrap();
            let mut decoder = zstd::stream::Decoder::new(compressed.as_slice()).unwrap();
            io::copy(&mut decoder, &mut dest).unwrap();
            println!("DECOMPRESSING: {}", dest_string);
        }
        _ => {
            println!("Job Corrupted. Skipping.");
        }
    }
    return true
}

fn get_files(assetspath: String) -> Vec<PathBuf> {
    let archivepaths = fs::read_dir(assetspath).expect("Failed to get files in the selected directory. Does this directory exist?");
    
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