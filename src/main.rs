/**
 * 微信3.7.0.30版本修改工具
 * 
 * 版权所有 (C) 2025
 * 核心实现版权所有来自于 https://github.com/ChisatoNishikigi73 
 * 由 https://github.com/sj817 代为开源
 */

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_QUERY_INFORMATION};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use std::env;

/// 将版本号字符串转换为字节数组
/// 
/// # 参数
/// 
/// * `version` - 版本号字符串，格式如 "3.7.0.30"
/// 
/// # 返回值
/// 
/// 返回转换后的字节数组，用于写入内存
fn convert_version(version: &str) -> Vec<u8> {
    // 第一步：版本号转十六进制字符串
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 4 {
        eprintln!("版本号格式错误，应为 x.x.x.x");
        return vec![18, 5, 0, 100]; // 默认返回 [18, 5, 0, 100]
    }
    
    let mut hex_string = String::from("6");
    for (i, part) in parts.iter().enumerate() {
        if let Ok(num) = part.parse::<u32>() {
            let part_hex = if i == 0 {
                format!("{:x}", num) // 首位只用1位十六进制
            } else {
                format!("{:02x}", num) // 其他位用2位十六进制，不足补0
            };
            hex_string.push_str(&part_hex);
        } else {
            eprintln!("版本号部分 '{}' 不是有效数字", part);
            return vec![18, 5, 0, 100]; // 默认返回值
        }
    }
    
    // 第二步：十六进制字符串转字节数组
    let mut bytes = Vec::new();
    for i in (0..hex_string.len()).step_by(2) {
        if i + 2 <= hex_string.len() {
            if let Ok(byte) = u8::from_str_radix(&hex_string[i..i+2], 16) {
                bytes.push(byte);
            }
        } else if i + 1 <= hex_string.len() {
            if let Ok(byte) = u8::from_str_radix(&hex_string[i..i+1], 16) {
                bytes.push(byte);
            }
        }
    }
    
    // 第三步：反转字节顺序（变为little-endian）
    bytes.reverse();
    
    bytes
}

/// 查找进程ID
fn find_process_id(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32 { dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32, ..Default::default() };
        let mut found = None;
        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let exe = String::from_utf8_lossy(&entry.szExeFile);
                if exe.to_lowercase().contains(&process_name.to_lowercase()) {
                    found = Some(entry.th32ProcessID);
                    break;
                }
                if !Process32Next(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        found
    }
}

/// 查找模块基址
fn find_module_base(pid: u32, module_name: &str) -> Option<usize> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid).ok()?;
        let mut entry = MODULEENTRY32 { dwSize: std::mem::size_of::<MODULEENTRY32>() as u32, ..Default::default() };
        let mut found = None;
        if Module32First(snapshot, &mut entry).is_ok() {
            loop {
                let modname = String::from_utf8_lossy(&entry.szModule);
                if modname.to_lowercase().contains(&module_name.to_lowercase()) {
                    found = Some(entry.modBaseAddr as usize);
                    break;
                }
                if !Module32Next(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        found
    }
}

fn main() {
    // 获取命令行参数，第一个参数为版本号
    let args: Vec<String> = env::args().collect();
    let version = if args.len() > 1 {
        &args[1]
    } else {
        "4.0.5.18" // 默认版本号
    };
    
    println!("使用版本号: {}", version);
    
    // 转换版本号为字节数组
    let new_ver = convert_version(version);
    println!("转换结果: {:?}", new_ver);
    
    let process_name = "wechat.exe";
    let module_name = "WeChatWin.dll";
    let read_size = 16usize;

    // 等待直到找到进程
    let pid = loop {
        match find_process_id(process_name) {
            Some(pid) => break pid,
            None => {
                eprintln!("无法找到进程，等待中...");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    };
    println!("[{}] 进程ID: {}", process_name, pid);

    let base = match find_module_base(pid, module_name) {
        Some(addr) => addr,
        None => {
            eprintln!("无法找到模块");
            return;
        }
    };
    println!("[{}] 基址: 0x{:X}", module_name, base);

    let offsets = [
        0x2367624,
        0x2385AF0,
        0x2385C44,
        0x239C98C,
        0x239EAFC,
        0x23A1604,
        // 所有可能的指针偏移
    ];

    unsafe {
        let handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            false,
            pid
        ).ok();
        let handle = match handle {
            Some(h) => h,
            None => {
                eprintln!("[{}] 无法打开进程", process_name);
                return;
            }
        };
        for &offset in &offsets {
            let target_addr = base + offset;
            print!("[{}] 目标地址: [0x{:X}]", module_name, target_addr);
            let mut buffer = vec![0u8; read_size];
            let mut read = 0usize;
            let ok = ReadProcessMemory(
                handle,
                target_addr as _,
                buffer.as_mut_ptr() as _,
                read_size,
                Some(&mut read)
            ).is_ok();
            if ok {
                if read >= 4 {
                    // 使用命令行参数转换得到的版本号
                    let write_ok = WriteProcessMemory(
                        handle,
                        target_addr as _,
                        new_ver.as_ptr() as _,
                        new_ver.len(),
                        None
                    ).is_ok();
                    if write_ok {
                        println!(" 成功");
                    } else {
                        eprintln!(" 写入失败");
                    }
                }
            } else {
                eprintln!("[{}] 读取失败", module_name);
            }
        }
        println!("完成！");
        println!("5秒后关闭...");
        std::thread::sleep(std::time::Duration::from_secs(5));
        let _ = CloseHandle(handle);
    }
}
