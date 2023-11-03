use windows::Win32::System::ClrHosting::CLRCreateInstance;
use windows::Win32::System::ClrHosting::CLSID_CLRMetaHost;
use windows::Win32::System::ClrHosting::CLRRuntimeHost;
use windows::Win32::System::ClrHosting::ICLRMetaHost;
use windows::Win32::System::ClrHosting::ICLRRuntimeHost;
use windows::Win32::System::ClrHosting::ICLRRuntimeInfo;

use windows::core::ComInterface;
use windows::core::GUID;
use windows::core::HSTRING;
use windows::core::IUnknown;
use windows::core::PCWSTR;
use windows::core::PWSTR;
use windows::core::w;

//function called should have following signature : static int MethodName(String args)

fn main() {
    let mut framework_version : Option<String> = None;
    let host: ICLRRuntimeHost;

	println!("CLR via native code");

    unsafe {
        let meta_host = CLRCreateInstance::<ICLRMetaHost>(&CLSID_CLRMetaHost as *const GUID).unwrap();
      
        
        let runtimes = meta_host.EnumerateInstalledRuntimes().unwrap();
        loop {
            let mut unk = [Option::<IUnknown>::None;1];
            runtimes.Next(&mut unk, None).unwrap();

            match &unk[0] {
                Some(runtime) => {
                    let info: ICLRRuntimeInfo = runtime.cast::<ICLRRuntimeInfo>().unwrap();
                    let mut buffer = vec![0u16; 2048];
                    let framework_name= PWSTR::from_raw(buffer.as_mut_ptr());
                    let mut framework_name_len: u32 = buffer.len() as u32;
                    //let raw_mut = &mut framework_name_len as *mut u32;
                    let _ = info.GetVersionString(framework_name, &mut framework_name_len as *mut u32);
                    println!("[*] Supported Framework: {}", framework_name.to_string().unwrap());
                    framework_version = Some(framework_name.to_string().unwrap());
                },
                None => break
            }
        }

        if framework_version.is_none() {
            println!("No runtime found!");
                return;
        }

        let fmk = framework_version.unwrap();
        println!("[*] loading runtime: {:?}", fmk.to_string());

        let ver_hstring = HSTRING::from(fmk);
        let ver_pcwstr = PCWSTR::from_raw(ver_hstring.as_ptr());
        let runtime: ICLRRuntimeInfo = meta_host.GetRuntime(ver_pcwstr).unwrap();

        match runtime.GetInterface::<ICLRRuntimeHost >(&CLRRuntimeHost as *const GUID) {
            Err(_) => {
                println!("No host found!");
                return;
            },
            Ok(h) => host = h,
        }

        match host.Start() {
            Err(_) =>  {
                println!("host start failed!");
                return;
            },
            Ok(_) => {},
        }

        match host.ExecuteInDefaultAppDomain(w!("E:\\Share\\Projects\\Rust\\Offensive-rust\\clr-from-file\\.net\\Test\\bin\\Debug\\Test.exe"),
                w!("Test.Program"),
                w!("HostingMain"), 
                w!("Test")) {
            Err(e) =>  {
                println!("execution of the assembly failed {}", e);
                return;
            },
            Ok(return_value) => {
                match return_value {
                    0 => {
                        println!("execution complete!");
                    },
                    val => {
                        println!("execution of the assembly return {}", val);
                        return;
                    }
                }
            }
        }
        
    }
	

}
