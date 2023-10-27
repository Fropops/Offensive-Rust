#[macro_export]
macro_rules! print_debug {
    ($($arg:tt)*) => (if ::std::cfg!(debug_assertions) { ::std::println!($($arg)*); })
}

#[macro_export]
macro_rules! dbg {
    () => {
        eprintln!("{}", format!("[{}:{}]", file!(), line!()));
    };
    ($val:expr $(,)?) => {
        match $val {
            tmp => {
                eprintln!("{} {} = {}",
                    format!("[{}:{}]", file!(), line!()),
                    stringify!($val),
                    format!("{:#?}", &tmp),
                );
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($(dbg!($val)),+,)
    };
}

#[macro_export]
macro_rules! debug_base {
    //1 parameter
    ($char:expr, $val:expr $(,)?) => {
                match $val {
                    tmp => {
                        if ::std::cfg!(debug_assertions) {
                            eprintln!("[{}] {} : {}",
                                $char,
                                stringify!($val),
                                format!("{:#?}", &tmp),
                            );
                        }
                        tmp
                    }
                }
            };
    //2 parameters
    ($char:expr, $msg:expr, $val:expr $(,)?) => {
        match $val {
            tmp => {
                if ::std::cfg!(debug_assertions) {
                    eprintln!("[{}] {} : {}",
                        $char,
                        $msg,
                        format!("{:#?}", $val),
                    );
                }
                tmp
            }
        }
    };
}

#[macro_export]
macro_rules! debug_base_hex {
    //1 parameter
    ($char:expr, $val:expr $(,)?) => {
                match $val {
                    tmp => {
                        if ::std::cfg!(debug_assertions) {
                            eprintln!("[{}] {} : {}",
                                $char,
                                stringify!($val),
                                format!("{:#x}", &tmp),
                            );
                        }
                        tmp
                    }
                }
            };
    //2 parameters
    ($char:expr, $msg:expr, $val:expr $(,)?) => {
        match $val {
            tmp => {
                if ::std::cfg!(debug_assertions) {
                    eprintln!("[{}] {} : {}",
                        $char,
                        $msg,
                        format!("{:#x}", $val),
                    );
                }
                tmp
            }
        }
    };
}

#[macro_export]
macro_rules! debug_base_msg {
    ($char:expr, $val:expr $(,)?) => {
            if ::std::cfg!(debug_assertions) {
                eprintln!("[{}] {}",
                    $char,
                    $val,
                );
            }
        };
}

#[macro_export]
macro_rules! debug_success {
    ($val:expr $(,)?) => { debug_base!("*", $val) };
    ($msg:expr, $val:expr $(,)?) => { debug_base!("*", $msg, $val); };
}
#[macro_export]
macro_rules! debug_success_msg {
    ($val:expr $(,)?) => { debug_base_msg!("*", $val); };
}

#[macro_export]
macro_rules! debug_ok {
    ($val:expr $(,)?) => { debug_base!("+", $val) };
    ($msg:expr, $val:expr $(,)?) => { debug_base!("+", $msg, $val); };
}
#[macro_export]
macro_rules! debug_ok_msg {
    ($val:expr $(,)?) => { debug_base_msg!("+", $val); };
}

#[macro_export]
macro_rules! debug_error {
    ($val:expr $(,)?) => { debug_base!("X", $val) };
    ($msg:expr, $val:expr $(,)?) => { debug_base!("X", $msg, $val); };
}
#[macro_export]
macro_rules! debug_error_msg {
    ($val:expr $(,)?) => { debug_base_msg!("X", $val) };
}

#[macro_export]
macro_rules! debug_info {
    ($val:expr $(,)?) => { debug_base!("?", $val) };
    ($msg:expr, $val:expr $(,)?) => { debug_base!("?", $msg, $val); };
}
#[macro_export]
macro_rules! debug_info_msg {
    ($val:expr $(,)?) => { debug_base_msg!("?", $val) };
}
#[macro_export]
macro_rules! debug_info_hex {
    ($val:expr $(,)?) => { debug_base_hex!("?", $val) };
}

#[macro_export]
macro_rules! debug_warning {
    ($val:expr $(,)?) => { debug_base!("!", $val) };
    ($msg:expr, $val:expr $(,)?) => { debug_base!("!", $msg, $val); };
}
#[macro_export]
macro_rules! debug_warning_msg {
    ($val:expr $(,)?) => { debug_base_msg!("!", $val) };
}

#[macro_export]
macro_rules! debug_ko {
    ($val:expr $(,)?) => { debug_base!("-", $val) };
    ($msg:expr, $val:expr $(,)?) => { debug_base!("-", $msg, $val); };
}
#[macro_export]
macro_rules! debug_ko_msg {
    ($val:expr $(,)?) => { debug_base_msg!("-", $val) };
}
// macro_rules! debug_base {
//     //1 parameter
//     ($val:expr $(,)?) => {
//                 match $val {
//                     tmp => {
//                         if ::std::cfg!(debug_assertions) {
//                             eprintln!("[*] {} : {}",
//                                 stringify!($val),
//                                 format!("{:#?}", &tmp),
//                             );
//                         }
//                         tmp
//                     }
//                 }
//             };
//     //2 parameters
//     ($msg:expr, $val:expr $(,)?) => {
//         match $val {
//             tmp => {
//                 if ::std::cfg!(debug_assertions) {
//                     eprintln!("[*] {} : {}",
//                         $msg,
//                         format!("{:#?}", $val),
//                     );
//                 }
//                 tmp
//             }
//         }
//     };
// }