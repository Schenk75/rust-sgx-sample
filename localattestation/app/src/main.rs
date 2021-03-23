extern crate sgx_types;
extern crate sgx_urts;

use std::{collections::HashMap, sync::Mutex};

use sgx_types::*;
use sgx_urts::SgxEnclave;

static ENCLAVE_FILE_1: &'static str = "enclave1.signed.so";
static ENCLAVE_FILE_2: &'static str = "enclave2.signed.so";
static ENCLAVE_FILE_3: &'static str = "enclave3.signed.so";

#[macro_use]
extern crate lazy_static;

lazy_static!{
    static ref ENCLAVE_ID_MAP: Mutex<HashMap<sgx_enclave_id_t, u32>> = Mutex::new(HashMap::new());
    static ref SESSION_PTR_MAP: Mutex<HashMap<sgx_enclave_id_t, HashMap<sgx_enclave_id_t, usize>>> = Mutex::new(HashMap::new());
}
    
// type ATTESTATION_STATUS = u32;
// const SUCCESS: u32 = 0x00;
// const INVALID_PARAMETER: u32 = 0xe1;
// const VALID_SESSION: u32 = 0xe2;
// const INVALID_SESSION: u32 = 0xe3;
// const ATTESTATION_ERROR: u32 = 0xe4;
// const ATTESTATION_SE_ERROR: u32 = 0xe5;
// const IPP_ERROR: u32 = 0xe6;
// const NO_AVAILABLE_SESSION_ERROR: u32 = 0xe7;
// const MALLOC_ERROR: u32 = 0xe8;
// const ERROR_TAG_MISMATCH: u32 = 0xe9;
// const OUT_BUFFER_LENGTH_ERROR: u32 = 0xea;
// const INVALID_REQUEST_TYPE_ERROR: u32 = 0xeb;
// const INVALID_PARAMETER_ERROR: u32 = 0xec;
// const ENCLAVE_TRUST_ERROR: u32 = 0xed;
// const ENCRYPT_DECRYPT_ERROR: u32 = 0xee;
// const DUPLICATE_SESSION: u32 = 0xef;

extern {
    fn Enclave1_test_enclave_init(eid: sgx_enclave_id_t);
    fn Enclave1_session_request(dest_enclave_id: sgx_enclave_id_t, 
                                retval: *mut sgx_status_t,
                                src_enclave_id: sgx_enclave_id_t,
                                dh_msg1: *mut sgx_dh_msg1_t,
                                session_ptr: *mut usize) -> sgx_status_t;
    fn Enclave1_test_create_session(eid: sgx_enclave_id_t, 
                                    retval: *mut sgx_status_t,
                                    src_enclave_id: sgx_enclave_id_t, 
                                    dest_enclave_id: sgx_enclave_id_t) -> sgx_status_t;
    fn Enclave1_test_close_session(eid: sgx_enclave_id_t, 
                                    retval: *mut sgx_status_t,
                                    src_enclave_id: sgx_enclave_id_t, 
                                    dest_enclave_id: sgx_enclave_id_t) -> sgx_status_t;
    fn Enclave2_test_enclave_init(eid: sgx_enclave_id_t);
    fn Enclave2_session_request(dest_enclave_id: sgx_enclave_id_t, 
                                retval: *mut sgx_status_t,
                                src_enclave_id: sgx_enclave_id_t,
                                dh_msg1: *mut sgx_dh_msg1_t,
                                session_ptr: *mut usize) -> sgx_status_t;
    fn Enclave2_test_create_session(eid: sgx_enclave_id_t, 
                                    retval: *mut sgx_status_t,
                                    src_enclave_id: sgx_enclave_id_t, 
                                    dest_enclave_id: sgx_enclave_id_t) -> sgx_status_t;
    fn Enclave2_test_close_session(eid: sgx_enclave_id_t, 
                                    retval: *mut sgx_status_t,
                                    src_enclave_id: sgx_enclave_id_t, 
                                    dest_enclave_id: sgx_enclave_id_t) -> sgx_status_t;
    fn Enclave3_test_enclave_init(eid: sgx_enclave_id_t);
    fn Enclave3_session_request(dest_enclave_id: sgx_enclave_id_t, 
                                retval: *mut sgx_status_t,
                                src_enclave_id: sgx_enclave_id_t,
                                dh_msg1: *mut sgx_dh_msg1_t,
                                session_ptr: *mut usize) -> sgx_status_t;
    fn Enclave3_test_create_session(eid: sgx_enclave_id_t, 
                                    retval: *mut sgx_status_t,
                                    src_enclave_id: sgx_enclave_id_t, 
                                    dest_enclave_id: sgx_enclave_id_t) -> sgx_status_t;
    fn Enclave3_test_close_session(eid: sgx_enclave_id_t, 
                                    retval: *mut sgx_status_t,
                                    src_enclave_id: sgx_enclave_id_t, 
                                    dest_enclave_id: sgx_enclave_id_t) -> sgx_status_t;
}

fn init_enclave(file_name: &'static str) -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(file_name,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

fn main() {
    let enclave1 = match init_enclave(ENCLAVE_FILE_1) {
        Ok(r) => {
            println!("[+] Init Enclave1 Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave1 Failed {}!", x.as_str());
            return;
        },
    };
    let enclave2 = match init_enclave(ENCLAVE_FILE_2) {
        Ok(r) => {
            println!("[+] Init Enclave2 Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave2 Failed {}!", x.as_str());
            return;
        },
    };
    let enclave3 = match init_enclave(ENCLAVE_FILE_3) {
        Ok(r) => {
            println!("[+] Init Enclave3 Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave3 Failed {}!", x.as_str());
            return;
        },
    };

    let eid1 = enclave1.geteid();
    let eid2 = enclave2.geteid();
    let eid3 = enclave3.geteid();

    ENCLAVE_ID_MAP.lock().unwrap().insert(eid1, 1);
    ENCLAVE_ID_MAP.lock().unwrap().insert(eid2, 2);
    ENCLAVE_ID_MAP.lock().unwrap().insert(eid3, 3);
    // println!("{:?}", ENCLAVE_ID_MAP.lock().unwrap());
    
    let mut retval = sgx_status_t::SGX_SUCCESS;

    unsafe {
        Enclave1_test_enclave_init(eid1);
        Enclave2_test_enclave_init(eid2);
        Enclave3_test_enclave_init(eid3);
    };
    
    // Test Create session between Enclave1(Source) and Enclave2(Destination)
    let result = unsafe {
        Enclave1_test_create_session(eid1, &mut retval, eid1, eid2)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            if retval == sgx_status_t::SGX_SUCCESS {
                println!("Secure Channel Establishment between Source (E1) and Destination (E2) Enclaves successful !!!");
            } else {
                println!("Session establishment and key exchange failure between Source (E1) and Destination (E2): {}", retval.as_str());
                return;
            }
        },
        _ => {
            println!("[-] Enclave1_test_create_session Ecall failed: {}!", result.as_str());
            return;
        }
    }

    //Test Create session between Enclave1(Source) and Enclave3(Destination)
    let result = unsafe {
        Enclave1_test_create_session(eid1, &mut retval, eid1, eid3)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            if retval == sgx_status_t::SGX_SUCCESS {
                println!("Secure Channel Establishment between Source (E1) and Destination (E3) Enclaves successful !!!");
            } else {
                println!("Session establishment and key exchange failure between Source (E1) and Destination (E3): {}", retval.as_str());
                return;
            }
        },
        _ => {
            println!("[-] Enclave1_test_create_session Ecall failed: {}!", result.as_str());
            return;
        }
    }

    //Test Create session between Enclave2(Source) and Enclave3(Destination)
    let result = unsafe {
        Enclave2_test_create_session(eid2, &mut retval, eid2, eid3)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            if retval == sgx_status_t::SGX_SUCCESS {
                println!("Secure Channel Establishment between Source (E2) and Destination (E3) Enclaves successful !!!");
            } else {
                println!("Session establishment and key exchange failure between Source (E2) and Destination (E3): {}", retval.as_str());
                return;
            }
        },
        _ => {
            println!("[-] Enclave2_test_create_session Ecall failed: {}!", result.as_str());
            return;
        }
    }

    //Test Create session between Enclave3(Source) and Enclave1(Destination)
    let result = unsafe {
        Enclave3_test_create_session(eid3, &mut retval, eid3, eid1)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            if retval == sgx_status_t::SGX_SUCCESS {
                println!("Secure Channel Establishment between Source (E3) and Destination (E1) Enclaves successful !!!");
            } else {
                println!("Session establishment and key exchange failure between Source (E3) and Destination (E1): {}", retval.as_str());
                return;
            }
        },
        _ => {
            println!("[-] Enclave3_test_create_session Ecall failed: {}!", result.as_str());
            return;
        }
    }

    //Test Closing Session between Enclave1(Source) and Enclave2(Destination)
    let result = unsafe {
        Enclave1_test_close_session(eid1, &mut retval, eid1, eid2)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            if retval == sgx_status_t::SGX_SUCCESS {
                println!("Close Session between Source (E1) and Destination (E2) Enclaves successful !!!");
            } else {
                println!("Close session failure between Source (E1) and Destination (E2): {}", retval.as_str());
                return;
            }
        },
        _ => {
            println!("[-] Enclave1_test_close_session Ecall failed: {}!", result.as_str());
            return;
        }
    }

    //Test Closing Session between Enclave1(Source) and Enclave3(Destination)
    let result = unsafe {
        Enclave1_test_close_session(eid1, &mut retval, eid1, eid3)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            if retval == sgx_status_t::SGX_SUCCESS {
                println!("Close Session between Source (E1) and Destination (E3) Enclaves successful !!!");
            } else {
                println!("Close session failure between Source (E1) and Destination (E3): {}", retval.as_str());
                return;
            }
        },
        _ => {
            println!("[-] Enclave1_test_close_session Ecall failed: {}!", result.as_str());
            return;
        }
    }

    //Test Closing Session between Enclave2(Source) and Enclave3(Destination)
    let result = unsafe {
        Enclave2_test_close_session(eid2, &mut retval, eid2, eid3)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            if retval == sgx_status_t::SGX_SUCCESS {
                println!("Close Session between Source (E2) and Destination (E3) Enclaves successful !!!");
            } else {
                println!("Close session failure between Source (E2) and Destination (E3): {}", retval.as_str());
                return;
            }
        },
        _ => {
            println!("[-] Enclave2_test_close_session Ecall failed: {}!", result.as_str());
            return;
        }
    }

    //Test Closing Session between Enclave3(Source) and Enclave1(Destination)
    let result = unsafe {
        Enclave3_test_close_session(eid3, &mut retval, eid3, eid1)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            if retval == sgx_status_t::SGX_SUCCESS {
                println!("Close Session between Source (E3) and Destination (E1) Enclaves successful !!!");
            } else {
                println!("Close session failure between Source (E3) and Destination (E1): {}", retval.as_str());
                return;
            }
        },
        _ => {
            println!("[-] Enclave3_test_close_session Ecall failed: {}!", result.as_str());
            return;
        }
    }
    
    enclave1.destroy();
    enclave2.destroy();
    enclave3.destroy();  
}


// OCALLs
//Makes an sgx_ecall to the destination enclave to get session id and message1
#[no_mangle]
pub extern "C" fn session_request_ocall(src_enclave_id: sgx_enclave_id_t, 
                                        dest_enclave_id: sgx_enclave_id_t,

                                        dh_msg1: *mut sgx_dh_msg1_t) -> sgx_status_t {
    let mut status = sgx_status_t::SGX_SUCCESS;
    let mut ret = sgx_status_t::SGX_SUCCESS;
    let mut session_ptr: usize = 0;   

    match ENCLAVE_ID_MAP.lock().unwrap().get(&dest_enclave_id) {
        Some(a) => {
            match a {
                &1 => {
                    unsafe {
                        ret = Enclave1_session_request(dest_enclave_id, &mut status, src_enclave_id, dh_msg1, &mut session_ptr);
                    }
                }
                &2 => {
                    unsafe {
                        ret = Enclave2_session_request(dest_enclave_id, &mut status, src_enclave_id, dh_msg1, &mut session_ptr);
                    }
                }
                &3 => {
                    unsafe {
                        ret = Enclave3_session_request(dest_enclave_id, &mut status, src_enclave_id, dh_msg1, &mut session_ptr);
                    }
                }
                _ => {}
            }
        }
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_ENCLAVE;
        }
    };

    if ret == sgx_status_t::SGX_SUCCESS {
        // std::map<sgx_enclave_id_t, std::map<sgx_enclave_id_t, size_t> >::iterator it_ptr = g_session_ptr_map.find(dest_enclave_id);
		// if(it_ptr != g_session_ptr_map.end())
		// {
		// 	it_ptr->second.insert(std::pair<sgx_enclave_id_t, size_t>(src_enclave_id, session_ptr));
		// }
		// else
		// {
		// 	std::map<sgx_enclave_id_t, size_t> sub_map;
		// 	sub_map.insert(std::pair<sgx_enclave_id_t, size_t>(src_enclave_id, session_ptr));
		// 	g_session_ptr_map.insert(std::pair<sgx_enclave_id_t, std::map<sgx_enclave_id_t, size_t> >(dest_enclave_id, sub_map));
		// }
        
        sgx_status_t::SGX_SUCCESS
    } else {
        sgx_status_t::SGX_ERROR_INVALID_ENCLAVE
    }
}

//Makes an sgx_ecall to the destination enclave sends message2 from the source enclave and gets message 3 from the destination enclave
#[no_mangle]
pub extern "C" fn exchange_report_ocall(src_enclave_id: sgx_enclave_id_t,
                                        dest_enclave_id: sgx_enclave_id_t,
                                        dh_msg2: *mut sgx_dh_msg2_t,
                                        dh_msg3: *mut sgx_dh_msg3_t) -> sgx_status_t {

    sgx_status_t::SGX_SUCCESS                                        
}

//Make an sgx_ecall to the destination enclave to close the session
#[no_mangle]
pub extern "C" fn end_session_ocall(src_enclave_id:sgx_enclave_id_t,
                                    dest_enclave_id:sgx_enclave_id_t) -> sgx_status_t {
    
    sgx_status_t::SGX_SUCCESS
}