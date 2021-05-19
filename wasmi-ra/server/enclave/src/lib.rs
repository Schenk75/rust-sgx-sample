// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "wasmienclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tcrypto;
extern crate sgx_tseal;
extern crate sgx_tse;
extern crate sgx_rand;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

#[macro_use]
extern crate lazy_static;

extern crate serde;
extern crate serde_json;
extern crate rustls;
extern crate webpki;
extern crate webpki_roots;
extern crate itertools;
extern crate base64;
extern crate httparse;
extern crate yasna;
extern crate bit_vec;
extern crate num_bigint;
extern crate chrono;

use sgx_types::*;
use sgx_tse::*;
use sgx_rand::*;
use sgx_tcrypto::*;

use std::prelude::v1::*;
use std::slice;
use std::sync::{SgxMutex, Arc};
use std::ptr;
use std::net::TcpStream;
use std::string::String;
use std::str;
use std::io::{Write, Read, BufReader};
use std::untrusted::fs;
use std::vec::Vec;
use itertools::Itertools;
use std::sgxfs::SgxFile;
use sgx_tseal::{SgxSealedData};

extern crate wasmi;
extern crate sgxwasm;

use sgxwasm::{SpecDriver, boundary_value_to_runtime_value, result_covert};
use wasmi::{ModuleInstance, ImportsBuilder, RuntimeValue, Error as InterpreterError, Module};

mod cert;
mod hex;

pub const DEV_HOSTNAME:&'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX:&'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX:&'static str = "/sgx/dev/attestation/v3/report";
pub const CERTEXPIRYDAYS: i64 = 90i64;

extern "C" {
    pub fn ocall_sgx_init_quote ( ret_val : *mut sgx_status_t,
                  ret_ti  : *mut sgx_target_info_t,
                  ret_gid : *mut sgx_epid_group_id_t,
                  print_log: u8) -> sgx_status_t;
    pub fn ocall_get_ias_socket ( ret_val : *mut sgx_status_t,
                  ret_fd  : *mut i32) -> sgx_status_t;
    pub fn ocall_get_quote (ret_val            : *mut sgx_status_t,
                p_sigrl            : *const u8,
                sigrl_len          : u32,
                p_report           : *const sgx_report_t,
                quote_type         : sgx_quote_sign_type_t,
                p_spid             : *const sgx_spid_t,
                p_nonce            : *const sgx_quote_nonce_t,
                p_qe_report        : *mut sgx_report_t,
                p_quote            : *mut u8,
                maxlen             : u32,
                p_quote_len        : *mut u32,
                print_log          : u8) -> sgx_status_t;
    pub fn ocall_load_wasm (ret_val: *mut sgx_status_t, sealed_log: &mut [u8; 4096],
                            file_name: *const u8, name_len: usize) -> sgx_status_t;
    pub fn ocall_store_wasm (ret_val: *mut sgx_status_t, sealed_log: &[u8; 4096],
                            file_name: *const u8, name_len: usize) -> sgx_status_t;
}

lazy_static!{
    static ref SPECDRIVER: SgxMutex<SpecDriver> = SgxMutex::new(SpecDriver::new());
    // store owner's key pair
    static ref PRIVATE_KEY: SgxMutex<sgx_rsa3072_key_t> = SgxMutex::new(sgx_rsa3072_key_t::default());
    static ref PUBLIC_KEY: SgxMutex<sgx_rsa3072_public_key_t> = SgxMutex::new(sgx_rsa3072_public_key_t::default());
}

#[no_mangle]
pub extern "C"
fn sgxwasm_init() -> sgx_status_t {
    let mut sd = SPECDRIVER.lock().unwrap();
    *sd = SpecDriver::new();
    sgx_status_t::SGX_SUCCESS
}

fn wasm_invoke(module : Option<String>, field : String, args : Vec<RuntimeValue>)
              -> Result<Option<RuntimeValue>, InterpreterError> {
    let mut program = SPECDRIVER.lock().unwrap();
    let module = program.module_or_last(module.as_ref().map(|x| x.as_ref()))
                        .expect(&format!("Expected program to have loaded module {:?}", module));
    module.invoke_export(&field, &args, program.spec_module())
}

fn wasm_get(module : Option<String>, field : String)
            -> Result<Option<RuntimeValue>, InterpreterError> {
    let program = SPECDRIVER.lock().unwrap();
    let module = match module {
        None => {
                 program
                 .module_or_last(None)
                 .expect(&format!("Expected program to have loaded module {:?}",
                        "None"
                 ))
        },
        Some(str) => {
                 program
                 .module_or_last(Some(&str))
                 .expect(&format!("Expected program to have loaded module {:?}",
                         str
                 ))
        }
    };

    let global = module.export_by_name(&field)
                       .ok_or_else(|| {
                           InterpreterError::Global(format!("Expected to have export with name {}", field))
                       })?
                       .as_global()
                       .cloned()
                       .ok_or_else(|| {
                           InterpreterError::Global(format!("Expected export {} to be a global", field))
                       })?;
     Ok(Some(global.get()))
}

fn try_load_module(wasm: &[u8]) -> Result<Module, InterpreterError> {
    wasmi::Module::from_buffer(wasm).map_err(|e| InterpreterError::Instantiation(format!("Module::from_buffer error {:?}", e)))
}

fn wasm_try_load(wasm: Vec<u8>) -> Result<(), InterpreterError> {
    let ref mut spec_driver = SPECDRIVER.lock().unwrap();
    let module = try_load_module(&wasm[..])?;
    let instance = ModuleInstance::new(&module, &ImportsBuilder::default())?;
    instance
        .run_start(spec_driver.spec_module())
        .map_err(|trap| InterpreterError::Instantiation(format!("ModuleInstance::run_start error on {:?}", trap)))?;
    Ok(())
}

fn wasm_load_module(name: Option<String>, module: Vec<u8>)
                    -> Result<(), InterpreterError> {
    let ref mut spec_driver = SPECDRIVER.lock().unwrap();
    let module = try_load_module(&module[..])?;
    let instance = ModuleInstance::new(&module, &**spec_driver)
        .map_err(|e| InterpreterError::Instantiation(format!("ModuleInstance::new error on {:?}", e)))?
        .run_start(spec_driver.spec_module())
        .map_err(|trap| InterpreterError::Instantiation(format!("ModuleInstance::run_start error on {:?}", trap)))?;

    spec_driver.add_module(name, instance.clone());

    Ok(())
}

fn wasm_register(name: &Option<String>, as_name: String)
                    -> Result<(), InterpreterError> {
    let ref mut spec_driver = SPECDRIVER.lock().unwrap();
    spec_driver.register(name, as_name)
}

fn rsa_verify(hash: &[u8;32], pubkey: &sgx_rsa3072_public_key_t, signature: &sgx_rsa3072_signature_t) -> sgx_status_t {
    match rsgx_rsa3072_verify_slice(hash, pubkey, signature) {
        Ok(flag) => {
            if flag {
                // println!("[+] verify signature success!");
                sgx_status_t::SGX_SUCCESS
            } else {
                // println!("[-] verify signature fail!");
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        },
        Err(err) => {
            // println!("[-] rsgx_rsa3072_verify_slice function fail: {}", err.as_str());
            err
        }
    }
}

#[no_mangle]
pub extern "C"
fn sgxwasm_run_action(hash: &[u8; 32], signature: &sgx_rsa3072_signature_t,
                      req_bin : *const u8, req_length: usize,
                      result_bin : *mut u8, result_max_len: usize) -> sgx_status_t {
    // let pubkey = PUBLIC_KEY.lock().unwrap().clone();
    // let result = rsa_verify(hash, &pubkey, signature);
    // match result {
    //     sgx_status_t::SGX_SUCCESS => {
    //         println!("[+] signature verified success!");
    //     },
    //     sgx_status_t::SGX_ERROR_UNEXPECTED => {
    //         println!("[-] signature verified fail!");
    //         return sgx_status_t::SGX_ERROR_UNEXPECTED;
    //     },
    //     _ => {
    //         println!("[-] rsa_verify function fail: {}", result.as_str());
    //         return result;
    //     }
    // };

    let req_slice = unsafe { slice::from_raw_parts(req_bin, req_length) };
    let action_req: sgxwasm::SgxWasmAction = serde_json::from_slice(req_slice).unwrap();

    let response;
    let return_status;

    match action_req {
        sgxwasm::SgxWasmAction::Invoke{module,field,args}=> {
            let args = args.into_iter()
                           .map(|x| boundary_value_to_runtime_value(x))
                           .collect::<Vec<RuntimeValue>>();
            let r = wasm_invoke(module, field, args);
            let r = result_covert(r);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
               }
            }
        },
        sgxwasm::SgxWasmAction::Get{module,field} => {
            let r = wasm_get(module, field);
            let r = result_covert(r);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_v) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::LoadModule{name,module} => {
            let r = wasm_load_module(name.clone(), module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_LOAD_MODULE_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::TryLoad{module} => {
            let r = wasm_try_load(module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_TRY_LOAD_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::Register{name, as_name} => {
            let r = wasm_register(&name, as_name.clone());
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_REGISTER_ERROR;
                }
            }
        }
    }

    //println!("len = {}, Response = {:?}", response.len(), response);

    if response.len() < result_max_len {
        unsafe {
            ptr::copy_nonoverlapping(response.as_ptr(),
                                     result_bin,
                                     response.len());
        }
        return return_status;
    }
    else{
        //println!("Result len = {} > buf size = {}", response.len(), result_max_len);
        return sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT;
    }
}

fn wasm_run_action(req: &str) -> Result<String, ()> {
    let action_req: sgxwasm::SgxWasmAction = serde_json::from_str(req).unwrap();
    let response;
    let return_status;

    match action_req {
        sgxwasm::SgxWasmAction::Invoke{module,field,args}=> {
            let args = args.into_iter()
                           .map(|x| boundary_value_to_runtime_value(x))
                           .collect::<Vec<RuntimeValue>>();
            let r = wasm_invoke(module, field, args);
            let r = result_covert(r);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
               }
            }
        },
        sgxwasm::SgxWasmAction::Get{module,field} => {
            let r = wasm_get(module, field);
            let r = result_covert(r);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_v) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::LoadModule{name,module} => {
            let r = wasm_load_module(name.clone(), module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_LOAD_MODULE_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::TryLoad{module} => {
            let r = wasm_try_load(module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_TRY_LOAD_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::Register{name, as_name} => {
            let r = wasm_register(&name, as_name.clone());
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_REGISTER_ERROR;
                }
            }
        }
    }

    Ok(response)
}

/// take a look at the module instances in the driver
#[no_mangle]
pub extern "C" fn examine_module() {
    println!("------------------------------------------------------------------------------------------------------");
    println!("WasmEngine module instances: {:?}", SPECDRIVER.lock().unwrap().get_instances());
    println!();
    println!("WasmEngine default module: {:?}", SPECDRIVER.lock().unwrap().get_last_module());
    println!("------------------------------------------------------------------------------------------------------");
}


/// upload key pair
#[no_mangle]
pub extern "C" fn upload_key(privkey: &sgx_rsa3072_key_t, pubkey: &sgx_rsa3072_public_key_t) -> sgx_status_t {
    let mut k = PRIVATE_KEY.lock().unwrap();
    *k = *privkey;
    let mut k = PUBLIC_KEY.lock().unwrap();
    *k = *pubkey;
    // println!("[+] upload key pair success!");
    sgx_status_t::SGX_SUCCESS
}


fn parse_response_attn_report(resp : &[u8], print_log: bool) -> (String, String, String){
    if print_log {println!("parse_response_attn_report");}
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp   = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    if print_log {println!("parse result {:?}", result);}

    let msg : &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
        _ => {println!("DBG:{}", respp.code.unwrap()); msg = "Unknown error occured"},
    }

    if print_log {println!("{}", msg);}
    let mut len_num : u32 = 0;

    let mut sig = String::new();
    let mut cert = String::new();
    let mut attn_report = String::new();

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
        match h.name{
            "Content-Length" => {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                if print_log {println!("content length = {}", len_num);}
            }
            "X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
            "X-IASReport-Signing-Certificate" => cert = str::from_utf8(h.value).unwrap().to_string(),
            _ => (),
        }
    }

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = cert::percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();
    let sig_cert = v[2].to_string();

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = str::from_utf8(resp_body).unwrap().to_string();
        if print_log {println!("Attestation report: {}", attn_report);}
    }

    // len_num == 0
    (attn_report, sig, sig_cert)
}

fn parse_response_sigrl(resp : &[u8], print_log: bool) -> Vec<u8> {
    if print_log {println!("parse_response_sigrl");}
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp   = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    if print_log {
        println!("parse result {:?}", result);
        println!("parse response{:?}", respp);  
    }
    

    let msg : &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
        _ => msg = "Unknown error occured",
    }

    if print_log {println!("{}", msg);}
    let mut len_num : u32 = 0;

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        if h.name == "content-length" {
            let len_str = String::from_utf8(h.value.to_vec()).unwrap();
            len_num = len_str.parse::<u32>().unwrap();
            if print_log {println!("content length = {}", len_num);}
        }
    }

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        if print_log {println!("Base64-encoded SigRL: {:?}", resp_body);}

        return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
    }

    // len_num == 0
    Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    config
}

pub fn get_sigrl_from_intel(fd: c_int, gid: u32, print_log: bool) -> Vec<u8> {
    if print_log {println!("get_sigrl_from_intel fd = {:?}", fd);}
    let config = make_ias_client_config();
    let ias_key = get_ias_api_key();

    let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                        SIGRL_SUFFIX,
                        gid,
                        DEV_HOSTNAME,
                        ias_key);

    if print_log {println!("{}", req);}

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    if print_log {println!("write complete");}

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) => {
            println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            panic!("haha");
        }
    }
    if print_log {println!("read_to_end complete");}
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    if print_log {println!("{}", resp_string);}

    parse_response_sigrl(&plaintext, print_log)
}

// TODO: support pse
pub fn get_report_from_intel(fd : c_int, quote : Vec<u8>, print_log: bool) -> (String, String, String) {
    if print_log {println!("get_report_from_intel fd = {:?}", fd);}
    let config = make_ias_client_config();
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);
    let ias_key = get_ias_api_key();

    let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                           REPORT_SUFFIX,
                           DEV_HOSTNAME,
                           ias_key,
                           encoded_json.len(),
                           encoded_json);

    if print_log {println!("{}", req);}
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    if print_log {println!("write complete");}

    tls.read_to_end(&mut plaintext).unwrap();
    if print_log {println!("read_to_end complete");}
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    if print_log {println!("resp_string = {}", resp_string);}

    let (attn_report, sig, cert) = parse_response_attn_report(&plaintext, print_log);

    (attn_report, sig, cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) <<  0) +
    ((array[1] as u32) <<  8) +
    ((array[2] as u32) << 16) +
    ((array[3] as u32) << 24)
}

#[allow(const_err)]
pub fn create_attestation_report(pub_k: &sgx_ec256_public_t, sign_type: sgx_quote_sign_type_t, print_log: bool) -> Result<(String, String, String), sgx_status_t> {
    let mut print_log_u8: u8 = 0;
    if print_log {print_log_u8 = 1;}
    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti : sgx_target_info_t = sgx_target_info_t::default();
    let mut eg : sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(&mut rt as *mut sgx_status_t,
                             &mut ti as *mut sgx_target_info_t,
                             &mut eg as *mut sgx_epid_group_id_t,
                             print_log_u8)
    };

    if print_log {println!("eg = {:?}", eg);}
    

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let eg_num = as_u32_le(&eg);

    // (1.5) get sigrl
    let mut ias_sock : i32 = 0;

    let res = unsafe {
        ocall_get_ias_socket(&mut rt as *mut sgx_status_t,
                             &mut ias_sock as *mut i32)
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    //println!("Got ias_sock = {}", ias_sock);

    // Now sigrl_vec is the revocation list, a vec<u8>
    let sigrl_vec : Vec<u8> = get_sigrl_from_intel(ias_sock, eg_num, print_log);

    // (2) Generate the report
    // Fill ecc256 public key into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.gx.clone();
    pub_k_gx.reverse();
    let mut pub_k_gy = pub_k.gy.clone();
    pub_k_gy.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) =>{
            if print_log {println!("Report creation => success {:?}", r.body.mr_signer.m);}
            Some(r)
        },
        Err(e) =>{
            println!("Report creation => failed {:?}", e);
            None
        },
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand : [0;16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    if print_log {println!("rand finished");}
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN : u32 = 2048;
    let mut return_quote_buf : [u8; RET_QUOTE_BUF_LEN as usize] = [0;RET_QUOTE_BUF_LEN as usize];
    let mut quote_len : u32 = 0;

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    let (p_sigrl, sigrl_len) =
        if sigrl_vec.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
        };
    let p_report = (&rep.unwrap()) as * const sgx_report_t;
    let quote_type = sign_type;

    let spid : sgx_spid_t = load_spid("spid.txt");

    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as * const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
    ocall_get_quote(&mut rt as *mut sgx_status_t,
                    p_sigrl,
                    sigrl_len,
                    p_report,
                    quote_type,
                    p_spid,
                    p_nonce,
                    p_qe_report,
                    p_quote,
                    maxlen,
                    p_quote_len,
                    print_log_u8)
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    if rt != sgx_status_t::SGX_SUCCESS {
        println!("ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => if print_log {println!("rsgx_verify_report passed!")},
        Err(x) => {
            println!("rsgx_verify_report failed with {:?}", x);
            return Err(x);
        },
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m ||
       ti.attributes.flags != qe_report.body.attributes.flags ||
       ti.attributes.xfrm  != qe_report.body.attributes.xfrm {
        println!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    if print_log {println!("qe_report check passed");}

    // Debug
    // for i in 0..quote_len {
    //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
    // }
    // println!("");

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.

    let mut rhs_vec : Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    if print_log {
        println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
        println!("report hs= {:02X}", lhs_hash.iter().format(""));
    }

    if rhs_hash != lhs_hash {
        if print_log {println!("Quote is tampered!");}
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let res = unsafe {
        ocall_get_ias_socket(&mut rt as *mut sgx_status_t,
                             &mut ias_sock as *mut i32)
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let (attn_report, sig, cert) = get_report_from_intel(ias_sock, quote_vec, print_log);
    Ok((attn_report, sig, cert))
}

fn load_spid(filename: &str) -> sgx_spid_t {
    let mut spidfile = fs::File::open(filename).expect("cannot open spid file");
    let mut contents = String::new();
    spidfile.read_to_string(&mut contents).expect("cannot read the spid file");

    hex::decode_spid(&contents)
}

fn get_ias_api_key() -> String {
    let mut keyfile = fs::File::open("key.txt").expect("cannot open ias key file");
    let mut key = String::new();
    keyfile.read_to_string(&mut key).expect("cannot read the ias key file");
    key.trim_end().to_owned()
}

#[no_mangle]
pub extern "C" fn run_server(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) -> sgx_status_t {
    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let (attn_report, sig, cert) = match create_attestation_report(&pub_k, sign_type, true) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return e;
        }
    };

    let payload = attn_report + "|" + &sig + "|" + &cert;
    let (key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_ecc_cert: {:?}", e);
            return e;
        }
    };
    let _result = ecc_handle.close();

    let root_ca_bin = include_bytes!("../../../cert/ca.crt");
    let mut ca_reader = BufReader::new(&root_ca_bin[..]);
    let mut rc_store = rustls::RootCertStore::empty();
    // Build a root ca storage
    rc_store.add_pem_file(&mut ca_reader).unwrap();
    
    // Build a default authenticator which allow every authenticated client
    let authenticator = rustls::AllowAnyAuthenticatedClient::new(rc_store);
    let mut cfg = rustls::ServerConfig::new(authenticator);
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![]).unwrap();

    let mut sess = rustls::ServerSession::new(&Arc::new(cfg));
    let mut conn = TcpStream::new(socket_fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut conn);

    // init connection
    let mut buf = [0u8; 32];
    match tls.read(&mut buf) {
        Ok(_) => {},
        Err(e) => {
            println!("Error in init connection: {:?}", e);
        }
    }

    // authentication
    let client_auth: u8;    // 1:root   2:guest
    let mut buf = [0u8; 32];
    let mut passwd = String::new();
    match tls.read(&mut buf) {
        Ok(_) => {
            for ch in buf.iter() {
                if *ch != 0x00 {
                    passwd.push(*ch as char);
                }
            }
        },
        Err(e) => {
            println!("Error in read passwd: {:?}", e);
        }
    }
    if passwd == "123" {
        client_auth = 1;
        tls.write_all("root".as_bytes()).unwrap();
    } else {
        client_auth = 2;
        tls.write_all("guest".as_bytes()).unwrap();
    }

    loop {
        println!("Server receiving mode...");
        // read mode
        let mut buf = [0u8; 32];
        let mut mode = String::new();
        match tls.read(&mut buf) {
            Ok(_) => {
                for ch in buf.iter() {
                    if *ch != 0x00 {
                        mode.push(*ch as char);
                    }
                }
            },
            Err(e) => {
                println!("[-] Error in read mode: {:?}", e);
            }
        }

        // guest don't have permission to upload module
        if &mode == "upload" && client_auth != 1 {
            tls.write_all(format!("[-] No Permission to execute mode: {}", &mode).as_bytes()).unwrap();
            continue;
        }
        tls.write_all(format!("Mode: {}", &mode).as_bytes()).unwrap();

        match mode.as_str() {
            "upload" | "test" => {
                loop {
                    println!("Server running in mode {}...", &mode);
    
                    let text_len = 4096;
                    let mut msg = String::new();
                    let mut exit_flag = false;
                    let mut plaintext = [0u8;4096];
                    while let Ok(len) = tls.read(&mut plaintext) {
                        // count the successive '}'
                        let mut cnt = 0;
                        for ch in plaintext.iter() {
                            if *ch == 125 {
                                cnt += 1;
                            } else {
                                cnt = 0;
                            }
                            // println!("u8:{}  char:{}", *ch, *ch as char);
                            msg.push(*ch as char);
                            if cnt == 2 {break;}
                        }
    
                        // the end of the text by client
                        if len < text_len {
                            // println!("Client said: {}", msg);
    
                            // exit the program
                            if msg.starts_with("exit") {
                                // println!("break");
                                tls.write_all("end".as_bytes()).unwrap();
                                exit_flag = true;
                                break;
                            }
    
                            // write to file (only in mode upload)
                            if &mode == "upload" {
                                let file_name = "add.bin".to_string();
    
                                // seal data
                                let sealed_log: [u8; 4096] = [0; 4096];
                                let sealed_log_size = sealed_log.len() as u32;
                                let aad: [u8; 0] = [0_u8; 0];
                                let result = SgxSealedData::<[u8]>::seal_data(&aad, msg.as_bytes());
                                let sealed_data = match result {
                                    Ok(x) => x,
                                    Err(ret) => { return ret; },
                                };
                                let opt = unsafe {
                                    sealed_data.to_raw_sealed_data_t(sealed_log.as_ptr() as *mut sgx_sealed_data_t, sealed_log_size)
                                };
                                if opt.is_none() {
                                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                                }
                                // println!("sealed data: {:?}", sealed_log);
    
                                // store sealed data to file
                                let mut retval = sgx_status_t::SGX_SUCCESS;
                                let result = unsafe {
                                    ocall_store_wasm(
                                        &mut retval as *mut sgx_status_t,
                                        &sealed_log,
                                        file_name.as_ptr() as *const u8,
                                        file_name.len())
                                };
                                match result {
                                    sgx_status_t::SGX_SUCCESS => {},
                                    _ => {
                                        tls.write_all(format!("[-] ocall_store_wasm Failed {}!", result.as_str()).as_bytes()).unwrap();
                                        break;
                                    }
                                }
                            }

                            // run the action provided by the client
                            let ret_str = match wasm_run_action(&msg) {
                                Ok(result) => result,
                                Err(_) => {
                                    tls.write_all("[-] wasm_run_action fail".as_bytes()).unwrap();
                                    break;
                                }
                            };
                            tls.write_all(ret_str.as_bytes()).unwrap();
                            break;
                        }
                    }
                    examine_module();
                    if exit_flag {break;}
                } 
            },
    
            "load" => {
                loop {
                    println!("Server running in mode {}...", &mode);
    
                    let mut file_name = String::new();
                    let mut plaintext = [0u8;64];
    
                    match tls.read(&mut plaintext) {
                        Ok(_) => {
                            for ch in plaintext.iter() {
                                if *ch != 0x00 {
                                    file_name.push(*ch as char);
                                }
                            }
                        },
                        Err(e) => {
                            tls.write_all(format!("[-] Error read tls: {:?}", e).as_bytes()).unwrap();
                            continue;
                        }
                    }
    
                    println!("wasm file name in enclave: {}", file_name);
                    // exit the program
                    if file_name.starts_with("exit") {
                        // println!("break");
                        tls.write_all("end".as_bytes()).unwrap();
                        break;
                    }
    
                    // read wasm file through ocall
                    let mut ret_val = sgx_status_t::SGX_SUCCESS;
                    let mut sealed_log: [u8; 4096] = [0; 4096];
                    let sealed_log_size = sealed_log.len() as u32;
                    let result = unsafe {
                        ocall_load_wasm(
                            &mut ret_val as *mut sgx_status_t, 
                            &mut sealed_log,
                            file_name.as_ptr() as *const u8, 
                            file_name.len())
                    };
                    match result {
                        sgx_status_t::SGX_SUCCESS => {},
                        _ => {
                            tls.write_all(format!("[-] ocall_load_wasm Failed {}", result.as_str()).as_bytes());
                            continue;
                        }
                    }
                    match ret_val {
                        sgx_status_t::SGX_SUCCESS => {},
                        _ => {
                            tls.write_all(format!("[-] ocall_load_wasm Failed {}", result.as_str()).as_bytes());
                            continue;
                        }
                    }
                    
                    // unseal data
                    let opt = unsafe {
                        SgxSealedData::<[u8]>::from_raw_sealed_data_t(sealed_log.as_ptr() as *mut sgx_sealed_data_t, sealed_log_size)
                    };
                    let sealed_data = match opt {
                        Some(x) => x,
                        None => {
                            tls.write_all("[-] unwrap sealed data fail".as_bytes()).unwrap();
                            // return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                            continue;
                        },
                    };
                    let result = sealed_data.unseal_data();
                    let unsealed_data = match result {
                        Ok(x) => x,
                        Err(ret) => {
                            tls.write_all("[-] unseal data fail".as_bytes()).unwrap();
                            continue;
                        },
                    };
                    let encoded_slice = unsealed_data.get_decrypt_txt();
                    let mut wasm = String::new();
                    for ch in encoded_slice {
                        if *ch != 0x00 {
                            wasm.push(*ch as char);
                        }
                    }
                    // println!("wasm to load: {}", wasm);                
    
                    // run action
                    let ret_str = match wasm_run_action(&wasm) {
                        Ok(result) => result,
                        Err(_) => {
                            tls.write_all("[-] wasm_run_action fail".as_bytes()).unwrap();
                            continue;
                        }
                    };
                    tls.write_all(ret_str.as_bytes()).unwrap();
                    examine_module();
                }
            },
    
            "check" => {
                println!("Client mode: {}", &mode);
                let (check_report, check_sig, check_cert) = match create_attestation_report(&pub_k, sign_type, false) {
                    Ok(r) => r,
                    Err(e) => {
                        println!("Error in create_attestation_report: {:?}", e);
                        // return e;
                        continue;
                    }
                };
                println!();
                println!("check_report: {}", &check_report);
                println!("check_sig: {}", &check_sig);
                println!("check_cert: {}", &check_cert);
            },
    
            "quit" => {
                println!("Close connection");
                break;
            },

            _ => {}
        }
    }

    sgx_status_t::SGX_SUCCESS
}