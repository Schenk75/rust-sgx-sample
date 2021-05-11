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

extern crate sgx_types;
extern crate sgx_urts;
extern crate sgx_ucrypto as crypto;

extern crate nan_preserving_float;
extern crate wabt;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use crypto::*;

mod wasm_def;

use wasm_def::{RuntimeValue, Error as InterpreterError};
use wabt::script::{Action, Command, CommandKind, ScriptParser, Value};
use std::os::unix::io::{IntoRawFd, AsRawFd};
use std::{fs, env, slice, ptr};
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, SocketAddr};

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

static MAXOUTPUT: usize = 4096;

extern {
    fn sgxwasm_init(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t ;
    fn sgxwasm_run_action(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                          hash: &[u8; 32],
                          signature: &sgx_rsa3072_signature_t,
                          req_bin : *const u8, req_len: usize,
                          result_bin : *mut u8,
                          result_max_len : usize ) -> sgx_status_t;
    fn examine_module(eid: sgx_enclave_id_t, retval: *mut sgx_status_t);
    fn upload_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        privkey: &sgx_rsa3072_key_t,
        pubkey: &sgx_rsa3072_public_key_t) -> sgx_status_t;
    fn run_server(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
        socket_fd: c_int, sign_type: sgx_quote_sign_type_t) -> sgx_status_t;
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SgxWasmAction {
    Invoke {
        module: Option<String>,
        field: String,
        args: Vec<BoundaryValue>
    },
    Get {
        module: Option<String>,
        field: String,
    },
    LoadModule {
        name: Option<String>,
        module: Vec<u8>,
    },
    TryLoad {
        module: Vec<u8>,
    },
    Register {
        name: Option<String>,
        as_name: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BoundaryValue {
    I32(i32),
    I64(i64),
    F32(u32),
    F64(u64),
    V128(u128),
}

fn wabt_runtime_value_to_boundary_value(wabt_rv : &wabt::script::Value) -> BoundaryValue {
    match wabt_rv {
        &wabt::script::Value::I32(wabt_rv) => BoundaryValue::I32(wabt_rv),
        &wabt::script::Value::I64(wabt_rv) => BoundaryValue::I64(wabt_rv),
        &wabt::script::Value::F32(wabt_rv) => BoundaryValue::F32(wabt_rv.to_bits()),
        &wabt::script::Value::F64(wabt_rv) => BoundaryValue::F64(wabt_rv.to_bits()),
        &wabt::script::Value::V128(wabt_rv) => BoundaryValue::V128(wabt_rv),
    }
}

#[allow(dead_code)]
fn runtime_value_to_boundary_value(rv: RuntimeValue) -> BoundaryValue {
    match rv {
        RuntimeValue::I32(rv) => BoundaryValue::I32(rv),
        RuntimeValue::I64(rv) => BoundaryValue::I64(rv),
        RuntimeValue::F32(rv) => BoundaryValue::F32(rv.to_bits()),
        RuntimeValue::F64(rv) => BoundaryValue::F64(rv.to_bits()),
        RuntimeValue::V128(rv) => BoundaryValue::V128(rv),
    }
}

fn boundary_value_to_runtime_value(rv: BoundaryValue) -> RuntimeValue {
    match rv {
        BoundaryValue::I32(bv) => RuntimeValue::I32(bv),
        BoundaryValue::I64(bv) => RuntimeValue::I64(bv),
        BoundaryValue::F32(bv) => RuntimeValue::F32(bv.into()),
        BoundaryValue::F64(bv) => RuntimeValue::F64(bv.into()),
        BoundaryValue::V128(bv) => RuntimeValue::V128(bv.into()),
    }
}

pub fn answer_convert(res : Result<Option<BoundaryValue>, InterpreterError>)
                     ->  Result<Option<RuntimeValue>, InterpreterError>
{
    match res {
        Ok(None) => Ok(None),
        Ok(Some(rv)) => Ok(Some(boundary_value_to_runtime_value(rv))),
        Err(x) => Err(x),
    }
}

fn spec_to_runtime_value(value: Value) -> RuntimeValue {
    match value {
        Value::I32(v) => RuntimeValue::I32(v),
        Value::I64(v) => RuntimeValue::I64(v),
        Value::F32(v) => RuntimeValue::F32(v.into()),
        Value::F64(v) => RuntimeValue::F64(v.into()),
        Value::V128(v) => RuntimeValue::V128(v.into()),
    }
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

fn sgx_enclave_wasm_init(enclave: &SgxEnclave) -> Result<(),String> {
    let mut retval:sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        sgxwasm_init(enclave.geteid(),
                     &mut retval)
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            panic!("sgx_enclave_wasm_init's ECALL returned unknown error!");
        }
    }

    match retval {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Function return fail: {}!", retval.as_str());
            return Err(format!("ECALL func return error: {}", retval.as_str()));
        }
    }

    Ok(())
}

fn sgx_enclave_wasm_invoke(sign_msg : Option<(String, sgx_rsa3072_signature_t, [u8;32])>,
                           result_max_len : usize,
                           enclave_id : u64) -> (Result<Option<BoundaryValue>, InterpreterError>, sgx_status_t) {
    let (req_str, signature, hash) = match sign_msg {
        Some((msg, sig, h)) => (msg, sig, h),
        None => panic!("sgx_enclave_wasm_invoke sign msg error!")
    };
    println!("req_str: {}", &req_str);

    let mut ret_val = sgx_status_t::SGX_SUCCESS;
    let     req_bin = req_str.as_ptr() as * const u8;
    let     req_len = req_str.len();

    let mut result_vec:Vec<u8> = vec![0; result_max_len];
    let     result_slice = &mut result_vec[..];

    let sgx_ret = unsafe{sgxwasm_run_action(enclave_id,
                                     &mut ret_val,
                                     &hash,
                                     &signature,
                                     req_bin,
                                     req_len,
                                     result_slice.as_mut_ptr(),
                                     result_max_len)};

    match sgx_ret {
        // sgx_ret falls in range of Intel's Error code set
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", sgx_ret.as_str());
            panic!("sgx_enclave_wasm_load_invoke's ECALL returned unknown error!");
        }
    }

    // We need to trim all trailing '\0's before conver to string
    let mut result_vec:Vec<u8> = result_slice.to_vec();
    result_vec.retain(|x| *x != 0x00u8);

    //let result_str : String;
    let result:Result<Option<BoundaryValue>, InterpreterError>;
    // Now result_vec only includes essential chars
    if result_vec.len() == 0 {
        result = Ok(None);
    }
    else{
        let raw_result_str = String::from_utf8(result_vec).unwrap();
        result = serde_json::from_str(&raw_result_str).unwrap();
    }

    match ret_val {
        // ret_val falls in range of [SGX_SUCCESS + SGX_ERROR_WASM_*]
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            // In this case, the returned buffer is useful
            return (result, ret_val);
        }
    }

    // ret_val should be SGX_SUCCESS here
    (result, ret_val)
}

fn sgx_enclave_wasm_load_module(module : Vec<u8>,
                                name   : &Option<String>,
                                privkey: &sgx_rsa3072_key_t,
                                enclave_id : u64)
                                -> Result<(), String> {

    // Init a SgxWasmAction::LoadModule struct and send it to enclave
    let req = SgxWasmAction::LoadModule {
                  name : name.as_ref().map(|x| x.clone()),
                  module : module,
              };
    let sign_msg = sign_msg(serde_json::to_string(&req).unwrap(), privkey);
    match sgx_enclave_wasm_invoke(sign_msg,
                                  MAXOUTPUT,
                                  enclave_id) {
        (_, sgx_status_t::SGX_SUCCESS) => {
            Ok(())
        },
        (Err(x), sgx_status_t::SGX_ERROR_WASM_LOAD_MODULE_ERROR) => {
            Err(x.to_string())
        },
        (_, _) => {
            println!("sgx_enclave_wasm_load_module should not arrive here!");
            panic!("sgx_enclave_wasm_load_module returned unknown error!");
        },
    }
}

fn sgx_enclave_wasm_run_action(action: &Action, privkey: &sgx_rsa3072_key_t, enclave_id: u64) -> Result<Option<RuntimeValue>, InterpreterError> {
    match action {
        &Action::Invoke {
            ref module,
            ref field,
            ref args,
        } => {
            // Deal with Invoke
            // Make a SgxWasmAction::Invoke structure and send it to sgx_enclave_wasm_invoke
            let req = SgxWasmAction::Invoke {
                          module : module.as_ref().map(|x| x.clone()),
                          field  : field.clone(),
                          args   : args.into_iter()
                                       .map(wabt_runtime_value_to_boundary_value)
                                       .collect()
            };
            let sign_msg = sign_msg(serde_json::to_string(&req).unwrap(), privkey);
            let result = sgx_enclave_wasm_invoke(sign_msg,
                                                 MAXOUTPUT,
                                                 enclave_id);
            match result {
                (result, sgx_status_t::SGX_SUCCESS) => {
                    let result_obj : Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                    result_obj
                },
                (result, sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR) => {
                    let result_obj : Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                    result_obj
                },
                (_, _) => {
                    println!("sgx_enclave_wasm_run_action::Invoke returned unknown error!");
                    panic!("sgx_enclave_wasm_run_action::Invoke returned unknown error!");
                },
            }
        },
        &Action::Get {
            ref module,
            ref field,
            ..
        } => {
            // Deal with Get
            // Make a SgxWasmAction::Get structure and send it to sgx_enclave_wasm_invoke
            let req = SgxWasmAction::Get {
                module : module.as_ref().map(|x| x.clone()),
                field  : field.clone(),
            };
            let sign_msg = sign_msg(serde_json::to_string(&req).unwrap(), privkey);
            let result = sgx_enclave_wasm_invoke(sign_msg,
                                                 MAXOUTPUT,
                                                 enclave_id);

            match result {
                (result, sgx_status_t::SGX_SUCCESS) => {
                    let result_obj : Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                    result_obj
                },
                (result, sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR) => {
                    let result_obj : Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                    result_obj
                },
                (_, _) => { println!("sgx_enclave_wasm_run_action::Get returned unknown error!");
                    panic!("sgx_enclave_wasm_run_action::Get returned unknown error!");
                }
            }
        },
    }
}

// Malform
fn sgx_enclave_wasm_try_load(module: &[u8], privkey: &sgx_rsa3072_key_t, enclave_id: u64) -> Result<(), InterpreterError> {
    // Make a SgxWasmAction::TryLoad structure and send it to sgx_enclave_wasm_invoke
    let req = SgxWasmAction::TryLoad {
        module : module.to_vec(),
    };

    let sign_msg = sign_msg(serde_json::to_string(&req).unwrap(), privkey);
    let result = sgx_enclave_wasm_invoke(sign_msg,
                                         MAXOUTPUT,
                                         enclave_id);
    match result {
        (_, sgx_status_t::SGX_SUCCESS) => {
            Ok(())
        },
        (Err(x), sgx_status_t::SGX_ERROR_WASM_TRY_LOAD_ERROR) => {
            Err(InterpreterError::Global(x.to_string()))
        },
        (_, _) => {
            println!("sgx_enclave_wasm_try_load returned unknown error!");
            panic!("sgx_enclave_wasm_try_load returned unknown error!");
        }
    }
}

// Register
fn sgx_enclave_wasm_register(name : Option<String>,
                             as_name : String,
                             privkey: &sgx_rsa3072_key_t,
                             enclave_id : u64) -> Result<(), InterpreterError> {
    // Make a SgxWasmAction::Register structure and send it to sgx_enclave_wasm_invoke
    let req = SgxWasmAction::Register{
        name : name,
        as_name : as_name,
    };
    let sign_msg = sign_msg(serde_json::to_string(&req).unwrap(), privkey);
    let result = sgx_enclave_wasm_invoke(sign_msg,
                                         MAXOUTPUT,
                                         enclave_id);

    match result {
        (_, sgx_status_t::SGX_SUCCESS) => {
            Ok(())
        },
        (Err(x), sgx_status_t::SGX_ERROR_WASM_REGISTER_ERROR) => {
            Err(InterpreterError::Global(x.to_string()))
        },
        (_, _) => {
            println!("sgx_enclave_wasm_register returned unknown error!");
            panic!("sgx_enclave_wasm_register returned unknown error!");
        }
    }
}

fn wasm_main_loop(wast_file: &str, privkey: &sgx_rsa3072_key_t, enclave_id: u64) -> Result<(), String> {
    // ScriptParser interface has changed. Need to feed it with wast content.
    let wast_content = match std::fs::read(wast_file) {
        Ok(content) => content,
        Err(x) => return Err(x.to_string())
    };
    // let wast_content : Vec<u8> = std::fs::read(wast_file).unwrap();
    // println!("{:?}", wast_content);
    let path = std::path::Path::new(wast_file);
    let fnme = path.file_name().unwrap().to_str().unwrap();
    // println!("{}", fnme);
    let mut parser = ScriptParser::from_source_and_name(&wast_content, fnme).unwrap();

    // sgx_enclave_wasm_init(enclave)?;
    while let Some(Command{kind,line}) =
            match parser.next() {
                Ok(x) => x,
                _ => { return Err("Error parsing test input".to_string()); }
            }
    {
        println!("Line : {}", line);

        match kind {
            CommandKind::Module { name, module, .. } => {
                // println!("module: {:?}", &module);
                // let name = Some(String::from("test"));
                sgx_enclave_wasm_load_module (module.into_vec(), &name, privkey, enclave_id)?;
                println!("load module - success at line {}", line)
            },

            CommandKind::AssertReturn { action, expected } => {
                // println!("expected: {:?}", &expected);
                let result:Result<Option<RuntimeValue>, InterpreterError> = sgx_enclave_wasm_run_action(&action, privkey, enclave_id);
                match result {
                    Ok(result) => {
                        let spec_expected = expected.iter()
                                                    .cloned()
                                                    .map(spec_to_runtime_value)
                                                    .collect::<Vec<_>>();
                        let actual_result = result.into_iter().collect::<Vec<RuntimeValue>>();
                        for (actual_result, spec_expected) in actual_result.iter().zip(spec_expected.iter()) {
                            assert_eq!(actual_result.value_type(), spec_expected.value_type());
                            // f32::NAN != f32::NAN
                            match spec_expected {
                                &RuntimeValue::F32(val) if val.is_nan() => match actual_result {
                                    &RuntimeValue::F32(val) => assert!(val.is_nan()),
                                    _ => unreachable!(), // checked above that types are same
                                },
                                &RuntimeValue::F64(val) if val.is_nan() => match actual_result {
                                    &RuntimeValue::F64(val) => assert!(val.is_nan()),
                                    _ => unreachable!(), // checked above that types are same
                                },
                                spec_expected @ _ => assert_eq!(actual_result, spec_expected),
                            }
                        }
                        println!("assert_return at line {} - success", line);
                    },
                    Err(e) => {
                        panic!("Expected action to return value, got error: {:?}", e);
                    }
                }
            },

            CommandKind::AssertReturnCanonicalNan { action }
            | CommandKind::AssertReturnArithmeticNan { action } => {
                let result:Result<Option<RuntimeValue>, InterpreterError> = sgx_enclave_wasm_run_action(&action, privkey, enclave_id);
                match result {
                    Ok(result) => {
                        for actual_result in result.into_iter().collect::<Vec<RuntimeValue>>() {
                            match actual_result {
                                RuntimeValue::F32(val) => if !val.is_nan() {
                                    panic!("Expected nan value, got {:?}", val)
                                },
                                RuntimeValue::F64(val) => if !val.is_nan() {
                                    panic!("Expected nan value, got {:?}", val)
                                },
                                val @ _ => {
                                    panic!("Expected action to return float value, got {:?}", val)
                                }
                            }
                        }
                        println!("assert_return_nan at line {} - success", line);
                    }
                    Err(e) => {
                        panic!("Expected action to return value, got error: {:?}", e);
                    }
                }
            },

            CommandKind::AssertExhaustion { action, .. } => {
                let result:Result<Option<RuntimeValue>, InterpreterError> = sgx_enclave_wasm_run_action(&action, privkey, enclave_id);
                match result {
                    Ok(result) => panic!("Expected exhaustion, got result: {:?}", result),
                    Err(e) => println!("assert_exhaustion at line {} - success ({:?})", line, e),
                }
            },

            CommandKind::AssertTrap { action, .. } => {
                println!("Enter AssertTrap!");
                let result:Result<Option<RuntimeValue>, InterpreterError> = sgx_enclave_wasm_run_action(&action, privkey, enclave_id);
                match result {
                    Ok(result) => {
                        panic!("Expected action to result in a trap, got result: {:?}", result);
                    },
                    Err(e) => {
                        println!("assert_trap at line {} - success ({:?})", line, e);
                    },
                }
            },

            CommandKind::AssertInvalid { module, .. }
            | CommandKind::AssertMalformed { module, .. }
            | CommandKind::AssertUnlinkable { module, .. } => {
                // Malformed
                let module_load = sgx_enclave_wasm_try_load(&module.into_vec(), privkey, enclave_id);
                match module_load {
                    Ok(_) => panic!("Expected invalid module definition, got some module!"),
                    Err(e) => println!("assert_invalid at line {} - success ({:?})", line, e),
                }
            },

            CommandKind::AssertUninstantiable { module, .. } => {
                let module_load = sgx_enclave_wasm_try_load(&module.into_vec(), privkey,  enclave_id);
                match module_load {
                    Ok(_) => panic!("Expected error running start function at line {}", line),
                    Err(e) => println!("assert_uninstantiable - success ({:?})", e),
                }
            },

            CommandKind::Register { name, as_name, .. } => {
                let result = sgx_enclave_wasm_register(name, as_name, privkey, enclave_id);
                match result {
                    Ok(_) => {println!("register - success at line {}", line)},
                    Err(e) => panic!("No such module, at line {} - ({:?})", e, line),
                }
            },

            CommandKind::PerformAction(action) => {
                let result:Result<Option<RuntimeValue>, InterpreterError> = sgx_enclave_wasm_run_action(&action, privkey, enclave_id);
                match result {
                    Ok(_) => {println!("invoke - success at line {}", line)},
                    Err(e) => panic!("Failed to invoke action at line {}: {:?}", line, e),
                }
            },
        }
    }
    println!("[+] all tests passed!\n");
    Ok(())
}

fn run_a_wast(enclave_id: u64,
              wast_file: &str,
              privkey: &sgx_rsa3072_key_t) -> Result<(), String> {
    let mut retval = sgx_status_t::SGX_SUCCESS;

    // Step 1: Init the sgxwasm spec driver engine
    // move it out of the loop
    // sgx_enclave_wasm_init(enclave)?;

    // Step 2: Load the wast file and run
    wasm_main_loop(wast_file, privkey, enclave_id)?;
    // examine the modules in enclave
    unsafe {examine_module(enclave_id, &mut retval);}

    Ok(())
}

fn generate_rsa_keypair(pubkey: &mut sgx_rsa3072_public_key_t, privkey: &mut sgx_rsa3072_key_t, file_name: String) -> i32 {
    let mut n: [u8; SGX_RSA3072_KEY_SIZE] = [0; SGX_RSA3072_KEY_SIZE];   // 384
    let mut e: [u8; SGX_RSA3072_PUB_EXP_SIZE] = [1, 0, 0, 1];   // 4
    let mut d: [u8; SGX_RSA3072_PRI_EXP_SIZE] = [0; SGX_RSA3072_PRI_EXP_SIZE];   // 384
    let mut p: [u8; SGX_RSA3072_KEY_SIZE / 2] = [0; SGX_RSA3072_KEY_SIZE / 2];
    let mut q: [u8; SGX_RSA3072_KEY_SIZE / 2] = [0; SGX_RSA3072_KEY_SIZE / 2];
    let mut dmp1: [u8; SGX_RSA3072_KEY_SIZE / 2] = [0; SGX_RSA3072_KEY_SIZE / 2];
    let mut dmq1: [u8; SGX_RSA3072_KEY_SIZE / 2] = [0; SGX_RSA3072_KEY_SIZE / 2];
    let mut iqmp: [u8; SGX_RSA3072_KEY_SIZE / 2] = [0; SGX_RSA3072_KEY_SIZE / 2];
    
    match rsgx_create_rsa_key_pair(
        384,
        4,
        &mut n,
        &mut d,
        &mut e,
        &mut p,
        &mut q,
        &mut dmp1,
        &mut dmq1,
        &mut iqmp)
        {
            Err(err) => {
                println!("[-] rsgx_create_rsa_key_pair function fail: {}", err.as_str());
                return -1;
            },
            Ok(()) => {}
        };

    // create a file to store rsa key pair
    match fs::File::create(&file_name) {
        Ok(_f) => {},
        Err(e) => {
            println!("[-] create file fail: {}", e);
            return -1;
        }
    }

    // open file
    let mut file = match fs::OpenOptions::new().append(true).open(&file_name) {
        Ok(f) => f,
        Err(e) => {
            println!("[-] open file fail: {}", e);
            return -1;
        }
    };

    // write into file
    file.write(&n).unwrap();
    file.write(&e).unwrap();
    file.write(&d).unwrap();
    file.write(&p).unwrap();
    file.write(&q).unwrap();
    file.write(&dmp1).unwrap();
    file.write(&dmq1).unwrap();
    file.write(&iqmp).unwrap();

    pubkey.modulus = n;
    pubkey.exponent = e;

    privkey.modulus = n;
    privkey.e = e;
    privkey.d = d;
    0
}

fn sha256_u(input: &str) -> [u8;32] {
    let result = rsgx_sha256_slice(input.as_bytes());

    match result {
        Ok(output_hash) => {
            output_hash
        },
        Err(_) => [0; 32]
    }
}

fn sign_msg(msg: String, privkey: &sgx_rsa3072_key_t) -> Option<(String, sgx_rsa3072_signature_t, [u8;32])> {
    let hash = sha256_u(msg.as_str());
    // // sign the sha256 hash by rsa3072 private key
    // let signature = match rsgx_rsa3072_sign_slice(&hash, privkey) {
    //     Ok(sig) => {sig},
    //     Err(err) => {
    //         println!("[-] rsgx_rsa3072_sign_slice function fail: {}", err.as_str());
    //         return None;
    //     }
    // };
    
    // Some((msg, signature, hash))
    Some((msg, sgx_rsa3072_signature_t::default(), hash))
}

#[no_mangle]
pub extern "C"
fn ocall_sgx_init_quote(ret_ti: *mut sgx_target_info_t,
                        ret_gid : *mut sgx_epid_group_id_t,
                        print_log: u8) -> sgx_status_t {
    if print_log == 1 {println!("Entering ocall_sgx_init_quote");}
    unsafe {sgx_init_quote(ret_ti, ret_gid)}
}

pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

#[no_mangle]
pub extern "C"
fn ocall_get_ias_socket(ret_fd : *mut c_int) -> sgx_status_t {
    let port = 443;
    let hostname = "api.trustedservices.intel.com";
    let addr = lookup_ipv4(hostname, port);
    let sock = TcpStream::connect(&addr).expect("[-] Connect tls server failed!");

    unsafe {*ret_fd = sock.into_raw_fd();}

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C"
fn ocall_get_quote (p_sigrl            : *const u8,
                    sigrl_len          : u32,
                    p_report           : *const sgx_report_t,
                    quote_type         : sgx_quote_sign_type_t,
                    p_spid             : *const sgx_spid_t,
                    p_nonce            : *const sgx_quote_nonce_t,
                    p_qe_report        : *mut sgx_report_t,
                    p_quote            : *mut u8,
                    _maxlen            : u32,
                    p_quote_len        : *mut u32,
                    print_log          : u8) -> sgx_status_t {
    if print_log == 1 {println!("Entering ocall_get_quote");}
    
    let mut real_quote_len : u32 = 0;

    let ret = unsafe {
        sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32)
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        if print_log == 1 {println!("sgx_calc_quote_size returned {}", ret);}
        return ret;
    }

    if print_log == 1 {println!("quote size = {}", real_quote_len);}
    unsafe { *p_quote_len = real_quote_len; }

    let ret = unsafe {
        sgx_get_quote(p_report,
                      quote_type,
                      p_spid,
                      p_nonce,
                      p_sigrl,
                      sigrl_len,
                      p_qe_report,
                      p_quote as *mut sgx_quote_t,
                      real_quote_len)
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        if print_log == 1 {println!("sgx_calc_quote_size returned {}", ret);}
        return ret;
    }

    if print_log == 1 {println!("sgx_calc_quote_size returned {}", ret);}
    ret
}

#[no_mangle]
pub extern "C"
fn ocall_get_update_info (platform_blob: * const sgx_platform_info_t,
                          enclave_trusted: i32,
                          update_info: * mut sgx_update_info_bit_t) -> sgx_status_t {
    unsafe{
        sgx_report_attestation_status(platform_blob, enclave_trusted, update_info)
    }
}


#[no_mangle]
pub extern "C" fn ocall_load_wasm (sealed_log: &mut [u8; 4096], file_name: *const u8, name_len: usize) -> sgx_status_t {
    let file_name_slice = unsafe {slice::from_raw_parts(file_name, name_len)};
    let file_name = format!("./storage/{}", std::str::from_utf8(file_name_slice).unwrap());

    let mut file = match fs::File::open(file_name){
        Ok(f) => f,
        Err(e) => {
            println!("Cannot open file: {:?}", e);
            return sgx_status_t::SGX_ERROR_FILE_BAD_STATUS;
        }
    };
    let _ = file.read(sealed_log);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ocall_store_wasm (sealed_log: &[u8; 4096], file_name: *const u8, name_len: usize) -> sgx_status_t {
    let file_name_slice = unsafe {slice::from_raw_parts(file_name, name_len)};
    let file_name = std::str::from_utf8(file_name_slice).unwrap();

    println!("file name: {}", file_name);

    let mut file = fs::File::create(format!("./storage/{}", file_name)).expect("create file failed");
    file.write_all(sealed_log).expect("write file failed");

    sgx_status_t::SGX_SUCCESS
}

fn main() {
    let mut args: Vec<_> = env::args().collect();
    let mut sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
    args.remove(0);
    while !args.is_empty() {
        match args.remove(0).as_ref() {
            "--unlink" => sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
            _ => {
                panic!("Only --unlink is accepted");
            }
        }
    }

    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };
    let eid = enclave.geteid();
    
    // Init the sgxwasm spec driver engine
    match sgx_enclave_wasm_init(&enclave) {
        Ok(()) => {
            println!("[+] Sgxwasm Spec Driver Engine Init Success!")
        },
        Err(x) => {
            println!("{}", x);
        }
    }

    println!("Running as server...");
    let listener = TcpListener::bind("0.0.0.0:3443").unwrap();

    // let mut result_vec:Vec<u8> = vec![0; MAXOUTPUT];
    // let result_slice = &mut result_vec[..];

    match listener.accept() {
        Ok((socket, addr)) => {
            println!("new client from {:?}", addr);
            let mut retval = sgx_status_t::SGX_SUCCESS;
            let result = unsafe {
                run_server(eid, &mut retval, socket.as_raw_fd(), sign_type)
            };
            match result {
                sgx_status_t::SGX_SUCCESS => {
                    println!("Ecall run_server success!");
                },
                _ => {
                    println!("[-] ECALL run_server Failed {}!", result.as_str());
                    return;
                }
            }
        }
        Err(e) => println!("couldn't get client: {:?}", e),
    }

    // // We need to trim all trailing '\0's before conver to string
    // let mut result_vec:Vec<u8> = result_slice.to_vec();
    // result_vec.retain(|x| *x != 0x00u8);
    // let mut wast_file = String::new();
    // // Now result_vec only includes essential chars
    // if result_vec.len() != 0 {
    //     wast_file = String::from_utf8(result_vec).unwrap().trim().to_string();
    // } else {
    //     println!("[-] result_vec is empty");
    // }
    // println!("wasm file: {}", wast_file);

    // // create rsa3072 public key and private key
    // let mut pubkey = sgx_rsa3072_public_key_t::default();
    // let mut privkey = sgx_rsa3072_key_t::default();
    // println!("Input rsa key file: ");
    // let mut key_file = String::new();
    // std::io::stdin().read_line(&mut key_file).expect("Failed to read line");
    // key_file = key_file.trim().to_string();
    // match fs::File::open(&key_file) {
    //     Ok(mut file) => {
    //         let mut n = [0_u8; SGX_RSA3072_KEY_SIZE];
    //         let mut e = [0_u8; 4];
    //         let mut d = [0_u8; SGX_RSA3072_PRI_EXP_SIZE];
    //         file.read(&mut n).unwrap();
    //         file.read(&mut e).unwrap();
    //         file.read(&mut d).unwrap();
    //         pubkey.modulus = n;
    //         pubkey.exponent = e;
    //         privkey.modulus = n;
    //         privkey.d = d;
    //         privkey.e = e;
    //     },
    //     Err(_e) => {
    //         if generate_rsa_keypair(&mut pubkey, &mut privkey, key_file) == -1 {
    //             println!("[-] generate_rsa_keypair function fail!");
    //             enclave.destroy();
    //             println!("\n[+] Destroy Enclave {}", eid);
    //             return;
    //         } else {
    //             println!("[+] create rsa key pair success!");
    //         }
    //     }
    // };
    // // upload rsa3072 key pair to enclave
    // let mut retval = sgx_status_t::SGX_SUCCESS;
    // let result = unsafe{
    //     upload_key(eid, &mut retval, &privkey, &pubkey)
    // };
    // match result {
    //     sgx_status_t::SGX_SUCCESS => {
    //         println!("[+] upload_key function success!");
    //     },
    //     _ => {
    //         println!("[-] upload_key function fail: {}", result.as_str());
    //     }
    // };

    // wast_file = format!("../test_input/{}.wast", wast_file);
    // println!("======================= testing {} =====================", &wast_file);
    // match run_a_wast(&enclave, &wast_file, &privkey) {
    //     Ok(()) => {},
    //     Err(x) => {
    //         println!("{}", x);
    //     }
    // };
    // loop {
    //     // println!("Input wast file name: ");
    //     let mut wast_file = String::new();
    //     // std::io::stdin().read_line(&mut wast_file).expect("Failed to read line");
    //     // wast_file = wast_file.trim().to_string();
    //     if wast_file.eq("exit") {
    //         break;
    //     }
    //     wast_file = format!("../test_input/{}.wast", wast_file);
    //     println!("======================= testing {} =====================", &wast_file);
    //     match run_a_wast(&enclave, &wast_file, &privkey) {
    //         Ok(()) => {},
    //         Err(x) => {
    //             println!("{}", x);
    //         }
    //     };
    // }

    enclave.destroy();
    println!("\n[+] Enclave destroy success! {}", eid);

    return;
}
