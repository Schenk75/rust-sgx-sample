extern crate chrono;
extern crate webpki;
extern crate rustls;
extern crate base64;
extern crate itertools;
extern crate serde_json;
extern crate num_bigint;
extern crate bit_vec;
extern crate hex;
extern crate sgx_types;
extern crate sgx_ucrypto as crypto;
extern crate wabt;
extern crate serde;
extern crate nan_preserving_float;
#[macro_use]
extern crate serde_derive;

use sgx_types::*;
use crypto::*;

mod cert;
mod pib;
mod wasm_def;

use std::io::{self, Write, Read, BufReader};
use std::sync::Arc;
use std::{str, fs, env, slice};
use std::net::TcpStream;
use wasm_def::{RuntimeValue, Error as InterpreterError};
use wabt::script::{Action, Command, CommandKind, ScriptParser, Value};

const SERVERADDR: &str = "localhost:3443";
static MAXOUTPUT: usize = 4096;

struct ServerAuth {
    outdated_ok: bool
}

impl ServerAuth {
    fn new(outdated_ok: bool) -> ServerAuth {
        ServerAuth{ outdated_ok }
    }
}

impl rustls::ServerCertVerifier for ServerAuth {
    fn verify_server_cert(&self,
              _roots: &rustls::RootCertStore,
              _certs: &[rustls::Certificate],
              _hostname: webpki::DNSNameRef,
              _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        println!("--received-server cert: {:?}", _certs);
        // This call will automatically verify cert is properly signed
        match cert::verify_mra_cert(&_certs[0].0) {
            Ok(()) => {
                Ok(rustls::ServerCertVerified::assertion())
            }
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    println!("outdated_ok is set, overriding outdated error");
                    Ok(rustls::ServerCertVerified::assertion())
                } else {
                    Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
                }
            }
            Err(_) => {
                Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
            }
        }
    }
}

fn make_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    let client_cert = include_bytes!("../../cert/client.crt");
    // let client_cert = include_bytes!("../../cert/otherclient.crt");
    let mut cc_reader = BufReader::new(&client_cert[..]);

    let client_pkcs8_key = include_bytes!("../../cert/client.pkcs8");
    // let client_pkcs8_key = include_bytes!("../../cert/otherclient.pkcs8");
    let mut client_key_reader = BufReader::new(&client_pkcs8_key[..]);

    let certs = rustls::internal::pemfile::certs(&mut cc_reader).unwrap();
    let privk = rustls::internal::pemfile::pkcs8_private_keys(&mut client_key_reader);

    config.set_single_client_cert(certs, privk.unwrap()[0].clone());

    config.dangerous().set_certificate_verifier(Arc::new(ServerAuth::new(true)));
    config.versions.clear();
    config.versions.push(rustls::ProtocolVersion::TLSv1_2);

    config
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
                     ->  Result<Option<RuntimeValue>, InterpreterError> {
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

fn wasm_load_module(module: Vec<u8>, name: &Option<String>) -> Option<String> {
    // Init a SgxWasmAction::LoadModule struct and send it to enclave
    let req = SgxWasmAction::LoadModule {
        name: name.as_ref().map(|x| x.clone()),
        module,
    };
    Some(serde_json::to_string(&req).unwrap())
}

fn wasm_run_action(action: &Action) -> Option<String> {
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
            Some(serde_json::to_string(&req).unwrap())
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
            Some(serde_json::to_string(&req).unwrap())
        },
    }
}

// Malform
fn wasm_try_load(module: &[u8]) -> Option<String> {
    // Make a SgxWasmAction::TryLoad structure and send it to sgx_enclave_wasm_invoke
    let req = SgxWasmAction::TryLoad {
        module : module.to_vec(),
    };

    Some(serde_json::to_string(&req).unwrap())
}

// Register
fn wasm_register(name: Option<String>, as_name: String) -> Option<String> {
    // Make a SgxWasmAction::Register structure and send it to sgx_enclave_wasm_invoke
    let req = SgxWasmAction::Register{
        name,
        as_name,
    };
    Some(serde_json::to_string(&req).unwrap())
}


fn main() {
    // let mut args: Vec<_> = env::args().collect();

    // let mut mode = 0;
    // args.remove(0);
    // while !args.is_empty() {
    //     match args.remove(0).as_ref() {
    //         "--upload" | "-u" => mode = 1,
    //         "--load" | "-l" => mode = 2,
    //         "--check" | "-c" => mode = 3,
    //         "--test" | "-t" => mode = 9,
    //         _ => {}
    //     }
    // }
    // if mode == 0 {
    //     panic!("Choose a mode: <--upload / --load / --check / --test>");
    // }

    println!("Starting wasmi-ra-client");
    println!("Connecting to {}", SERVERADDR);

    let client_config = make_config();
    let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
    
    let mut sess = rustls::ClientSession::new(&Arc::new(client_config), dns_name);
    let mut conn = TcpStream::connect(SERVERADDR).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut conn);

    // init connection
    tls.write_all("init".as_bytes()).unwrap();

    // authentication - root password:123   guest:any button
    println!("Input password: ");
    let mut passwd = String::new();
    std::io::stdin().read_line(&mut passwd).expect("Failed to read password");
    passwd = passwd.trim().to_string();
    tls.write_all(passwd.as_bytes()).unwrap();
    let mut plaintext = [0u8;128];
    let mut auth_res = String::new();
    match tls.read(&mut plaintext) {
        Ok(_) => {
            for ch in plaintext.iter() {
                if *ch != 0x00 {auth_res.push(*ch as char);}
            }
            println!("Authentication(root/guest): {}", &auth_res);
        }
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
            println!("EOF (tls)");
        }
        Err(e) => println!("Error in read_to_end: {:?}", e),
    }

    loop {
        // upload: client upload wabt json to enclave and enclave run commands
        // load: client input the wasm module name stored in romote server, server read the file and run commands
        // check: check the integrity of code in enclave by getting the report
        // test: test all wast files in test_input folder
        // quit: close connection
        println!("Input mode[upload/load/check/test/quit]: ");
        let mut mode = String::new();
        std::io::stdin().read_line(&mut mode).expect("Fail to read mode");
        mode = mode.trim().to_string();

        // send mode to server
        tls.write_all(&mode.as_bytes()).unwrap();
        let mut buf = [0u8; 128];
        let mut mode_res = String::new();
        match tls.read(&mut buf) {
            Ok(_) => {
                for ch in buf.iter() {
                    if *ch != 0x00 {mode_res.push(*ch as char);}
                }
                println!("{}", &mode_res);
            }
            Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                println!("EOF (tls)");
            }
            Err(e) => println!("Error in read_to_end: {:?}", e),
        }
        if mode_res.starts_with("[-]") {continue;}

        // owner upload wast (and run)
        if &mode == "upload" {
            loop {
                println!("Wast file name: ");
                let mut wast_file = String::new();
                std::io::stdin().read_line(&mut wast_file).expect("Failed to read line");
                wast_file = wast_file.trim().to_string();

                // if user enter "exit", change mode
                if wast_file == "exit" {
                    tls.write_all("exit".as_bytes()).unwrap();
                    let mut plaintext = [0u8;1024];
                    match tls.read(&mut plaintext) {
                        Ok(_) => {
                            println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
                        }
                        Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                            println!("EOF (tls)");
                        }
                        Err(e) => println!("Error in read_to_end: {:?}", e),
                    }
                    break;
                }

                wast_file = format!("./test_input/{}.wast", wast_file);
                println!("======================= testing {} =====================", &wast_file);

                // ScriptParser interface has changed. Need to feed it with wast content.
                let wast_content = match std::fs::read(&wast_file) {
                    Ok(content) => content,
                    Err(x) => {
                        println!("{}", x.to_string());
                        continue;
                    }
                };
                let path = std::path::Path::new(&wast_file);
                let fnme = path.file_name().unwrap().to_str().unwrap();
                let mut parser: ScriptParser = ScriptParser::from_source_and_name(&wast_content, fnme).unwrap();
                
                while let Some(Command{kind,line}) =
                    match parser.next() {
                                Ok(x) => x,
                                _ => {
                                    println!("Error parsing test input");
                                    return;
                                }
                    }
                {
                    println!("Line : {}", line);

                    // input file name
                    match kind {
                        CommandKind::Module { name, module, .. } => {
                            let script = match wasm_load_module(module.into_vec(), &name) {
                                Some(module) => module,
                                None => {
                                    println!("No module to load!");
                                    return;
                                }
                            };
                            // the same
                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            // the same

                            println!("load module - success at line {}", line)
                        },

                        CommandKind::AssertReturn { action, expected } => {
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertReturn wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            match result_obj {
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
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertReturnCanonicalNan | AssertReturnArithmeticNan wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            match result_obj {
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
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertExhaustion wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            match result_obj {
                                Ok(result) => panic!("Expected exhaustion, got result: {:?}", result),
                                Err(e) => println!("assert_exhaustion at line {} - success ({:?})", line, e),
                            }
                        },

                        CommandKind::AssertTrap { action, .. } => {
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertTrap wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            match result_obj {
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
                            let script = match wasm_try_load(&module.into_vec()) {
                                Some(res) => res,
                                None => {
                                    println!("AssertInvalid | AssertMalformed | AssertUnlinkable wasm_run_action fail");
                                    return;
                                }
                            };
                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);

                            match result_obj {
                                Ok(_) => panic!("Expected invalid module definition, got some module!"),
                                Err(e) => println!("assert_invalid at line {} - success ({:?})", line, e),
                            }
                        },

                        CommandKind::AssertUninstantiable { module, .. } => {
                            let script = match wasm_try_load(&module.into_vec()) {
                                Some(res) => res,
                                None => {
                                    println!("AssertUninstantiable wasm_run_action fail");
                                    return;
                                }
                            };
                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            
                            match result_obj {
                                Ok(_) => panic!("Expected error running start function at line {}", line),
                                Err(e) => println!("assert_uninstantiable - success ({:?})", e),
                            }
                        },

                        CommandKind::Register { name, as_name, .. } => {
                            let script = match wasm_register(name, as_name) {
                                Some(res) => res,
                                None => {
                                    println!("Register wasm_run_action fail");
                                    return;
                                }
                            };
                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);

                            match result_obj {
                                Ok(_) => {println!("register - success at line {}", line)},
                                Err(e) => panic!("No such module, at line {} - ({:?})", e, line),
                            }
                        },

                        CommandKind::PerformAction(action) => {
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertTrap wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            
                            match result_obj {
                                Ok(_) => {println!("invoke - success at line {}", line)},
                                Err(e) => panic!("Failed to invoke action at line {}: {:?}", line, e),
                            }
                        },
                    }
                }
            }
        } 

        // client run wasm module stored in remote device
        else if &mode == "load" {
            loop {
                println!("Load wasm file name: ");
                let mut msg = String::new();
                std::io::stdin().read_line(&mut msg).expect("Failed to read line");
                msg = msg.trim().to_string();

                // if user enter "exit", change mode
                if msg == "exit" {
                    tls.write_all("exit".as_bytes()).unwrap();
                    let mut plaintext = [0u8;1024];
                    match tls.read(&mut plaintext) {
                        Ok(_) => {
                            println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
                        }
                        Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                            println!("EOF (tls)");
                        }
                        Err(e) => println!("Error in read_to_end: {:?}", e),
                    }
                    break;
                }
            
                match tls.write_all(msg.as_bytes()) {
                    Ok(_) => {},
                    Err(x) => {
                        println!("[-] TLS write msg error: {}", x);
                    }
                };

                // receive response from server
                let mut plaintext = [0u8;4096];
                let mut res_str = String::new();
                match tls.read(&mut plaintext) {
                    Ok(_) => {
                        for ch in plaintext.iter() {
                            if *ch != 0x00 {res_str.push(*ch as char);}
                        }
                        println!("Server replied: {}", &res_str);
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                        println!("EOF (tls)");
                    }
                    Err(e) => println!("Error in read_to_end: {:?}", e),
                }
                if msg.starts_with("exit") || res_str.starts_with("[-]") {break;}
            }
        }
        
        // check the integrity of code in enclave by getting the report
        else if &mode == "check" {
            println!("check module");
        }

        // test all wast files in test_input folder
        else if mode == "test" {
            let wast_list = vec![
                "test_input/int_exprs.wast",
                "test_input/conversions.wast",
                "test_input/nop.wast",
                "test_input/float_memory.wast",
                "test_input/call.wast",
                "test_input/memory.wast",
                "test_input/utf8-import-module.wast",
                "test_input/labels.wast",
                "test_input/align.wast",
                "test_input/memory_trap.wast",
                "test_input/br.wast",
                "test_input/globals.wast",
                "test_input/comments.wast",
                "test_input/get_local.wast",
                "test_input/float_literals.wast",
                "test_input/elem.wast",
                "test_input/f64_bitwise.wast",
                "test_input/custom_section.wast",
                "test_input/inline-module.wast",
                "test_input/call_indirect.wast",
                "test_input/break-drop.wast",
                "test_input/unreached-invalid.wast",
                "test_input/utf8-import-field.wast",
                "test_input/loop.wast",
                "test_input/br_if.wast",
                "test_input/select.wast",
                "test_input/unwind.wast",
                "test_input/binary.wast",
                "test_input/tee_local.wast",
                "test_input/custom.wast",
                "test_input/start.wast",
                "test_input/float_misc.wast",
                "test_input/stack.wast",
                "test_input/f32_cmp.wast",
                "test_input/i64.wast",
                "test_input/const.wast",
                "test_input/unreachable.wast",
                "test_input/switch.wast",
                "test_input/resizing.wast",
                "test_input/i32.wast",
                "test_input/f64_cmp.wast",
                "test_input/int_literals.wast",
                "test_input/br_table.wast",
                "test_input/traps.wast",
                "test_input/return.wast",
                "test_input/f64.wast",
                "test_input/type.wast",
                "test_input/fac.wast",
                "test_input/set_local.wast",
                "test_input/func.wast",
                "test_input/f32.wast",
                "test_input/f32_bitwise.wast",
                "test_input/float_exprs.wast",
                "test_input/linking.wast",
                "test_input/skip-stack-guard-page.wast",
                // "test_input/names.wast",
                "test_input/address.wast",
                "test_input/memory_redundancy.wast",
                "test_input/block.wast",
                "test_input/utf8-invalid-encoding.wast",
                "test_input/left-to-right.wast",
                "test_input/forward.wast",
                "test_input/typecheck.wast",
                "test_input/store_retval.wast",
                "test_input/imports.wast",
                "test_input/exports.wast",
                "test_input/endianness.wast",
                "test_input/func_ptrs.wast",
                "test_input/if.wast",
                "test_input/token.wast",
                "test_input/data.wast",
                "test_input/utf8-custom-section-id.wast",
            ];
            for wfile in wast_list {
                println!("======================= testing {} =====================", wfile);
                let wast_content = match std::fs::read(&wfile) {
                    Ok(content) => content,
                    Err(x) => {
                        println!("{}", x.to_string());
                        return;
                    }
                };
                let path = std::path::Path::new(&wfile);
                let fnme = path.file_name().unwrap().to_str().unwrap();
                let mut parser: ScriptParser = ScriptParser::from_source_and_name(&wast_content, fnme).unwrap();
                
                while let Some(Command{kind,line}) =
                    match parser.next() {
                                Ok(x) => x,
                                _ => {
                                    println!("Error parsing test input");
                                    return;
                                }
                    }
                {
                    println!("Line : {}", line);

                    match kind {
                        CommandKind::Module { name, module, .. } => {
                            let script = match wasm_load_module(module.into_vec(), &name) {
                                Some(module) => module,
                                None => {
                                    println!("No module to load!");
                                    return;
                                }
                            };
                            // the same
                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            // the same

                            println!("load module - success at line {}", line)
                        },

                        CommandKind::AssertReturn { action, expected } => {
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertReturn wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            match result_obj {
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
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertReturnCanonicalNan | AssertReturnArithmeticNan wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            match result_obj {
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
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertExhaustion wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            match result_obj {
                                Ok(result) => panic!("Expected exhaustion, got result: {:?}", result),
                                Err(e) => println!("assert_exhaustion at line {} - success ({:?})", line, e),
                            }
                        },

                        CommandKind::AssertTrap { action, .. } => {
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertTrap wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            match result_obj {
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
                            let script = match wasm_try_load(&module.into_vec()) {
                                Some(res) => res,
                                None => {
                                    println!("AssertInvalid | AssertMalformed | AssertUnlinkable wasm_run_action fail");
                                    return;
                                }
                            };
                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);

                            match result_obj {
                                Ok(_) => panic!("Expected invalid module definition, got some module!"),
                                Err(e) => println!("assert_invalid at line {} - success ({:?})", line, e),
                            }
                        },

                        CommandKind::AssertUninstantiable { module, .. } => {
                            let script = match wasm_try_load(&module.into_vec()) {
                                Some(res) => res,
                                None => {
                                    println!("AssertUninstantiable wasm_run_action fail");
                                    return;
                                }
                            };
                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            
                            match result_obj {
                                Ok(_) => panic!("Expected error running start function at line {}", line),
                                Err(e) => println!("assert_uninstantiable - success ({:?})", e),
                            }
                        },

                        CommandKind::Register { name, as_name, .. } => {
                            let script = match wasm_register(name, as_name) {
                                Some(res) => res,
                                None => {
                                    println!("Register wasm_run_action fail");
                                    return;
                                }
                            };
                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);

                            match result_obj {
                                Ok(_) => {println!("register - success at line {}", line)},
                                Err(e) => panic!("No such module, at line {} - ({:?})", e, line),
                            }
                        },

                        CommandKind::PerformAction(action) => {
                            let script = match wasm_run_action(&action) {
                                Some(res) => res,
                                None => {
                                    println!("AssertTrap wasm_run_action fail");
                                    return;
                                }
                            };

                            println!("script to enclave: {}", script);
                            match tls.write_all(script.as_bytes()) {
                                Ok(_) => {},
                                Err(x) => {
                                    println!("[-] Write Module Err: {}", x);
                                    break;
                                }
                            };
                            let mut plaintext = [0u8;4096];
                            let mut res_str = String::new();
                            match tls.read(&mut plaintext) {
                                Ok(_) => {
                                    for ch in plaintext.iter() {
                                        if *ch != 0x00 {res_str.push(*ch as char);}
                                    }
                                    println!("Server replied: {}", &res_str);
                                }
                                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                                    println!("EOF (tls)");
                                }
                                Err(e) => println!("Error in read_to_end: {:?}", e),
                            }
                            
                            let result: Result<Option<BoundaryValue>, InterpreterError> = serde_json::from_str(&res_str).unwrap();
                            // not consider error handling(not use in-enclave function return value sgx_status_t)
                            let result_obj: Result<Option<RuntimeValue>, InterpreterError> = answer_convert(result);
                            
                            match result_obj {
                                Ok(_) => {println!("invoke - success at line {}", line)},
                                Err(e) => panic!("Failed to invoke action at line {}: {:?}", line, e),
                            }
                        },
                    }
                }
            }

            println!("[+] Pass all tests!");

            match tls.write_all("exit".as_bytes()) {
                Ok(_) => {},
                Err(x) => {
                    println!("[-] TLS write msg error: {}", x);
                }
            };
        
            let mut plaintext = [0u8;1024];
            match tls.read(&mut plaintext) {
                Ok(_) => {
                    println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
                }
                Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                    println!("EOF (tls)");
                }
                Err(e) => println!("Error in read_to_end: {:?}", e),
            }
        }

        // close connection
        else if &mode == "quit" {
            println!("Bye");
            break;
        }

        // wrong mode
        else {
            println!("Mode not exist.");
        }
    }
}
