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

use sgx_types::*;
use sgx_urts::SgxEnclave;
use crypto::*;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern {
    fn calc_sha256(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        input_str: *const u8,
        some_len: usize,
        hash: &mut [u8;32]) -> sgx_status_t;
    fn rsa_verify(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        hash: &[u8;32], 
        pubkey: &sgx_rsa3072_public_key_t, 
        signature: &sgx_rsa3072_signature_t) -> sgx_status_t;
    fn upload_pubkey(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        pubkey: &sgx_rsa3072_public_key_t) -> sgx_status_t;
    fn rsa_verify_without_key(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        hash: &[u8;32],
        signature: &sgx_rsa3072_signature_t) -> sgx_status_t;

    fn aes_gcm_128_encrypt(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        key: &[u8;16],
        plaintext: *const u8,
        text_len: usize,
        iv: &[u8;12],
        ciphertext: *mut u8,
        mac: &mut [u8;16]) -> sgx_status_t;
    fn aes_gcm_128_decrypt(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        key: &[u8;16],
        ciphertext: *const u8,
        text_len: usize,
        iv: &[u8;12],
        mac: &[u8;16],
        plaintext: *mut u8) -> sgx_status_t;
    fn aes_cmac(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        text: *const u8,
        text_len: usize,
        key: &[u8;16],
        cmac: &mut [u8;16]) -> sgx_status_t;
    fn rsa_key(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        text: * const u8, 
        text_len: usize) -> sgx_status_t;
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

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!\n", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };

    let eid = enclave.geteid();

    let wast_file = "../test_input/forward.wast";
    let wast_content : String = std::fs::read_to_string(wast_file).unwrap();
    let mut hash = [0_u8; 32];
    // println!("{:?}", wast_content);
    if sha_256(eid, wast_content, &mut hash) == -1 {
        println!("[-] sha_256 function fail!");
        enclave.destroy();
        println!("\n[+] Destroy Enclave {}", eid);
        return;
    }
    print!("[+] SHA256 result is ");
    for i in 0..32 {
        print!("{:02x}", hash[i]);
    }
    println!("\n\n");

    // create rsa3072 public key and private key
    let mut pubkey = sgx_rsa3072_public_key_t {
        modulus: [0_u8; SGX_RSA3072_KEY_SIZE],
        exponent: [0_u8; SGX_RSA3072_PUB_EXP_SIZE],
    };
    let mut privkey = sgx_rsa3072_key_t {
        modulus: [0_u8; SGX_RSA3072_KEY_SIZE],
        d: [0_u8; SGX_RSA3072_PRI_EXP_SIZE],
        e: [0_u8; SGX_RSA3072_PUB_EXP_SIZE],
    };
    if generate_rsa_keypair(&mut pubkey, &mut privkey) == -1 {
        println!("[-] generate_rsa_keypair function fail!");
        enclave.destroy();
        println!("\n[+] Destroy Enclave {}", eid);
        return;
    } else {
        println!("[+] create rsa key pair success!");
    }
    
    // sign the sha256 hash by rsa3072 private key
    let signature = match rsgx_rsa3072_sign_slice(&hash, &privkey) {
        Ok(sig) => {sig},
        Err(err) => {
            println!("[-] rsgx_rsa3072_sign_slice function fail: {}", err.as_str());
            enclave.destroy();
            println!("\n[+] Destroy Enclave {}", eid);
            return;
        }
    };
    // println!("signature: {:?}", signature.signature);

    // upload rsa3072 public key to enclave
    let mut retval = sgx_status_t::SGX_SUCCESS;
    println!("\n+++++++++++ Enter Enclave +++++++++++");
    let result = unsafe{
        upload_pubkey(eid, &mut retval, &pubkey)
    };
    println!("----------- Leave Enclave -----------\n");
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] upload_pubkey function success!");
        },
        _ => {
            println!("[-] upload_pubkey function fail: {}", result.as_str());
        }
    };
    
    // enter enclave to verify the signature
    println!("\n+++++++++++ Enter Enclave +++++++++++");
    let result = unsafe{
        rsa_verify_without_key(eid, &mut retval, &hash, &signature)
        // rsa_verify(eid, &mut retval, &hash, &pubkey, &signature)
    };
    println!("----------- Leave Enclave -----------\n");
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("[+] signature verified success!");
        },
        sgx_status_t::SGX_ERROR_UNEXPECTED => {
            println!("[-] signature verified fail!");
        },
        _ => {
            println!("[-] rsa_verify function fail: {}", result.as_str());
        }
    };




    // let input_str = "abc".to_string();
    // if sha_256_test(enclave.geteid(), input_str) == -1 {
    //     println!("[-] sha_256 fail!");
    // }
    // if aes_gcm_128(enclave.geteid()) == -1 {
    //     println!("[-] aes_gcm_128 fail!");
    // }
    // if aes_cmac_u(enclave.geteid()) == -1 {
    //     println!("[-] aes_cmac fail!");
    // }
    // if rsa_test(enclave.geteid()) == -1 {
    //     println!("[-] rsa fail!");
    // }
    
    enclave.destroy();
    println!("\n[+] Destroy Enclave {}", eid);
}



fn sha_256(eid: sgx_enclave_id_t, input: String, hash: &mut [u8;32]) -> i32 {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let len = input.len();

    println!("\n+++++++++++ Enter Enclave +++++++++++");
    let result = unsafe {
        calc_sha256(
            eid, 
            &mut retval,
            input.as_ptr() as *const u8,
            len,
            hash)
    };
    println!("----------- Leave Enclave -----------\n");

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return -1;
        }
    }
    
    println!("[+] calc_sha256 success ...");
    0
}

fn generate_rsa_keypair(pubkey: &mut sgx_rsa3072_public_key_t, privkey: &mut sgx_rsa3072_key_t) -> i32 {
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

    pubkey.modulus = n;
    pubkey.exponent = e;

    privkey.modulus = n;
    privkey.e = e;
    privkey.d = d;
    0
}





fn sha_256_test(eid: u64, input_str: String) -> i32 {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let len = input_str.len();
    let mut hash = [0_u8; 32];
    println!("[+] sha256 input string is {}", input_str);
    println!("[+] Expected SHA256 hash: {}",
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");


    println!("*********** Enter Enclave");
    let result = unsafe {
        calc_sha256(
            eid, 
            &mut retval,
            input_str.as_ptr() as *const u8,
            len,
            &mut hash)
    };
    println!("*********** Leave Enclave");
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return -1;
        }
    }

    print!("[+] SHA256 result is ");
    for i in 0..32 {
        print!("{:02x}", hash[i]);
    }
    println!("\n[+] calc_sha256 success ...\n\n");
    0
}

fn aes_gcm_128(eid: u64) -> i32 {
    println!("[+] Starting aes-gcm-128 encrypt calculation");
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let key = [0_u8; 16];
    let plaintext = [0_u8; 16];
    let iv = [0_u8; 12];
    let ciphertext = [0_u8; 16];
    let mut mac = [0_u8; 16];
    println!("[+] aes-gcm-128 args prepared!");
    println!("[+] aes-gcm-128 expected ciphertext: {}",
           "0388dace60b6a392f328c2b971b2fe78");

    // encrypt
    println!("*********** Encrypt - Enter Enclave");
    let result = unsafe {
        aes_gcm_128_encrypt(
            eid, 
            &mut retval,
            &key,
            plaintext.as_ptr() as *const u8,
            16,
            &iv,
            ciphertext.as_ptr() as *mut u8,
            &mut mac)
    };
    println!("*********** Encrypt - Leave Enclave");
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return -1;
        }
    }

    print!("[+] aes-gcm-128 ciphertext is: ");
    for i in 0..16 {
        print!("{:02x}", ciphertext[i]);
    }
    print!("\n[+] aes-gcm-128 result mac is: ");
    for i in 0..16 {
        print!("{:02x}", plaintext[i]);
    }
    println!();

    // decrypt
    let decrypted_text = [0_u8; 16];
    println!("*********** Decrypt - Enter Enclave");
    let result = unsafe {
        aes_gcm_128_decrypt(
            eid, 
            &mut retval,
            &key,
            ciphertext.as_ptr() as *const u8,
            16,
            &iv,
            &mac,
            decrypted_text.as_ptr() as *mut u8)
    };
    println!("*********** Decrypt - Leave Enclave");
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return -1;
        }
    }

    print!("[+] aes-gcm-128 decrypted plaintext is: ");
    for i in 0..16 {
        print!("{:02x}", decrypted_text[i]);
    }
    println!("\n[+] aes-gcm-128 decrypt complete\n\n");
    0
}

fn aes_cmac_u(eid: u64) -> i32 {
    println!("[+] Starting aes-cmac test");
    println!("[+] aes-cmac expected digest: {}",
           "51f0bebf7e3b9d92fc49741779363cfe");
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let cmac_key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ];
    let cmac_msg: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    ];
    let mut cmac_result: [u8; 16] = [0; 16];

    println!("*********** Enter Enclave");
    let result = unsafe {
        aes_cmac(
            eid, 
            &mut retval,
            cmac_msg.as_ptr() as *const u8,
            cmac_msg.len(),
            &cmac_key,
            &mut cmac_result)
    };
    println!("*********** Leave Enclave");
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return -1;
        }
    }

    print!("[+] aes-cmac result is: ");
    for i in 0..16 {
        print!("{:02x}", cmac_result[i]);
    }
    println!("\n\n");
    0
}

fn rsa_test(eid: u64) -> i32 {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let rsa_msg: [u8; 128] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    ];

    println!("*********** Enter Enclave ***********");
    let result = unsafe {
        rsa_key(
            eid, 
            &mut retval,
            rsa_msg.as_ptr() as *const u8, 
            rsa_msg.len())
    };
    println!("*********** Leave Enclave ***********");
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return -1;
        }
    }
    println!("rsa_key success.");
    0
}