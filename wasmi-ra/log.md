client:

```bash
Starting wasmi-ra-client
Connecting to localhost:3443
--received-server cert: [Certificate(b"0\x82\rI0\x82\x0c\xef\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0\x1e\x17\r210515123551Z\x17\r210813123551Z0\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\0\x049\xcd\xbd\x87\x9a-J\xd5Z\xea\xec\xdcV\x7f\xd9G\xd5\xbd\x1dl6\xfe\x0e\xafh\x93\xbb\xf8\xb8\xe6<\xed\xfd'-\xe1\xdd\x91\x81uz\x1cI\x92'\xb0j\xa1d|\x90A\x1d\xd1\xfa\xab\xad\xcf\x13\x95\x12u6\x92\xa3\x82\x0c40\x82\x0c00\x82\x0c,\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x82\x0c\x1d{\"id\":\"7057584773508210092544248488841107980\",\"timestamp\":\"2021-05-15T12:35:51.548684\",\"version\":3,\"epidPseudonym\":\"mMqrHF1zVv/25u2Yo6kds/4NBT7rGSfBAF3PwwfzyDNiqG5Xnv1eA3/PDQ1bVpIraEtZqAFsMvtjoLfciLKhGY+6yBwyite6aHFY/XbS0jNs1Z87bCSjHmRM6MD2izxQYDjIIH8BF6wsolOacmwW9CCcRTvxWtb/+woLKRR7aEo=\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"150200650400010000111102040101070000000000000000000B00000B000000020000000000000AC9731F92F1AF6AE813563D02CF1E50A11D3FD42A58E9994C0796CA47B17D5E6EDE9402460F253E59A3074CDA60201E8EA55EEBDABC46F2EFC4440FA24E0A03A405\",\"isvEnclaveQuoteBody\":\"AgABAMkKAAALAAoAAAAAABjXJMzAoX9P70dp7BBkzUcAAAAAAAAAAAAAAAAAAAAABRH/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAPtdnw4exduHgzNePZ+wfk8oeuKnDaFDDIQUWUvw74XjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5zb2Hmi1K1Vrq7NxWf9lH1b0dbDb+Dq9ok7v4uOY87f0nLeHdkYF1ehxJkiewaqFkfJBBHdH6q63PE5USdTaS\"}|kVVzi8LsyVyJ4Eaiwh8gEtLSpR+P+1bfKCaZyq20bRovfAL2zFDtyeZRuhFt6TpWizMD2ZRSDS3dBWITgIxWW4nVI98haaYWT5D+wbimkTCPz40MG1ebxW7NO7NBfouNdP3oW3VbYfic7jbO8VCedbEdV33vnZcTAJVRzM6jVphVTyHq/gjHJzUkIPaPiddGzLuKyhcdK5MsjUeAMw8HDI3zJrGNYRQl581pRdRAwiDzG9TM/ggzgRGlvGKHw2J+Z9s+Fx6Gt34c/vbwdPTRk8Cob+5gsQsW1oCwMJlKqktD3yDmYz+68HgW1+VI2izkr2nwPt77zJbuhPkZQstgag==|MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\00E\x02!\0\x8cU\"\xa2\x15\xcf\x18#\xd8z-\xc5\xaa\xaa\xca\xc0\xb0\xa0\xf5\x87\xa3=\x9e*\r?\x1co\xbch]\x19\x02 {{\x97^\x8b\x9a\x0cY\xbf\xfbFV\xfe\x126\x99\xddJs\xcfF\xda=\rL\xd8\xf9D\xc2q\xdd\xc7")]
Cert is good
Signature good
Time diff = 0
isvEnclaveQuoteStatus = GROUP_OUT_OF_DATE
platform_info_blob { sgx_epid_group_flags: 4, sgx_tcb_evaluation_flags: 256, pse_evaluation_flags: 0, latest_equivalent_tcb_psvn: [17, 17, 2, 4, 1, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0], latest_pse_isvsvn: [0, 11], latest_psda_svn: [0, 0, 0, 2], xeid: 0, gid: 3372875776, signature: sgx_ec256_signature_t { gx: [115, 31, 146, 241, 175, 106, 232, 19, 86, 61, 2, 207, 30, 80, 161, 29, 63, 212, 42, 88, 233, 153, 76, 7, 150, 202, 71, 177, 125, 94, 110, 222], gy: [148, 2, 70, 15, 37, 62, 89, 163, 7, 76, 218, 96, 32, 30, 142, 165, 94, 235, 218, 188, 70, 242, 239, 196, 68, 15, 162, 78, 10, 3, 164, 5] } }
Quote = [2, 0, 1, 0, 201, 10, 0, 0, 11, 0, 10, 0, 0, 0, 0, 0, 24, 215, 36, 204, 192, 161, 127, 79, 239, 71, 105, 236, 16, 100, 205, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 17, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 251, 93, 159, 14, 30, 197, 219, 135, 131, 51, 94, 61, 159, 176, 126, 79, 40, 122, 226, 167, 13, 161, 67, 12, 132, 20, 89, 75, 240, 239, 133, 227, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, 205, 189, 135, 154, 45, 74, 213, 90, 234, 236, 220, 86, 127, 217, 71, 213, 189, 29, 108, 54, 254, 14, 175, 104, 147, 187, 248, 184, 230, 60, 237, 253, 39, 45, 225, 221, 145, 129, 117, 122, 28, 73, 146, 39, 176, 106, 161, 100, 124, 144, 65, 29, 209, 250, 171, 173, 207, 19, 149, 18, 117, 54, 146]
sgx quote version = 2
sgx quote signature type = 1
sgx quote report_data = 39cdbd879a2d4ad55aeaecdc567fd947d5bd1d6c36fe0eaf6893bbf8b8e63cedfd272de1dd9181757a1c499227b06aa1647c90411dd1faabadcf139512753692
sgx quote mr_enclave = fb5d9f0e1ec5db8783335e3d9fb07e4f287ae2a70da1430c8414594bf0ef85e3
sgx quote mr_signer = 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
Anticipated public key = 39cdbd879a2d4ad55aeaecdc567fd947d5bd1d6c36fe0eaf6893bbf8b8e63cedfd272de1dd9181757a1c499227b06aa1647c90411dd1faabadcf139512753692
ue RA done!
```





server:

```bash
[+] Init Enclave Successful 2!
[+] Sgxwasm Spec Driver Engine Init Success!
Running as server...
new client from 127.0.0.1:37992


Entering ocall_sgx_init_quote
eg = [201, 10, 0, 0]


get_sigrl_from_intel fd = 7
-- req
GET /sgx/dev/attestation/v3/sigrl/00000ac9 HTTP/1.1
HOST: api.trustedservices.intel.com
Ocp-Apim-Subscription-Key: a1790cf4c3a645ea9d734cf6cddce5f3
Connection: Close
-- req
write complete
read_to_end complete
-- resp_string
HTTP/1.1 200 OK
Content-Length: 0
Request-ID: 0132406de697419cb0117aa6fa78a504
Date: Sat, 15 May 2021 12:35:49 GMT
Connection: close
-- resp_string



parse_response_sigrl
parse result Ok(Complete(140))
parse responseResponse { version: Some(1), code: Some(200), reason: Some("OK"), headers: [Header { name: "Content-Length", value: [48] }, Header { name: "Request-ID", value: [48, 49, 51, 50, 52, 48, 54, 100, 101, 54, 57, 55, 52, 49, 57, 99, 98, 48, 49, 49, 55, 97, 97, 54, 102, 97, 55, 56, 97, 53, 48, 52] }, Header { name: "Date", value: [83, 97, 116, 44, 32, 49, 53, 32, 77, 97, 121, 32, 50, 48, 50, 49, 32, 49, 50, 58, 51, 53, 58, 52, 57, 32, 71, 77, 84] }, Header { name: "Connection", value: [99, 108, 111, 115, 101] }] }
OK Operation Successful


Report creation => success [131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158]



rand finished



Entering ocall_get_quote
quote size = 1116
sgx_calc_quote_size returned SGX_SUCCESS.



-- ??????qe_report
rsgx_verify_report passed!
qe_report check passed
rhs hash = 7E511F30FD61FEA8F4C3B1A565948A8DC6C706D0A3F72195031DF8DAD8909E18
report hs= 7E511F30FD61FEA8F4C3B1A565948A8DC6C706D0A3F72195031DF8DAD8909E18



get_report_from_intel fd = 7
POST /sgx/dev/attestation/v3/report HTTP/1.1
HOST: api.trustedservices.intel.com
Ocp-Apim-Subscription-Key:a1790cf4c3a645ea9d734cf6cddce5f3
Content-Length:1512
Content-Type: application/json
Connection: close

{"isvEnclaveQuote":"AgABAMkKAAALAAoAAAAAABjXJMzAoX9P70dp7BBkzUcAAAAAAAAAAAAAAAAAAAAABRH/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAPtdnw4exduHgzNePZ+wfk8oeuKnDaFDDIQUWUvw74XjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5zb2Hmi1K1Vrq7NxWf9lH1b0dbDb+Dq9ok7v4uOY87f0nLeHdkYF1ehxJkiewaqFkfJBBHdH6q63PE5USdTaSqAIAAHmM3b3fCCg/8rtNuQIa9yXhkMFDhv3knSVk6eWoQFUUnyt5BNy3e8gc5jwPgCU0am9fWEpq/tQBAHO8DYD304YDxiF0Nv9U90AJq+sUtKFOzdx2Fj79kqpkkbKa2/m3Veg5eHkgkPalaD/UPEn/U8pqe2f6lD0wPTeXzUu7nBGJHMdbzrEmiI7aerKc4d9zLujK0PW5khOimTzgglxXehV5i+eLRw8gFfYFfuw60NWvdqmfNsfSxxa5LJHlER2jkzRKP3VR6vmkXx/3x/A64JpeKboQNznqcXEu/MTwtfDM5bY1+57dxMliOjqb/aY/YD2O12ExRAZDb8ETdixAZUsCTpi7VB00dp8ykWb2itRx9Fj+vslEscKLMeKWHWePIZ+r8wVWnkFVeD+rsGgBAABNrTk9Fx+sMnHyuXu8ZRXAPf58lGkWpEMAk4LBpKzLlSNyZe2YWSqznaBfmOIo1SEkLwdG4LdSyO6tsoCj1We+6Glsqttbv+6ILWZogkKggDDh5dHGhUdHQp5HeOQKH7XINiIr/Tj3nryOGPabozpwFIIeF3PSOg5l2CxWsnjWAY7Wp/5uNV0dYrocgNOPjhebWA3zyrscqbD58VWt3I8s/KHxikYuh7uaXlriRUEN4uKGk/TP9PO6JFR2Cv/TiYSWdmWyuvLvGspiFray+2N2Idq/r5MbAuexx/EfUU4jK4TFFpMSHSa+UmFnKct4fwNlFlNyyygekHVIfmZu2VYPUCwWtouMEv61isTsnjrTiHDzVmNHVYmGZeZOkyn4jqagHMd4DFUXvI6Ty+MVnJfOM6VABmvBllwFd56LSai/8v7uVttPJdKrxNYU2ag0/yJJnp3DLYK8pzZhArYBUe9o7jgaEe3T/LUGVY3UvPHLijSUt+yqTlzD"}

write complete
read_to_end complete
resp_string = HTTP/1.1 200 OK
Content-Length: 1167
Content-Type: application/json
Request-ID: e2fbd56ae1854312b15cffe08b6139da
Advisory-URL: https://security-center.intel.com
Advisory-IDs: INTEL-SA-00381,INTEL-SA-00389,INTEL-SA-00320,INTEL-SA-00329,INTEL-SA-00220,INTEL-SA-00270,INTEL-SA-00293,INTEL-SA-00233,INTEL-SA-00203,INTEL-SA-00106,INTEL-SA-00115,INTEL-SA-00135,INTEL-SA-00088
X-IASReport-Signature: kVVzi8LsyVyJ4Eaiwh8gEtLSpR+P+1bfKCaZyq20bRovfAL2zFDtyeZRuhFt6TpWizMD2ZRSDS3dBWITgIxWW4nVI98haaYWT5D+wbimkTCPz40MG1ebxW7NO7NBfouNdP3oW3VbYfic7jbO8VCedbEdV33vnZcTAJVRzM6jVphVTyHq/gjHJzUkIPaPiddGzLuKyhcdK5MsjUeAMw8HDI3zJrGNYRQl581pRdRAwiDzG9TM/ggzgRGlvGKHw2J+Z9s+Fx6Gt34c/vbwdPTRk8Cob+5gsQsW1oCwMJlKqktD3yDmYz+68HgW1+VI2izkr2nwPt77zJbuhPkZQstgag==
X-IASReport-Signing-Certificate: -----BEGIN%20CERTIFICATE-----%0AMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV%0ABAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV%0ABAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0%0AYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw%0AMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh%0AbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk%0ASW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG%0A9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA%2Bt%0AbeCTUR106AL1ENcWA4FX3K%2BE9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId%0Acv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv%0ALUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV%2BW9tOhA%0AImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt%2B%2BqO/6%2BKAXJuKwZqjRlEtSEz8%0AgZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh%0AMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN%2Bs1fDuHAVE8MA4GA1UdDwEB/wQEAwIG%0AwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk%0Ac2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl%0AcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r%0ARq%2BZKE%2B7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9%0AlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv%0AWLrtXXfFBSSPD4Afn7%2B3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd%0AZseZCcaZZZn65tdqee8UXZlDvx0%2BNdO0LR%2B5pFy%2BjuM0wWbu59MvzcmTXbjsi7HY%0A6zd53Yq5K244fwFHRQ8eOB0IWB%2B4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7%0A2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN%2BKwPbpA39%2BxOsStjhP9N1Y1a2%0AtQAVo%2ByVgLgV2Hws73Fc0o3wC78qPEA%2Bv2aRs/Be3ZFDgDyghc/1fgU%2B7C%2BP6kbq%0Ad4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV%0ABAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV%0ABAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0%0AYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy%0AMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL%0AU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD%0ADCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G%0ACSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR%2BtXc8u1EtJzLA10Feu1Wg%2Bp7e%0ALmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh%0ArgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT%0AL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe%0ANpEJUmg4ktal4qgIAxk%2BQHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ%0AbyinkNndn%2BBgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H%0AafuVeLHcDsRp6hol4P%2BZFIhu8mmbI1u0hH3W/0C2BuYXB5PC%2B5izFFh/nP0lc2Lf%0A6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM%0ARoOaX4AS%2B909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX%0AMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50%0AL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW%0ABBR4Q3t2pn680K9%2BQjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9%2BQjfr%0ANXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq%0AhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir%0AIEqucRiJSSx%2BHjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi%2BripMtPZ%0AsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi%0AzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra%0AUd4APK0wZTGtfPXU7w%2BIBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA%0A152Sq049ESDz%2B1rRGc2NVEqh1KaGXmtXvqxXcTB%2BLjy5Bw2ke0v8iGngFBPqCTVB%0A3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5%2BxmBc388v9Dm21HGfcC8O%0ADD%2BgT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R%2BmJTLwPXVMrv%0ADaVzWh5aiEx%2BidkSGMnX%0A-----END%20CERTIFICATE-----%0A
Date: Sat, 15 May 2021 12:35:51 GMT
Connection: close

{"id":"7057584773508210092544248488841107980","timestamp":"2021-05-15T12:35:51.548684","version":3,"epidPseudonym":"mMqrHF1zVv/25u2Yo6kds/4NBT7rGSfBAF3PwwfzyDNiqG5Xnv1eA3/PDQ1bVpIraEtZqAFsMvtjoLfciLKhGY+6yBwyite6aHFY/XbS0jNs1Z87bCSjHmRM6MD2izxQYDjIIH8BF6wsolOacmwW9CCcRTvxWtb/+woLKRR7aEo=","isvEnclaveQuoteStatus":"GROUP_OUT_OF_DATE","platformInfoBlob":"150200650400010000111102040101070000000000000000000B00000B000000020000000000000AC9731F92F1AF6AE813563D02CF1E50A11D3FD42A58E9994C0796CA47B17D5E6EDE9402460F253E59A3074CDA60201E8EA55EEBDABC46F2EFC4440FA24E0A03A405","isvEnclaveQuoteBody":"AgABAMkKAAALAAoAAAAAABjXJMzAoX9P70dp7BBkzUcAAAAAAAAAAAAAAAAAAAAABRH/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAPtdnw4exduHgzNePZ+wfk8oeuKnDaFDDIQUWUvw74XjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5zb2Hmi1K1Vrq7NxWf9lH1b0dbDb+Dq9ok7v4uOY87f0nLeHdkYF1ehxJkiewaqFkfJBBHdH6q63PE5USdTaS"}



parse_response_attn_report
parse result Ok(Complete(4604))
OK Operation Successful
content length = 1167
Attestation report: {"id":"7057584773508210092544248488841107980","timestamp":"2021-05-15T12:35:51.548684","version":3,"epidPseudonym":"mMqrHF1zVv/25u2Yo6kds/4NBT7rGSfBAF3PwwfzyDNiqG5Xnv1eA3/PDQ1bVpIraEtZqAFsMvtjoLfciLKhGY+6yBwyite6aHFY/XbS0jNs1Z87bCSjHmRM6MD2izxQYDjIIH8BF6wsolOacmwW9CCcRTvxWtb/+woLKRR7aEo=","isvEnclaveQuoteStatus":"GROUP_OUT_OF_DATE","platformInfoBlob":"150200650400010000111102040101070000000000000000000B00000B000000020000000000000AC9731F92F1AF6AE813563D02CF1E50A11D3FD42A58E9994C0796CA47B17D5E6EDE9402460F253E59A3074CDA60201E8EA55EEBDABC46F2EFC4440FA24E0A03A405","isvEnclaveQuoteBody":"AgABAMkKAAALAAoAAAAAABjXJMzAoX9P70dp7BBkzUcAAAAAAAAAAAAAAAAAAAAABRH/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAPtdnw4exduHgzNePZ+wfk8oeuKnDaFDDIQUWUvw74XjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5zb2Hmi1K1Vrq7NxWf9lH1b0dbDb+Dq9ok7v4uOY87f0nLeHdkYF1ehxJkiewaqFkfJBBHdH6q63PE5USdTaS"}
```







quote:

```json
{
"id":"7057584773508210092544248488841107980",
"timestamp":"2021-05-15T12:35:51.548684",
"version":3,
"epidPseudonym":"mMqrHF1zVv/25u2Yo6kds/4NBT7rGSfBAF3PwwfzyDNiqG5Xnv1eA3/PDQ1bVpIraEtZqAFsMvtjoLfciLKhGY+6yBwyite6aHFY/XbS0jNs1Z87bCSjHmRM6MD2izxQYDjIIH8BF6wsolOacmwW9CCcRTvxWtb/+woLKRR7aEo=",
"isvEnclaveQuoteStatus":"GROUP_OUT_OF_DATE",
"platformInfoBlob":"150200650400010000111102040101070000000000000000000B00000B000000020000000000000AC9731F92F1AF6AE813563D02CF1E50A11D3FD42A58E9994C0796CA47B17D5E6EDE9402460F253E59A3074CDA60201E8EA55EEBDABC46F2EFC4440FA24E0A03A405",
"isvEnclaveQuoteBody":"AgABAMkKAAALAAoAAAAAABjXJMzAoX9P70dp7BBkzUcAAAAAAAAAAAAAAAAAAAAABRH/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAPtdnw4exduHgzNePZ+wfk8oeuKnDaFDDIQUWUvw74XjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5zb2Hmi1K1Vrq7NxWf9lH1b0dbDb+Dq9ok7v4uOY87f0nLeHdkYF1ehxJkiewaqFkfJBBHdH6q63PE5USdTaS"
}
```



validate quote:

```json
Cert is good
Signature good
Time diff = 0
isvEnclaveQuoteStatus = GROUP_OUT_OF_DATE
platform_info_blob { 
    sgx_epid_group_flags: 4, 
    sgx_tcb_evaluation_flags: 256, 
    pse_evaluation_flags: 0, 
    latest_equivalent_tcb_psvn: [17, 17, 2, 4, 1, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0], 
    latest_pse_isvsvn: [0, 11], 
    latest_psda_svn: [0, 0, 0, 2], 
    xeid: 0, gid: 3372875776, 
    signature: sgx_ec256_signature_t { 
    	gx: [115, 31, 146, 241, 175, 106, 232, 19, 86, 61, 2, 207, 30, 80, 161, 29, 63, 212, 			 42, 88, 233, 153, 76, 7, 150, 202, 71, 177, 125, 94, 110, 222], 
		gy: [148, 2, 70, 15, 37, 62, 89, 163, 7, 76, 218, 96, 32, 30, 142, 165, 94, 235, 218, 			  188, 70, 242, 239, 196, 68, 15, 162, 78, 10, 3, 164, 5] } 
}
sgx quote version = 2
sgx quote signature type = 1
sgx quote report_data = 39cdbd879a2d4ad55aeaecdc567fd947d5bd1d6c36fe0eaf6893bbf8b8e63cedfd272
						de1dd9181757a1c499227b06aa1647c90411dd1faabadcf139512753692
sgx quote mr_enclave = fb5d9f0e1ec5db8783335e3d9fb07e4f287ae2a70da1430c8414594bf0ef85e3
sgx quote mr_signer = 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
Anticipated public key = 39cdbd879a2d4ad55aeaecdc567fd947d5bd1d6c36fe0eaf6893bbf8b8e63cedfd27
						2de1dd9181757a1c499227b06aa1647c90411dd1faabadcf139512753692
```

