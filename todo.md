進入enclave時的度量方法：使用/opt/intel/sgxsdk/bin/x64/sgx_sign工具
動態鏈接的wasm代碼：使用rust/c寫程序之後轉換爲wast

技術路線確定：白名單機制（enclave初始化之前就確定好能加載什麼內容） or 運行時通過某種方式度量
流程圖完善
確定在代碼中哪些部分需要修改

場景：區塊鏈中 在系統運行過程中，用戶提交新的wasm腳本，enclave來判斷是否執行



-------------

3/24

A用戶的Enclave通過某種方式認證A的身份：A用戶生成一個證書，在創建（初始化）enclave時存入

A用戶在Enclave外生成一對公私鑰，A用戶對wasm腳本籤名，A用戶的Enclave辨別A所籤名的wasm腳本並允許添加

B用戶調用A用戶Enclave中的wasm腳本，B從A處獲得wasm腳本的內容並且可以驗證在Enclave中運行的確實是這一個腳本（通過驗證腳本的哈希）

B用戶不能向A用戶的Enclave中添加他籤名的wasm腳本，Enclave需要進行權限管理



1. wasm腳本哈希計算
2. 在enclave外生成rsa公私鑰
3. 用戶對一段sha256哈希值籤名，在enclave中驗證籤名（rsa3072）
4. 將私鑰以lazy_static的形式保存在enclave中，以便其他用戶申請驗證wasm腳本時給出籤名
5. 搞清楚wasmi在enclave外對wasm腳本解析的具體原理
   - 根節點下的每一個子節點作爲一個CommandKind，會作爲整體解析。如一個根節點下的module作爲一個整體經過序列化後載入enclave，在wast文本中的表現就是每一對最外層的括號會被parse成一個整體
6. SPECDRIVER加載的模塊是否在enclave的生命周期中一直存在？
   - 如果執行了 `sgxwasm_init` ，那麼SPECDRIVER中的內容會清空；若不執行，module會一直在SPECDRIVER中，直到enclave銷毀

-------------

3/31

將enclave作爲服務器跑起來

在命令行傳文件名，動態加載到enclave中：經過用戶籤名的載入，沒有籤名的拒絕載入

web3基金項目

開題ppt添加項目進展

不可信的代碼解耦合（invoke和籤名）大致完成

公私鑰保存到本地



1. 加載模塊時怎麼給模塊附加名字

   - 可以通過使用代碼修改name來將module注冊到SPECDRIVER.instances中

     ```rust
     CommandKind::Module { name, module, .. } => {
         let name = Some(String::from("test"));
         sgx_enclave_wasm_load_module (module.into_vec(), &name, enclave)?;
         println!("load module - success at line {}", line)
     }
     ```

   - 在wast腳本中直接寫module名

     ```wast
     (module $add_module
       (func $add (param $lhs i32) (param $rhs i32) (result i32)
         get_local $lhs
         get_local $rhs
         i32.add)
       (export "add" (func $add))
     )
     ```

2. 測試動態加載：將文件名作爲命令行輸入，開兩個進程，將enclave+wasmi作爲服務端進程，通過另一進程注入wasm模塊

3. 基金項目的申請：

   - 要與Polkadot、Substrate相關（怎麼整合）
   - 團隊？

4. 公私鑰本地生成，保存到本地文件中（還沒有很完善）

----------------------------

4/7

eos以太坊 wasm結合區塊鏈的方法

TWINE論文

證書

-------------------

4/14

#### 學習substrate

- 基礎內容：blog
- *substrate/primitives/sandbox* ：使用到wasmi的沙箱環境

#### enclave遠程認證

- 證書部分 openssl

  - CA生成椭圆曲线私鑰：

    ```bash
    openssl ecparam -genkey -name prime256v1 -out ca.key
    ```

  - CA生成證書CRT：

    ```bash
    openssl req -x509 -new -SHA256 -nodes -key ca.key -days 3650 -out ca.crt
    ```

  - client生成椭圆曲线私鑰：(-genkey:生成密鑰  -name:採用短名字)

    ```bash
    openssl ecparam -genkey -name prime256v1 -out client.key
    ```

  - client將密鑰轉換爲pkcs8格式：(-topk8:輸出pkcs8文件  -nocrypt: 加密输入文件，输出的文件不被加密)

    ```bash
    openssl pkcs8 -topk8 -nocrypt -in client.key -out client.pkcs8
    ```

  - client生成證書請求文件CSR：(-new:生成證書請求文件  -nodes:說明生成的密鑰不需要加密)

    ```bash
    openssl req -new -SHA256 -key client.key -nodes -out client.csr
    ```

  - client生成證書CRT：(-req:输入为证书请求，需要进行处理  -CA:设置CA文件，必须为PEM格式  -CAcreateserial:表示创建证书序列号文件ca.srl)

    ```bash
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,DNS:www.example.com") -days 3650 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
    ```

- 認證的大致流程：用戶需要驗證服務端的quote，服務端需要認證用戶的證書是否由自己認可的CA頒發

  - 雙方在什麼時候驗證的證書（代碼沒太看明白）

- wasmi-ra整體邏輯

  - 提供正確證書的client可以上傳wasm腳本（client是否還需要對wasm腳本籤名？）
  - 沒有證書或者證書驗證不通過的client只能運行wasm腳本，不能上傳

- 修改wasmi-ra代碼：

  - step1: 整合wasmi-sgx和ue-ra兩個項目，將包含wasmi解釋器的enclave作爲服務器，能使用client連接
    - 整合代碼後無法編譯：在enclave/target/release目錄下，編譯出了兩個.a文件，而在enclave/Makefile中只把一個復制到了根目錄下的lib目錄中【解決：粗暴地把兩個.a靜態庫合並爲一個再復制】【最終解決：make clean後重新make，只剩一個.a靜態庫；其次，enclave裏的run_server函數之前忘記加  #[no_mangle]】
  - step2: 加入證書認證，client端通過認證後傳給服務器wasm腳本文件名稱（修改run_server的代碼）

--------

4/21

- 完善wasmi-ra代碼：
  - step1：服務端一直循環監聽客戶端，客戶端輸入exit兩端都結束進程
  - step2：客戶端發送需要執行的wast腳本到enclave，enclave執行
    - upload模式：enclave擁有者經過認證後發送序列化後的wast腳本到enclave，enclave執行
    - test模式：測試test_input目錄下的所有wast文件（待更正：names.wast跑不通）【之前的錯誤是由於server端buffer長度不夠讀取所有client發送的字節流，現在改爲循環讀取】
  - step3：在upload模式中，將傳進Enclave的json持久化到本地，使用一個Ocall將字符串傳遞到非安全區（密封功能、文件自己命名功能未完成）
  - step4：根據客戶端輸入的文件名，讀取(並解封)在Enclave外的文件內的wasm模塊的json字符串，加載進Enclave

---------



#### todo

1. 在upload模式中，將傳進Enclave的json經過密封後保存
2. 實現Ocall函數 `ocall_load_wast` ，根據客戶端輸入的文件名，讀取並解封在Enclave外的文件內的wasm模塊的json字符串，加載進Enclave
3. 客戶端對模塊進行籤名，服務端驗證籤名後才將模塊加載到driver中並持久化保存（最好使用證書中的公私鑰重新實現）
4. 驗證代碼的完整性（還沒想好技術方案）
5. 對於沒有指定CA籤發的證書的用戶，即非Enclave擁有者，如何建立TLS通信（暫時考慮使用不同的CA籤發證書）（這一部分不一定要實現）

- upload模式輸入不存在的文件名時的錯誤處理



#### experiment

1. 性能測試：比較原生的wasmi和sgx-wasmi跑所有test_input的效率
2. 安全測試：
   - 



#### future work

- 引入多線程




> `sgx_tse::se`
>
> `pub fn rsgx_create_report(target_info: &sgx_target_info_t, report_data: &sgx_report_data_t) -> SgxResult<sgx_report_t>`
>
> ------
>
> The rsgx_create_report function tries to use the information of the target enclave and other information to create a cryptographic report of the enclave.
>
> This function is a wrapper for the SGX EREPORT instruction.
>
> # Description
>
> Use the function rsgx_create_report to create a cryptographic report that describes the contents of the calling enclave. The report can be used by other enclaves to verify that the enclave is running on the same platform. When an enclave calls rsgx_verify_report to verify a report, it will succeed only if the report was generated using the target_info for said enclave. This function is a wrapper for the SGX EREPORT instruction.
>
> Before the source enclave calls rsgx_create_report to generate a report, it needs to populate target_info with information about the target enclave that will verify the report. The target enclave may obtain this information calling rsgx_create_report with a default value for target_info and pass it to the source enclave at the beginning of the inter-enclave attestation process.
>
> # Parameters
>
> **target_info**
>
> A pointer to the sgx_target_info_t object that contains the information of the target enclave, which will be able to cryptographically verify the report calling rsgx_verify_report.efore calling this function.
>
> If value is default, sgx_create_report retrieves information about the calling enclave, but the generated report cannot be verified by any enclave.
>
> **report_data**
>
> A pointer to the sgx_report_data_t object which contains a set of data used for communication between the enclaves.



已跑通：

- mutual-ra: Mutual Remote Attestation 雙向遠程認證（兩個enclave）

- ue-ra: Untrusted-Enclave Remote Attestation（非安全區和enclave之間認證）
- tr-mpc: Trusted Multi-player computing

  - Assuming that there are two players: Alice and Bob.

    - Alice wants to get data from bob and compute its hash.

    - Bob does not want to let Alice know the origin data.

全rust改寫：

- secretsharing: shamir密钥共享
- localattestation: 本地enclave認證

還跑不通：
- pcl: protected code launch 受保護代碼部署

  ```bash
  /usr/bin/ld: ./lib/libenclave.a(sgx_libc-bc016a3e80658a88.sgx_libc.9ij658qc-cgu.5.rcgu.o): in function `sgx_libc::linux::x86_64::ocall::stat64':
  sgx_libc.9ij658qc-cgu.5:(.text._ZN8sgx_libc5linux6x86_645ocall6stat6417h11aa72a7ac58e91aE+0x27): undefined reference to `u_stat64_ocall'
  collect2: error: ld returned 1 exit status
  make[1]: *** [Makefile:133: enclave/enclave.so] Error 1
  make[1]: Leaving directory '/home/schenk/sgx/incubator-teaclave-sgx-sdk/rust-sgx-sample/pcl/encrypted-hello'
  make: *** [Makefile:11: payload] Error 2
  ```

暫時用不到：

- dcap-pkcretrieval: Data Center Attestation Primitives 与基于英特尔 EPID 的鉴证解决方案相比，英特尔 SGX DCAP 基于ECDSA，要求更多由提供商管理的基础设施，并帮助提供商创建此类基础设施
- psi: Private Set Intersection 两个数据集求他们的交集的协议，但是却不泄露任何一方除了交集之外的信息！





Secure Channel Establishment between Source (E1) and Destination (E2) Enclaves successful !!!

Secure Channel Establishment between Source (E1) and Destination (E3) Enclaves successful !!!

Secure Channel Establishment between Source (E2) and Destination (E3) Enclaves successful !!!

Secure Channel Establishment between Source (E3) and Destination (E1) Enclaves successful !!!

Close Session between Source (E1) and Destination (E2) Enclaves successful !!!

Close Session between Source (E1) and Destination (E3) Enclaves successful !!!

Close Session between Source (E2) and Destination (E3) Enclaves successful !!!

Close Session between Source (E3) and Destination (E1) Enclaves successful !!!

Hit a key....


