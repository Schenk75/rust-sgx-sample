# only compile ./app folder (untrusted part)

App_Name := bin/app
App_Enclave_u_Object :=app/libEnclave_u.a
App_SRC_Files := $(shell find app/ -type f -name '*.rs') $(shell find app/ -type f -name 'Cargo.toml')
App_Rust_Flags := --release
App_Rust_Path := ./app/target/release

$(App_Name): $(App_Enclave_u_Object) $(App_SRC_Files)
	@cd app && SGX_SDK=$(SGX_SDK) cargo build $(App_Rust_Flags)
	@echo "Cargo  =>  $@"
	mkdir -p bin
	cp $(App_Rust_Path)/app ./bin

.PHONY: clean
clean:
	@cd app && cargo clean && rm -f Cargo.lock