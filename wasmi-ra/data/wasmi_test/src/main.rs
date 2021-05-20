extern crate wasmi;
extern crate wabt;
extern crate time;

use std::collections::HashMap;
use std::io::{self, Write, Read, BufReader};

mod wasm_def;

// use wasm_def::{RuntimeValue, Error as InterpreterError};
use wasmi::memory_units::Pages;
use wasmi::Error as InterpreterError;
use wasmi::{ModuleInstance,
            ImportsBuilder,
            RuntimeValue,
//          NopExternals,
            MemoryInstance,
            GlobalInstance,
            GlobalRef,
            TableRef,
            MemoryRef,
            TableInstance,
            Trap,
            Externals,
            RuntimeArgs,
            FuncRef,
            Signature,
            FuncInstance,
            ModuleImportResolver,
            TableDescriptor,
            MemoryDescriptor,
            GlobalDescriptor,
            ModuleRef,
            ImportResolver,
            Module,
};
use wabt::script;
use wabt::script::{Action, Command, CommandKind, ScriptParser, Value};

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

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
        // RuntimeValue::V128(rv) => BoundaryValue::V128(rv),
    }
}

fn boundary_value_to_runtime_value(rv: BoundaryValue) -> RuntimeValue {
    match rv {
        BoundaryValue::I32(bv) => RuntimeValue::I32(bv),
        BoundaryValue::I64(bv) => RuntimeValue::I64(bv),
        BoundaryValue::F32(bv) => RuntimeValue::F32(bv.into()),
        BoundaryValue::F64(bv) => RuntimeValue::F64(bv.into()),
        BoundaryValue::V128(bv) => panic!("Not supported yet!"),
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

pub fn result_covert(res : Result<Option<RuntimeValue>, InterpreterError>)
                     -> Result<Option<BoundaryValue>, InterpreterError>
{
    match res {
        Ok(None) => Ok(None),
        Ok(Some(rv)) => Ok(Some(runtime_value_to_boundary_value(rv))),
        Err(x) => Err(x),
    }
}

fn spec_to_runtime_value(value: Value) -> RuntimeValue {
    match value {
        Value::I32(v) => RuntimeValue::I32(v),
        Value::I64(v) => RuntimeValue::I64(v),
        Value::F32(v) => RuntimeValue::F32(v.into()),
        Value::F64(v) => RuntimeValue::F64(v.into()),
        _             => panic!("Not supported yet!"),
    }
}

pub struct SpecModule {
    table: TableRef,
    memory: MemoryRef,
    global_i32: GlobalRef,
    global_f32: GlobalRef,
    global_f64: GlobalRef,
}

impl SpecModule {
    pub fn new() -> Self {
        SpecModule {
            table: TableInstance::alloc(10, Some(20)).unwrap(),
            memory: MemoryInstance::alloc(Pages(1), Some(Pages(2))).unwrap(),
            global_i32: GlobalInstance::alloc(RuntimeValue::I32(666), false),
            global_f32: GlobalInstance::alloc(RuntimeValue::F32(666.0.into()), false),
            global_f64: GlobalInstance::alloc(RuntimeValue::F64(666.0.into()), false),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Load(String),
    Start(Trap),
    Script(script::Error),
    Interpreter(InterpreterError),
}

impl From<InterpreterError> for Error {
    fn from(e: InterpreterError) -> Error {
        Error::Interpreter(e)
    }
}

impl From<script::Error> for Error {
    fn from(e: script::Error) -> Error {
        Error::Script(e)
    }
}

const PRINT_FUNC_INDEX: usize = 0;

impl Externals for SpecModule {
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {
        match index {
            PRINT_FUNC_INDEX => {
                println!("print: {:?}", args);
                Ok(None)
            }
            _ => panic!("SpecModule doesn't provide function at index {}", index),
        }
    }
}

impl ModuleImportResolver for SpecModule {
    fn resolve_func(
        &self,
        field_name: &str,
        func_type: &Signature,
    ) -> Result<FuncRef, InterpreterError> {
        let index = match field_name {
            "print" => PRINT_FUNC_INDEX,
            "print_i32" => PRINT_FUNC_INDEX,
            "print_i32_f32" => PRINT_FUNC_INDEX,
            "print_f64_f64" => PRINT_FUNC_INDEX,
            "print_f32" => PRINT_FUNC_INDEX,
            "print_f64" => PRINT_FUNC_INDEX,
            _ => {
                return Err(InterpreterError::Instantiation(format!(
                    "Unknown host func import {}",
                    field_name
                )));
            }
        };

        if func_type.return_type().is_some() {
            return Err(InterpreterError::Instantiation(
                "Function `print_` have unit return type".into(),
            ));
        }

        let func = FuncInstance::alloc_host(func_type.clone(), index);
        return Ok(func);
    }
    fn resolve_global(
        &self,
        field_name: &str,
        _global_type: &GlobalDescriptor,
    ) -> Result<GlobalRef, InterpreterError> {
        match field_name {
            "global_i32" => Ok(self.global_i32.clone()),
            "global_f32" => Ok(self.global_f32.clone()),
            "global_f64" => Ok(self.global_f64.clone()),
            _ => Err(InterpreterError::Instantiation(format!(
                "Unknown host global import {}",
                field_name
            )))
        }
    }

    fn resolve_memory(
        &self,
        field_name: &str,
        _memory_type: &MemoryDescriptor,
    ) -> Result<MemoryRef, InterpreterError> {
        if field_name == "memory" {
            return Ok(self.memory.clone());
        }

        Err(InterpreterError::Instantiation(format!(
            "Unknown host memory import {}",
            field_name
        )))
    }

    fn resolve_table(
        &self,
        field_name: &str,
        _table_type: &TableDescriptor,
    ) -> Result<TableRef, InterpreterError> {
        if field_name == "table" {
            return Ok(self.table.clone());
        }

        Err(InterpreterError::Instantiation(format!(
            "Unknown host table import {}",
            field_name
        )))
    }
}

pub struct SpecDriver {
    spec_module: SpecModule,
    instances: HashMap<String, ModuleRef>,
    last_module: Option<ModuleRef>,
}

impl SpecDriver {
    pub fn new() -> SpecDriver {
        SpecDriver {
            spec_module: SpecModule::new(),
            instances: HashMap::new(),
            last_module: None,
        }
    }

    pub fn spec_module(&mut self) -> &mut SpecModule {
        &mut self.spec_module
    }

    pub fn add_module(&mut self, name: Option<String>, module: ModuleRef) {
        self.last_module = Some(module.clone());
        if let Some(name) = name {
            self.instances.insert(name, module);
        }
    }

    pub fn module(&self, name: &str) -> Result<ModuleRef, InterpreterError> {
        self.instances.get(name).cloned().ok_or_else(|| {
            InterpreterError::Instantiation(format!("Module not registered {}", name))
        })
    }

    pub fn module_or_last(&self, name: Option<&str>) -> Result<ModuleRef, InterpreterError> {
        match name {
            Some(name) => self.module(name),
            None => self.last_module
                .clone()
                .ok_or_else(|| InterpreterError::Instantiation("No modules registered".into())),
        }
    }

    pub fn register(&mut self, name : &Option<String>,
                    as_name : String) -> Result<(), InterpreterError> {
        let module = match self.module_or_last(name.as_ref().map(|x| x.as_ref())) {
            Ok(module) => module,
            Err(_) => return Err(InterpreterError::Instantiation("No such modules registered".into())),
        };
        self.add_module(Some(as_name), module);
        Ok(())
    }
}

impl ImportResolver for SpecDriver {
    fn resolve_func(
        &self,
        module_name: &str,
        field_name: &str,
        func_type: &Signature,
    ) -> Result<FuncRef, InterpreterError> {
        if module_name == "spectest" {
            self.spec_module.resolve_func(field_name, func_type)
        } else {
            self.module(module_name)?
                .resolve_func(field_name, func_type)
        }
    }

    fn resolve_global(
        &self,
        module_name: &str,
        field_name: &str,
        global_type: &GlobalDescriptor,
    ) -> Result<GlobalRef, InterpreterError> {
        if module_name == "spectest" {
            self.spec_module.resolve_global(field_name, global_type)
        } else {
            self.module(module_name)?
                .resolve_global(field_name, global_type)
        }
    }

    fn resolve_memory(
        &self,
        module_name: &str,
        field_name: &str,
        memory_type: &MemoryDescriptor,
    ) -> Result<MemoryRef, InterpreterError> {
        if module_name == "spectest" {
            self.spec_module.resolve_memory(field_name, memory_type)
        } else {
            self.module(module_name)?
                .resolve_memory(field_name, memory_type)
        }
    }

    fn resolve_table(
        &self,
        module_name: &str,
        field_name: &str,
        table_type: &TableDescriptor,
    ) -> Result<TableRef, InterpreterError> {
        if module_name == "spectest" {
            self.spec_module.resolve_table(field_name, table_type)
        } else {
            self.module(module_name)?
                .resolve_table(field_name, table_type)
        }
    }
}

pub fn try_load_module(wasm: &[u8]) -> Result<Module, Error> {
    Module::from_buffer(wasm).map_err(|e| Error::Load(e.to_string()))
}

pub fn try_load(wasm: &[u8], spec_driver: &mut SpecDriver) -> Result<(), Error> {
    let module = try_load_module(wasm)?;
    let instance = ModuleInstance::new(&module, &ImportsBuilder::default())?;
    instance
        .run_start(spec_driver.spec_module())
        .map_err(|trap| Error::Start(trap))?;
    Ok(())
}

pub fn load_module(wasm: &[u8], name: &Option<String>, spec_driver: &mut SpecDriver) -> Result<ModuleRef, Error> {
    let module = try_load_module(wasm)?;
    let instance = ModuleInstance::new(&module, spec_driver)
        .map_err(|e| Error::Load(e.to_string()))?
        .run_start(spec_driver.spec_module())
        .map_err(|trap| Error::Start(trap))?;

    let module_name = name.clone();
    spec_driver.add_module(module_name, instance.clone());

    Ok(instance)
}

fn run_action(action: &Action, spec_driver: &mut SpecDriver) -> Result<Option<RuntimeValue>, InterpreterError> {
    match action {
        &Action::Invoke {
            ref module,
            ref field,
            ref args,
        } => {
            let args: Vec<BoundaryValue> = args.into_iter()
                .map(wabt_runtime_value_to_boundary_value)
                .collect();
            let args = args.into_iter()
                .map(|x| boundary_value_to_runtime_value(x))
                .collect::<Vec<RuntimeValue>>();
            let module = spec_driver.module_or_last(module.as_ref().map(|x| x.as_ref()))
                        .expect(&format!("Expected program to have loaded module {:?}", module));
            module.invoke_export(&field, &args, spec_driver.spec_module())
        },
        &Action::Get {
            ref module,
            ref field,
            ..
        } => {
            let module = match module {
                None => {
                         spec_driver
                         .module_or_last(None)
                         .expect(&format!("Expected program to have loaded module {:?}",
                                "None"
                         ))
                },
                Some(str) => {
                         spec_driver
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
        },
    }
}


fn main() {
    let wast_list = vec![
        "test_input/int_exprs.wast",
        // "test_input/conversions.wast",
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
        // "test_input/float_misc.wast",
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
        // "test_input/f64.wast",
        "test_input/type.wast",
        "test_input/fac.wast",
        "test_input/set_local.wast",
        "test_input/func.wast",
        // "test_input/f32.wast",
        "test_input/f32_bitwise.wast",
        // "test_input/float_exprs.wast",
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
    let mut spec_driver = SpecDriver::new();
    let file_path = "data10.txt";
    std::fs::File::create(file_path).unwrap();
    let mut file = std::fs::OpenOptions::new().append(true).open(file_path).expect("cannot open file");
    for wast_file in wast_list {
        println!("======================= testing {} =====================", wast_file);
        let start_time = time::get_time();
        // ScriptParser interface has changed. Need to feed it with wast content.
        let wast_content : Vec<u8> = std::fs::read(wast_file).unwrap();
        let path = std::path::Path::new(wast_file);
        let fnme = path.file_name().unwrap().to_str().unwrap();
        let mut parser = ScriptParser::from_source_and_name(&wast_content, fnme).unwrap();
    
        while let Some(Command{kind,line}) =
            match parser.next() {
                Ok(x) => x,
                _ => { return; }
            } 
        {
            // println!("Line : {}", line);
            match kind {
                CommandKind::Module { name, module, .. } => {
                    let module = module.into_vec();
                    
                    let r = load_module(&module[..], &name, &mut spec_driver);
                    match r {
                        Ok(_) => {},
                        Err(x) => {
                            panic!(x);
                        }
                    }

                    // println!("load module - success at line {}", line)
                },
    
                CommandKind::AssertReturn { action, expected } => {
                    let result = run_action(&action, &mut spec_driver);
                    
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
                            // println!("assert_return at line {} - success", line);
                        },
                        Err(e) => {
                            panic!("Expected action to return value, got error: {:?}", e);
                        }
                    }
                },
    
                CommandKind::AssertReturnCanonicalNan { action }
                | CommandKind::AssertReturnArithmeticNan { action } => {
                    let result = run_action(&action, &mut spec_driver);
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
                            // println!("assert_return_nan at line {} - success", line);
                        }
                        Err(e) => {
                            panic!("Expected action to return value, got error: {:?}", e);
                        }
                    }
                },
    
                CommandKind::AssertExhaustion { action, .. } => {
                    let result = run_action(&action, &mut spec_driver);
                    match result {
                        Ok(result) => panic!("Expected exhaustion, got result: {:?}", result),
                        Err(e) => {
                            // println!("assert_exhaustion at line {} - success ({:?})", line, e)
                        },
                    }
                },
    
                CommandKind::AssertTrap { action, .. } => {
                    // println!("Enter AssertTrap!");
                    let result = run_action(&action, &mut spec_driver);
                    match result {
                        Ok(result) => {
                            panic!("Expected action to result in a trap, got result: {:?}", result);
                        },
                        Err(e) => {
                            // println!("assert_trap at line {} - success ({:?})", line, e);
                        },
                    }
                },
    
                CommandKind::AssertInvalid { module, .. }
                | CommandKind::AssertMalformed { module, .. }
                | CommandKind::AssertUnlinkable { module, .. } => {
                    // Malformed
                    let module = module.into_vec();
                    let module_load = try_load(&module[..], &mut spec_driver);
                    match module_load {
                        Ok(_) => panic!("Expected invalid module definition, got some module!"),
                        Err(e) => {
                            // println!("assert_invalid at line {} - success ({:?})", line, e)
                        },
                    }
                },
    
                CommandKind::AssertUninstantiable { module, .. } => {
                    let module = module.into_vec();
                    let module_load = try_load(&module[..], &mut spec_driver);
                    match module_load {
                        Ok(_) => panic!("Expected error running start function at line {}", line),
                        Err(e) => {
                            // println!("assert_uninstantiable - success ({:?})", e)
                        },
                    }
                },
    
                CommandKind::Register { name, as_name, .. } => {
                    let result = spec_driver.register(&name, as_name);
                    match result {
                        Ok(_) => {
                            // println!("register - success at line {}", line)
                        },
                        Err(e) => panic!("No such module, at line {} - ({:?})", e, line),
                    }
                },
    
                CommandKind::PerformAction(action) => {
                    let result = run_action(&action, &mut spec_driver);
                    match result {
                        Ok(_) => {
                            // println!("invoke - success at line {}", line)
                        },
                        Err(e) => panic!("Failed to invoke action at line {}: {:?}", line, e),
                    }
                },
            }
        }
        let duration = time::get_time() - start_time;
        let wasm_name: Vec<&str> = wast_file.split(|c| c == '/' || c == '.').collect();
        file.write_all(format!("{}: {}\n", wasm_name[1], duration.num_nanoseconds().unwrap()).as_bytes()).expect("write fail");
    }
}
