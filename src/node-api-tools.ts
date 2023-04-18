enum napi_valuetype {
    // ES6 types (corresponds to typeof)
    napi_undefined,
    napi_null,
    napi_boolean,
    napi_number,
    napi_string,
    napi_symbol,
    napi_object,
    napi_function,
    napi_external,
    napi_bigint,
}

enum napi_status {
    napi_ok,
    napi_invalid_arg,
    napi_object_expected,
    napi_string_expected,
    napi_name_expected,
    napi_function_expected,
    napi_number_expected,
    napi_boolean_expected,
    napi_array_expected,
    napi_generic_failure,
    napi_pending_exception,
    napi_cancelled,
    napi_escape_called_twice,
    napi_handle_scope_mismatch,
    napi_callback_scope_mismatch,
    napi_queue_full,
    napi_closing,
    napi_bigint_expected,
    napi_date_expected,
    napi_arraybuffer_expected,
    napi_detachable_arraybuffer_expected,
    napi_would_deadlock, // unused
    napi_no_external_buffers_allowed,
}

interface napi_extended_error_info {
    error_message: string | null;
    engine_reserved: NativePointer;
    engine_error_code: number;
    error_code: napi_status;
}

class NapiEnv extends NativePointer {
    static napi_get_property_func = new NativeFunction(
        Module.getExportByName(null, "napi_get_property"),
        "int",
        ["pointer", "pointer", "pointer", "pointer"]
    );
    static napi_get_named_property_func = new NativeFunction(
        Module.getExportByName(null, "napi_get_named_property"),
        "int",
        ["pointer", "pointer", "pointer", "pointer"]
    );
    static napi_create_string_utf8_func = new NativeFunction(
        Module.getExportByName(null, "napi_create_string_utf8"),
        "int",
        ["pointer", "pointer", "int", "pointer"]
    );
    static napi_get_last_error_info_func = new NativeFunction(
        Module.getExportByName(null, "napi_get_last_error_info"),
        "int",
        ["pointer", "pointer"]
    );
    static napi_run_script_func = new NativeFunction(
        Module.getExportByName(null, "napi_run_script"),
        "int",
        ["pointer", "pointer", "pointer"]
    );
    static napi_get_value_string_utf8_func = new NativeFunction(
        Module.getExportByName(null, "napi_get_value_string_utf8"),
        "int",
        ["pointer", "pointer", "pointer", "int", "pointer"]
    );
    static napi_get_buffer_info_func = new NativeFunction(
        Module.getExportByName(null, "napi_get_buffer_info"),
        "int",
        ["pointer", "pointer", "pointer", "pointer"]
    );
    static napi_typeof_func = new NativeFunction(
        Module.getExportByName(null, "napi_typeof"),
        "int",
        ["pointer", "pointer", "pointer"]
    );

    constructor(public env: NativePointer) {
        super(env);
    }

    napi_get_last_error_info(): napi_extended_error_info {
        const env = this.env;
        const result = Memory.alloc(4);
        if (NapiEnv.napi_get_last_error_info_func(env, result) != 0) {
            throw new Error("napi_get_last_error_info_func 失败");
        }
        const error_info = result.readPointer();
        return {
            error_message: error_info.readPointer().readUtf8String(),
            engine_reserved: error_info.add(Process.pointerSize).readPointer(),
            engine_error_code: error_info
                .add(Process.pointerSize * 2)
                .readInt(),
            error_code: error_info.add(Process.pointerSize * 3).readInt(),
        };
    }
    create_string(str: string): NapiValue {
        const env = this.env;
        const script_ptr = Memory.allocUtf8String(str);
        const script_len = str.length;
        const point_to_napi_value = Memory.alloc(4);
        if (
            NapiEnv.napi_create_string_utf8_func(
                env,
                script_ptr,
                script_len,
                point_to_napi_value
            ) != 0
        ) {
            throw new Error(this.napi_get_last_error_info().error_message!);
        }
        return NapiValue.from(this, point_to_napi_value.readPointer());
    }

    napi_get_property(obj: NapiValue, key: string): NapiValue {
        const env = this.env;
        const result = Memory.alloc(4);
        if (
            NapiEnv.napi_get_property_func(
                env,
                obj,
                this.create_string(key),
                result
            ) != 0
        ) {
            throw new Error(this.napi_get_last_error_info().error_message!);
        }
        return NapiValue.from(this, result.readPointer());
    }

    napi_run_script(script: string): NapiValue {
        const env = this.env;
        const result = Memory.alloc(4);
        if (
            NapiEnv.napi_run_script_func(
                env,
                this.create_string(script),
                result
            ) != 0
        ) {
            const error_info = this.napi_get_last_error_info();
            throw new Error(error_info.error_message!);
        }
        return NapiValue.from(this, result.readPointer());
    }

    get_napi_value_string_utf8(napi_value: NapiValue) {
        const result = Memory.alloc(4);
        const buffer = Memory.alloc(1000);
        const buffer_len = 1000;
        if (
            NapiEnv.napi_get_value_string_utf8_func(
                this.env,
                napi_value,
                buffer,
                buffer_len,
                result
            ) != 0
        ) {
            throw new Error(this.napi_get_last_error_info().error_message!);
        }
        return buffer.readUtf8String();
    }

    get_buffer_info(napi_value: NapiValue) {
        const buffer = Memory.alloc(4);
        const buffer_len = Memory.alloc(4);
        if (
            NapiEnv.napi_get_buffer_info_func(
                this.env,
                napi_value,
                buffer,
                buffer_len
            ) != 0
        ) {
            throw new Error(this.napi_get_last_error_info().error_message!);
        }
        const result = buffer.readPointer().readByteArray(buffer_len.readInt());
        if (result === null)
            throw new Error("readByteArray failed, result is null");
        return result;
    }

    get_type(napi_value: NapiValue): napi_valuetype {
        const result = Memory.alloc(4);
        if (NapiEnv.napi_typeof_func(this.env, napi_value, result) != 0) {
            throw new Error(this.napi_get_last_error_info().error_message!);
        }
        return result.readInt();
    }

    static from(env: NativePointer) {
        return new NapiEnv(env);
    }
}

class NapiValue extends NativePointer {
    env: NapiEnv;
    constructor(env: NapiEnv | NativePointer, ptr: NativePointer) {
        super(ptr);
        if (env instanceof NapiEnv) {
            this.env = env;
        } else {
            this.env = NapiEnv.from(env);
        }
    }

    static from(env: NapiEnv | NativePointer, ptr: NativePointer): NapiValue {
        return new NapiValue(env, ptr);
    }

    getString(): string | null {
        return this.env.get_napi_value_string_utf8(this);
    }

    getArrayBuffer(): ArrayBuffer {
        return this.env.get_buffer_info(this);
    }

    getType(): napi_valuetype {
        return this.env.get_type(this);
    }

    getProperty(key: string): NapiValue {
        return this.env.napi_get_property(this, key);
    }
}

function buffer_to_file(buffer: ArrayBuffer, name: string) {
    const f = new File(name, "wb");
    f.write(buffer);
    f.flush();
    f.close();
}

export { NapiEnv, NapiValue, buffer_to_file };
