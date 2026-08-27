fn main() {
    #[cfg(feature = "proto")]
    {
        prost_build::compile_protos(&["proto/hydr.proto"], &["proto"]).expect("compile hydr protobuf");
    }
}
