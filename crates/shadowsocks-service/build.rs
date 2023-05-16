use std::io;

fn main() -> io::Result<()> {
    #[cfg(feature = "local-fake-dns")]
    prost_build::compile_protos(
        &["src/local/fake_dns/proto/fake_dns.proto"],
        &["src/local/fake_dns/proto/"],
    )?;

    Ok(())
}
