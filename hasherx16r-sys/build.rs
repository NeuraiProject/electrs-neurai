fn main() {
    let sources = [
        "blake.c",
        "bmw.c",
        "groestl.c",
        "jh.c",
        "keccak.c",
        "skein.c",
        "luffa.c",
        "cubehash.c",
        "shavite.c",
        "simd.c",
        "echo.c",
        "hamsi.c",
        "fugue.c",
        "shabal.c",
        "whirlpool.c",
        "sph_sha2big.c",
        "tiger.c",
        "x16r.c",
    ];
    let mut build = cc::Build::new();
    build.include("csrc").warnings(false).opt_level(3);
    for source in sources {
        build.file(format!("csrc/{}", source));
        println!("cargo:rerun-if-changed=csrc/{}", source);
    }
    build.compile("hasherx16r");
}
