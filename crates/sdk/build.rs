fn main() {
    println!("cargo::rustc-check-cfg=cfg(monerochan_ci_in_progress)");
    if std::env::var("MONEROCHAN_CI_IN_PROGRESS").is_ok() {
        println!("cargo::rustc-cfg=monerochan_ci_in_progress");
    }
}
