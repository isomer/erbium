fn main() {
    /* We would like to log what version we were built at to aid in debugging problems, many people
     * end up running old versions of erbium and never upgrade.
     */
    vergen::EmitBuilder::builder()
        .quiet()
        .idempotent()
        .cargo_features()
        .git_describe(true, true, None)
        .emit()
        .expect("Failed to extract vergen build information")
}
