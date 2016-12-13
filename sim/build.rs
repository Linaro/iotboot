// Build the library.

extern crate gcc;

fn main() {
    let mut conf = gcc::Config::new();

    conf.file("../src/bootutil/src/loader.c");
    conf.file("../src/bootutil/src/bootutil_misc.c");
    conf.file("csupport/run.c");
    conf.include("../src/bootutil/include");
    conf.include("../include");
    conf.debug(true);
    conf.compile("libbootutil.a");
}
