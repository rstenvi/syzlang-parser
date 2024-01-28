# syzlang-parser

Parse [Syzkaller](https://github.com/google/syzkaller) data into structures more
useful in Rust.

## Status

This projects was created to extract some system call descriptions and you
should not expect it to parse everything from the latest version of Syzkaller. A
known working version of Syzkaller is hash
`1834ff143d083ae2c374f2a18d887575887321a9`.

I use this is in my `build.rs` file, therefore I haven't seen much need for
fixing the many uses of `unwrap()`. This crate should not be seen as stable to
use if you don't decide on the data source during compilation time. I will
hopefully fix this at some point.

## Build

To build with our without CLI tool to parse Syzkaller checkout.

~~~
cargo build --release
cargo build --release --features=cli
~~~

There is also a [Makefile.toml](Makefile.toml) used by
[cargo-make](https://github.com/sagiegurari/cargo-make) but that can be ignored.

To test on a checkout of Syzkaller you can use:

~~~
cargo run --features=cli -- --os all --dir /path/to/syzkaller -a process
~~~

This will parse everything, but do not store the results, see help command for
more info.