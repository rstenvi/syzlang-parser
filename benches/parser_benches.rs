use criterion::{criterion_group, criterion_main, Criterion};
use syzlang_parser::parser::Parsed;

fn bench_parse(c: &mut Criterion) {
	c.bench_function("parser", |b| {
		let s1 = r#"
arches = amd64
__NR_fake = 1
		"#;
		let s2 = r#"
resource fd[int32]: 1
resource fd[int32]: 0x1000
type abc1 const[0xffff]
type abc2 const[0xffffffff]
type abc3 const[0x0fffffffffffffff]
syz_some(a const[0x1])
syz_some(b const[-1])
fake(fd fd)
		"#;
		b.iter(|| Parsed::assemble(s2, s1, None).unwrap());
	});
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
