use criterion::{criterion_group, criterion_main, Criterion};
use syzlang_parser::token::Token;

fn bench_parse(c: &mut Criterion) {
	c.bench_function("parse tokens1", |b| {
		let s = r#"abcd = "hello", `world`, "!", "Hello World!""#;
		b.iter(|| Token::create_from_str(s).unwrap())
	});
	c.bench_function("parse tokens2", |b| {
		let s = r#"resource fd[int32]"#;
		b.iter(|| Token::create_from_str(s).unwrap())
	});
	c.bench_function("parse tokens3", |b| {
		let s = r#"
		# Some comment
		
		func$abcd(type int32, meta int64) fd
		
"#;
		b.iter(|| Token::create_from_str(s).unwrap())
	});
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
