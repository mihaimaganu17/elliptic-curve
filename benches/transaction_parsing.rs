use criterion::{black_box, criterion_group, criterion_main, Criterion};
use elliptic_curve::{io::Reader, tx::{Transaction, Input, Output}};

pub fn criterion_benchmark(c: &mut Criterion) {
    //let mut reader= Reader::from_vec(include_bytes!("testdata/transaction_ex5_pg58.bin").to_vec());
    //c.bench_function("Tx parsing", |b| b.iter(|| Transaction::<Input, Output>::from_reader(&mut reader).unwrap()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
