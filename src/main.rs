use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use clap::Parser;
use log::{debug, info};
use syzlang_parser::parser::{Const, Consts, Os, Parsed, Statement};
use syzlang_parser::token::Token;

#[derive(Debug, Clone)]
enum Action {
	Tokenize,
	Parse,
	Process,
}

impl FromStr for Action {
	type Err = syzlang_parser::Error;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"tokenize" => Ok(Self::Tokenize),
			"parse" => Ok(Self::Parse),
			"process" => Ok(Self::Process),
			_ => Err(Self::Err::InvalidString(s.to_string())),
		}
	}
}

/// Convert Syzkaller language files to processed data
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	#[command(flatten)]
	verbose: clap_verbosity_flag::Verbosity<clap_verbosity_flag::WarnLevel>,

	// Action to perform (tokenize, parse, process)
	#[arg(short, long)]
	action: Action,

	/// Which operating systems to parse, use 'all' to parse all
	#[arg(long)]
	os: Vec<Os>,

	/// Syzkaller directory to parse
	#[arg(short, long)]
	dir: PathBuf,

	/// Save output to a file
	#[arg(short, long)]
	out: Option<PathBuf>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum SkFileType {
	Const,
	Stmts,
	All,
}

fn tokenize(
	dir: &mut PathBuf,
	os: &Os,
	sktype: SkFileType,
) -> Result<HashMap<PathBuf, Vec<Token>>> {
	let mut tokens = HashMap::new();
	let osdir = os.to_string();
	dir.push(osdir);
	assert!(dir.is_dir());
	for f in dir.read_dir()? {
		let f = f?;
		let ft = f.file_type()?;
		if ft.is_file() {
			let fpb = f.path();
			let fp = fpb.as_path();
			if let Some(fname) = fp.file_name() {
				let fname = fname.to_str().unwrap();

				let is_const = fname.ends_with(".const");
				let is_stmt = fname.ends_with(".txt");
				if (is_const || is_stmt)
					&& (sktype == SkFileType::All
						|| (sktype == SkFileType::Const && is_const)
						|| (sktype == SkFileType::Stmts && is_stmt))
				{
					debug!("parsing {fp:?}");
					let ins = Token::from_file(fp)?;
					tokens.insert(fpb, ins);
				}
			}
		}
	}
	dir.pop(); // os
	Ok(tokens)
}

fn tokenize_all(mut dir: PathBuf, oss: &[Os]) -> Result<HashMap<Os, HashMap<PathBuf, Vec<Token>>>> {
	let mut ret = HashMap::new();
	assert!(dir.is_dir());
	for os in oss.iter() {
		let tokens = tokenize(&mut dir, os, SkFileType::All)?;
		ret.insert(os.clone(), tokens);
	}
	Ok(ret)
}

fn parse_all(mut dir: PathBuf, oss: &[Os]) -> Result<HashMap<Os, Parsed>> {
	let mut ret = HashMap::new();
	assert!(dir.is_dir());
	for os in oss.iter() {
		info!("parsing {os:?}");
		let constsmap = tokenize(&mut dir, os, SkFileType::Const)?;
		debug!("got tokens from {} files", constsmap.len());
		let mut consts = Consts::default();
		for (key, tokens) in constsmap.into_iter() {
			let arch = Consts::get_arch_from_path(&key)?;
			let ins = Const::from_tokens(tokens, arch)?;
			consts.add_vec(ins);
		}
		info!("got {} consts", consts.consts().len());

		let tokens = tokenize(&mut dir, os, SkFileType::Stmts)?;
		let mut stmts = Vec::new();
		for (_key, tokens) in tokens.into_iter() {
			let mut ins = Statement::from_tokens(tokens)?;
			stmts.append(&mut ins);
		}
		info!("got {} statements", stmts.len());
		let parsed = Parsed::new(consts, stmts)?;
		ret.insert(os.clone(), parsed);
	}
	Ok(ret)
}

fn process_all(dir: PathBuf, oss: &[Os]) -> Result<HashMap<Os, Parsed>> {
	let mut parsed = parse_all(dir, oss)?;

	for (os, p) in parsed.iter_mut() {
		info!("postprocess on {os:?}");
		p.insert_builtin()?;
		p.postprocess()?;
		p.clear_unneeded()?;
	}

	Ok(parsed)
}

fn main() -> Result<()> {
	let mut args = Args::parse();
	pretty_env_logger::formatted_builder()
		.filter_level(args.verbose.log_level_filter())
		.init();
	info!("started");

	let oss = if let Some(Os::All) = args.os.first() {
		Os::all()
	} else {
		std::mem::take(&mut args.os)
	};

	let mut skdir = args.dir.clone();
	skdir.push("sys");

	let save = match args.action {
		Action::Tokenize => serde_json::to_value(tokenize_all(skdir, &oss)?)?,
		Action::Parse => serde_json::to_value(parse_all(skdir, &oss)?)?,
		Action::Process => serde_json::to_value(process_all(skdir, &oss)?)?,
	};
	if let Some(n) = &args.out {
		info!("writing result to {n:?}");
		std::fs::write(n, serde_json::to_string(&save)?)?;
	}
	Ok(())
}
