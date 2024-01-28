//! Parse Syzkaller language into a series of tokens for future processing.

use crate::{generror, verify, Error, Result};
use log::{debug, error, trace};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// All the different tokens we divide the language into
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Token {
	/// Include a C header file
	Include,

	/// Includes a directory of C header files
	Incdir,

	/// Resource keyword indicating a resource is being declared
	Resource,

	/// Type keyword, indicating a type being declared
	Type,

	/// Define statement indicating a C macro expression is coming next
	Define,

	/// Meta keyword, next entry can be some meta information about the file
	Meta,

	/// Char: <
	CrocOpen,

	/// Char: >
	CrocClose,

	/// Char: (
	ParenOpen,

	/// Char: )
	ParenClose,

	/// Char: }
	BracketOpen,

	/// Char: }
	BracketClose,

	/// Char: [
	SquareOpen,

	/// Char: ]
	SquareClose,

	/// Char: :
	Colon,

	/// Char: ,
	Comma,
	Newline,

	/// Char: =
	Equal,

	/// Char: $
	Dollar,

	/// The text has been processed as a comment, because it started with '#'
	Comment(String),

	/// Some string enclosed in double quotes
	String(String),

	/// Some identifier we didn't match to any keyword
	Name(String),

	/// Character enclosed in single quotes
	Char(char),
}

impl Token {
	/// Load all tokens from file
	pub fn from_file(s: &Path) -> Result<Vec<Token>> {
		debug!("loading file {s:?}");
		let data = std::fs::read(s)?;
		let data = std::str::from_utf8(&data)?;
		Self::create_from_str(data)
	}
	/// Load all files matching glob pattern
	pub fn all_globs(dir: &Path, pattern: &str) -> Result<Vec<Vec<Token>>> {
		debug!("loading globs {pattern} @ {dir:?}");
		if let Some(q) = dir.as_os_str().to_str() {
			let mut q = q.to_string();
			q.push('/');
			q.push_str(pattern);

			let mut ret = Vec::new();
			for file in glob::glob(&q).unwrap() {
				let file = file.unwrap();
				debug!("file {file:?}");
				let n = Self::from_file(file.as_path())?;
				ret.push(n);
			}
			Ok(ret)
		} else {
			Err(Error::Error(format!(
				"unable to parse dir to string {dir:?}"
			)))
		}
	}

	/// Load all data from string
	pub fn create_from_str(data: &str) -> Result<Vec<Token>> {
		trace!("parsing '{data}'");
		let mut ret = Vec::new();
		let mut curr = String::default();
		let mut quote = None;

		// let parts: Vec<_> = data.split('\n').collect();
		for (i, line) in data.split('\n').enumerate() {
			trace!("line[{i}]: {line}");

			// TODO: Doesn't preserve number of spaces or type of whitespace
			let line = line.trim();
			if quote.is_none() && line.is_empty() {
				ret.push(Token::Newline);
				continue;
			}

			if line.starts_with('#') {
				let ins = Token::Comment(line.to_string());
				ret.push(ins);
				ret.push(Token::Newline);
				continue;
			}
			for item in line.split([' ', '\t']) {
				trace!("item = '{item}'");
				if let Some(q) = &quote {
					curr.push(' ');
					curr.push_str(item);
					if Self::quote_enclosed(&curr, *q) || *q == '\'' {
						Self::parse_loop(curr, &mut ret)?;
						// curr.clear();
						curr = String::default();
						quote = None;
						continue;
					}
				} else if !Self::quote_enclosed(item, '"') {
					quote = Some('"');
					curr.push_str(item);
				} else if !Self::quote_enclosed(item, '\'') {
					quote = Some('\'');
					curr.push_str(item);
				} else if !Self::quote_enclosed(item, '`') {
					quote = Some('`');
					curr.push_str(item);
				} else {
					Self::parse_loop(item, &mut ret)?;
				}
			}

			ret.push(Token::Newline);
		}
		// We always add an extra newline at the end
		ret.pop();

		if !curr.is_empty() {
			return Err(Self::error(format!(
				"remaining data from unenclosed quote '{curr}'"
			)));
		}
		let ret = Self::post_proc(ret);
		Ok(ret)
	}

	/// Get token as string, but only it it's a valid name identifier
	pub fn to_name(&self) -> Result<&String> {
		debug!("calling to_name {self:?}");
		match self {
			Token::Name(n) => Ok(n),
			_ => generror!(format!("cannot parse {self:?} as string")),
		}
	}
	fn error<S: Into<String>>(err: S) -> Error {
		let err: String = err.into();
		error!("tokenize error {err}");
		Error::Tokenize(err)
	}
	fn valid_name_char(c: char) -> bool {
		c.is_ascii_lowercase()
			|| c.is_ascii_uppercase()
			|| c.is_ascii_digit()
			|| c == '_' || c == '/'
			|| c == '.' || c == '?'
			|| c == '-' || c == '\''
	}
	fn post_proc(mut tokens: Vec<Token>) -> Vec<Token> {
		let mut ret = Vec::with_capacity(tokens.len());
		let mut paren = 0;
		let mut bracket = 0;
		let mut square = 0;
		while !tokens.is_empty() {
			let r = tokens.remove(0);
			match &r {
				Token::ParenOpen => paren += 1,
				Token::ParenClose => paren -= 1,
				Token::BracketOpen => bracket += 1,
				Token::BracketClose => bracket -= 1,
				Token::SquareOpen => square += 1,
				Token::SquareClose => square -= 1,
				Token::Type => {
					if paren > 0 || bracket > 0 || square > 0 {
						// We should never have a type specifier inside
						// function, structs or unions. If it is, we assume it's
						// an argument name
						ret.push(Token::Name(String::from("type")));
						continue;
					}
				}
				Token::Meta => {
					if let Some(x) = tokens.first() {
						if let Token::Name(n) = x {
							if n != "noextract" && n != "arches" {
								ret.push(Token::Name(String::from("meta")));
								continue;
							}
							// Was a correct meta token, we push it below
						}
					} else {
						ret.push(Token::Name(String::from("meta")));
						continue;
					}
				}
				_ => {}
			}
			ret.push(r);
		}
		ret
	}
	fn parse(s: String) -> Result<(Self, Option<String>)> {
		trace!("parse {s}");
		verify!(!s.is_empty(), UnexpectedToken);
		let mut ss = s.chars();
		let f = ss.next().unwrap();
		let rem: String = ss.collect();
		trace!("checking char {f:?}");
		trace!("rem {rem:?}");
		let n = match f {
			'(' => (Token::ParenOpen, Some(rem)),
			')' => (Token::ParenClose, Some(rem)),
			'[' => (Token::SquareOpen, Some(rem)),
			']' => (Token::SquareClose, Some(rem)),
			'{' => (Token::BracketOpen, Some(rem)),
			'}' => (Token::BracketClose, Some(rem)),
			':' => (Token::Colon, Some(rem)),
			'<' => (Token::CrocOpen, Some(rem)),
			'>' => (Token::CrocClose, Some(rem)),
			',' => (Token::Comma, Some(rem)),
			'=' => (Token::Equal, Some(rem)),
			'$' => (Token::Dollar, Some(rem)),
			'\'' => {
				let val = rem.chars().next();
				let nq = rem.chars().nth(1);
				if nq == Some('\'') {
					(Token::Char(val.unwrap()), Some(rem[2..].to_string()))
				} else {
					(Token::String(String::from("'")), Some(rem))
				}
			}
			'"' | '`' => {
				if let Some(idx) = rem.find(f) {
					let str = rem[..idx].to_string();
					let rem = rem[idx + 1..].to_string();
					(Token::String(str), Some(rem))
				} else {
					return Err(Self::error(format!(
						"Unable to find enclosing quote in {rem}"
					)));
				}
			}
			'\n' => (Token::Newline, Some(rem)),
			_ => {
				// rem.insert(0, f);
				let empty = None;
				match s.as_str() {
					"include" => (Token::Include, empty),
					"incdir" => (Token::Incdir, empty),
					"resource" => (Token::Resource, empty),
					"type" => (Token::Type, empty),
					"define" => (Token::Define, empty),
					"meta" => (Token::Meta, empty),
					_ => {
						let mut start = String::from("");
						start.push(f);

						let mut prem = String::from("");
						let mut ss = rem.chars();

						while let Some(c) = ss.next() {
							if Self::valid_name_char(c) {
								start.push(c)
							} else {
								prem.push(c);
								let ins: String = ss.collect();
								prem.push_str(&ins);
								break;
							}
						}
						trace!("start {start} | prem: '{prem}'");
						let ins = Token::Name(start);
						(ins, Some(prem))
					}
				}
			}
		};
		Ok(n)
	}
	fn quote_enclosed(s: &str, quote: char) -> bool {
		let chars = s.chars();
		let mut count = 0;

		for n in chars {
			if n == quote {
				count += 1;
			}
		}
		count % 2 == 0
	}
	fn parse_loop<S: Into<String>>(item: S, tokens: &mut Vec<Token>) -> Result<()> {
		let mut item: String = item.into();
		while !item.is_empty() {
			let (ins, rem) = Token::parse(item)?;
			tokens.push(ins);
			if let Some(n) = rem {
				item = n;
			} else {
				break;
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use test::Bencher;
	extern crate test;

	#[bench]
	fn bench_token1(b: &mut Bencher) {
		let s = r#"abcd = "hello", `world`, "!", "Hello World!""#;
		b.iter(|| Token::create_from_str(s).unwrap())
	}

	#[bench]
	fn bench_token0(b: &mut Bencher) {
		let s = r#"resource fd[int32]"#;
		b.iter(|| Token::create_from_str(s).unwrap())
	}

	#[bench]
	fn bench_token2(b: &mut Bencher) {
		let s = r#"
		# Some comment
		
		func$abcd(type int32, meta int64) fd
		
"#;
		b.iter(|| Token::create_from_str(s).unwrap())
	}

	#[test]
	fn tokens0() {
		let s = r#"resource fd[int32]: -1"#;
		let t = Token::create_from_str(s).unwrap();
		assert_eq!(
			t,
			vec![
				Token::Resource,
				Token::Name(String::from("fd")),
				Token::SquareOpen,
				Token::Name(String::from("int32")),
				Token::SquareClose,
				Token::Colon,
				Token::Name(String::from("-1")),
			]
		);
	}

	#[test]
	fn tokens1() {
		let s = r#"abcd = "hello", `world`, "!", "Hello World!", `acdb efgh`"#;
		let t = Token::create_from_str(s).unwrap();
		assert_eq!(
			t,
			vec![
				Token::Name(String::from("abcd")),
				Token::Equal,
				Token::String(String::from("hello")),
				Token::Comma,
				Token::String(String::from("world")),
				Token::Comma,
				Token::String(String::from("!")),
				Token::Comma,
				Token::String(String::from("Hello World!")),
				Token::Comma,
				Token::String(String::from("acdb efgh"))
			]
		);
	}

	#[test]
	fn tokens2() {
		// Check that extra newlines are preserved
		let s = r#"
# Some comment

func$abcd(type int32, meta int64) fd

"#;
		let t = Token::create_from_str(s).unwrap();
		assert_eq!(
			t,
			vec![
				Token::Newline,
				Token::Comment(String::from("# Some comment")),
				Token::Newline,
				Token::Newline,
				Token::Name(String::from("func")),
				Token::Dollar,
				Token::Name(String::from("abcd")),
				Token::ParenOpen,
				Token::Name(String::from("type")),
				Token::Name(String::from("int32")),
				Token::Comma,
				Token::Name(String::from("meta")),
				Token::Name(String::from("int64")),
				Token::ParenClose,
				Token::Name(String::from("fd")),
				Token::Newline,
				Token::Newline
			]
		);
	}
	#[test]
	fn tokens3() {
		let s = r#"const[' ', int8]"#;
		let t = Token::create_from_str(s).unwrap();
		assert_eq!(
			t,
			vec![
				Token::Name(String::from("const")),
				Token::SquareOpen,
				Token::Char(' '),
				Token::Comma,
				Token::Name(String::from("int8")),
				Token::SquareClose
			]
		);
	}

	#[test]
	fn bad_tokens0() {
		let s = r#"value = "asd", "qwert"#;
		let t = Token::create_from_str(s);
		assert!(t.is_err());
	}
}
