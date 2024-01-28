//! Parse Syzkaller syntax descriptions
//! [syzlang](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions_syntax.md)
//! into a more suitable format for analysis with Rust.
//!
//! Parsing is done in several steps:
//! 1. Tokenize into [token::Token]
//! 2. Parse into [parser::Parsed]
//!

#![feature(extract_if)]
#![feature(test)]

pub mod parser;
pub mod token;

/// All the different errors the crate can produce
#[derive(thiserror::Error, Debug)]
pub enum Error {
	/// Some arbitrary string describing the error in more detail
	#[error("Error: {0}")]
	Error(String),

	/// The string passed in was unexpected / invalid
	#[error("Invalid String: {0}")]
	InvalidString(String),

	/// Tokenize error, string contains more details
	#[error("Tokenize: {0}")]
	Tokenize(String),

	#[error("Unexpected token")]
	UnexpectedToken,

	#[error("Unexpected length")]
	UnexpectedLength,

	#[error("Unexpected value")]
	UnexpectedValue,

	#[error("Unsupported")]
	Unsupported,

	/// Parser error, string contains more details
	#[error("Parse: {0}")]
	Parser(String),

	#[error("serde_json")]
	Serde(#[from] serde_json::Error),

	#[error("IO")]
	Io(#[from] std::io::Error),

	#[error("Utf8")]
	Utf8(#[from] std::str::Utf8Error),
}
type Result<T> = std::result::Result<T, Error>;

macro_rules! errloc {
	() => {{
		let line = line!();
		let file = file!();
		format!("{file}:{line}")
	}};
}

pub(crate) use errloc;

macro_rules! parsererror {
	($msg:expr) => {{
		let errloc = crate::errloc!();
		let err = format!("{errloc}: error: {}", $msg);
		log::error!("{err}");
		Err(crate::Error::Parser(err))
	}};
}
pub(crate) use parsererror;

macro_rules! generror {
	($msg:expr, $log:ident) => {{
		let errloc = crate::errloc!();
		let err = format!("{errloc}: error: {}", $msg);
		log::$log!("{err}");
		Err(crate::Error::Error(err))
	}};
	($msg:expr) => {
		generror!($msg, error)
	};
}
pub(crate) use generror;

macro_rules! verify {
	($expr:expr, $error:ident) => {
		if (!($expr)) {
			let errloc = crate::errloc!();
			log::error!("{errloc}: expression failed: {}", stringify!($expr));
			return Err(crate::Error::$error);
		}
	};
}
pub(crate) use verify;

macro_rules! consume {
	($tokens:expr, $check:expr) => {{
		if $tokens.is_empty() {
			let errloc = crate::errloc!();
			let msg = format!("{errloc}: expected {:?}, but tokens is empty", $check);
			log::error!("{msg}");
			return Err(crate::Error::Parser(msg));
		}
		let t = $tokens.remove(0);
		if t != $check {
			let errloc = crate::errloc!();
			let msg = format!("{errloc}: expected {:?}, but got token {:?}", $check, t);
			log::error!("{msg}");
			return Err(crate::Error::Parser(msg));
		}
		t
	}};
	($tokens:expr) => {{
		if $tokens.is_empty() {
			let errloc = crate::errloc!();
			let msg = format!("{errloc}: expected new value but tokens is empty");
			log::error!("{msg}");
			return Err(crate::Error::Parser(msg));
		}
		$tokens.remove(0)
	}};
}
pub(crate) use consume;

macro_rules! check_empty {
	($tokens:expr) => {
		if !$tokens.is_empty() {
			let errloc = crate::errloc!();
			let msg = format!("{errloc}: expected tokens to be empty, left: {:?}", $tokens);
			log::error!("{msg}");
			return Err(crate::Error::Parser(msg));
		}
	};
}
pub(crate) use check_empty;

macro_rules! gen_get_ident {
	($name:ident) => {
		/// Get identifier for object
		pub fn identifier(&self) -> &Identifier {
			&self.$name
		}
	};
}
pub(crate) use gen_get_ident;

macro_rules! gen_get {
	($funcname:ident, $field:ident, $val:ty) => {
		pub fn $funcname(&self) -> &$val {
			&self.$field
		}
	};
	($field:ident, $val:ty) => {
		gen_get! { $field, $field, $val }
	};
}

pub(crate) use gen_get;

macro_rules! gen_get_mut {
	($funcname:ident, $field:ident, $val:ty) => {
		pub fn $funcname(&mut self) -> &mut $val {
			&mut self.$field
		}
	};
	($field:ident, $val:ty) => {
		gen_get_mut! { $field, $field, $val }
	};
}

pub(crate) use gen_get_mut;

macro_rules! gen_get_iter {
	($funcname:ident, $field:ident, $val:ty) => {
		pub fn $funcname(&self) -> std::slice::Iter<'_, $val> {
			self.$field.iter()
		}
	};
	($field:ident, $val:ty) => {
		gen_get_iter! { $field, $field, $val }
	};
}
pub(crate) use gen_get_iter;

macro_rules! gen_find_ident {
	($field:ident) => {
		/// Find vector entry with a matching [Identifier]
		pub fn find_ident<'a>(entries: &'a [Self], ident: &Identifier) -> Option<&'a Self> {
			for val in entries.iter() {
				if val.$field == *ident {
					return Some(val);
				}
			}
			None
		}
	};
	($field:ident, $val:ty) => {
		gen_get_iter! { $field, $field, $val }
	};
}
pub(crate) use gen_find_ident;

macro_rules! gen_get_ident_matches {
	($name:ident) => {
		/// Get identifier for object
		pub fn ident_matches(&self, name: &str) -> bool {
			self.$name.name == name
		}
	};
}
pub(crate) use gen_get_ident_matches;

macro_rules! gen_find_by_ident {
	($name:ident, $field:ident, $val:ty) => {
		pub fn $name(&self, ident: &Identifier) -> Option<&$val> {
			self.$field.iter().find(|&s| s.identifier() == ident)
		}
	};
}
pub(crate) use gen_find_by_ident;

macro_rules! gen_find_by_name {
	($name:ident, $field:ident, $val:ty) => {
		pub fn $name<I: Into<Identifier>>(&self, name: I) -> Option<&$val> {
			let ident: Identifier = name.into();
			self.$field.iter().find(|&s| s.identifier() == &ident)
		}
	};
}
pub(crate) use gen_find_by_name;

#[cfg(test)]
#[ctor::ctor]
fn global_test_setup() {
	env_logger::init();
}
