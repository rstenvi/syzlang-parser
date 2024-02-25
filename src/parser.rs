//! Parse tokens into valid objects

use crate::token::Token;
use crate::{
	check_empty, consume, gen_find_by_ident, gen_find_by_name, gen_find_ident, gen_get,
	gen_get_ident, gen_get_ident_matches, gen_get_iter, gen_get_mut, generror, parsererror, verify,
	Error, Result,
};

use log::{debug, error, trace, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::path::Path;
use std::str::FromStr;

trait Postproc {
	fn simplify(&mut self, idents: &HashMap<Identifier, IdentType>) -> Result<usize>;
	fn fill_in_aliases(&mut self, aliases: &[TypeAlias]) -> Result<usize>;
	fn fill_in_templates(&mut self, tmpls: &[TypeRaw]) -> Result<usize>;
}

/// Whether the argument is input, output or both (from perspective of caller)
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub enum Direction {
	In,
	Out,
	InOut,
}

impl Direction {
	pub fn matches(&self, other: &Self) -> bool {
		*self == *other || *self == Self::InOut || *other == Self::InOut
	}
}

impl FromStr for Direction {
	type Err = Error;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		match s {
			"in" => Ok(Self::In),
			"out" => Ok(Self::Out),
			"inout" => Ok(Self::InOut),
			_ => Err(Error::InvalidString(s.to_string())),
		}
	}
}

/// All the different architectures supported.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Arch {
	X86,
	X86_64,
	Aarch64,
	Aarch32,
	Mips64le,
	Ppc64le,
	Riscv64,
	S390x,
	Native,
}
impl Arch {
	pub fn all() -> Vec<Self> {
		vec![
			Arch::X86,
			Arch::X86_64,
			Arch::Aarch32,
			Arch::Aarch64,
			Arch::Mips64le,
			Arch::Ppc64le,
			Arch::Riscv64,
			Arch::S390x,
		]
	}
}

/// All the operating systems supported
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Os {
	Akaros,
	Darwin,
	Freebsd,
	Fuchsia,
	Linux,
	Netbsd,
	Openbsd,
	Trusty,
	Windows,
	All,
}
impl Os {
	pub fn all() -> Vec<Self> {
		vec![
			Self::Akaros,
			Self::Darwin,
			Self::Freebsd,
			Self::Fuchsia,
			Self::Linux,
			Self::Netbsd,
			Self::Openbsd,
			Self::Trusty,
			Self::Windows,
		]
	}
}

impl FromStr for Os {
	type Err = Error;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"akaros" => Ok(Self::Akaros),
			"darwin" => Ok(Self::Darwin),
			"freebsd" => Ok(Self::Freebsd),
			"fuchsia" => Ok(Self::Fuchsia),
			"linux" => Ok(Self::Linux),
			"netbsd" => Ok(Self::Netbsd),
			"openbsd" => Ok(Self::Openbsd),
			"trusty" => Ok(Self::Trusty),
			"windows" => Ok(Self::Windows),
			"all" => Ok(Self::All),
			_ => Err(Error::InvalidString(s.to_string())),
		}
	}
}

impl std::fmt::Display for Os {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Os::Akaros => "akaros",
			Os::Darwin => "darwin",
			Os::Freebsd => "freebsd",
			Os::Fuchsia => "fuchsia",
			Os::Linux => "linux",
			Os::Netbsd => "netbsd",
			Os::Openbsd => "openbsd",
			Os::Trusty => "trusty",
			Os::Windows => "windows",
			Os::All => "all",
		})
	}
}

impl FromStr for Arch {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self> {
		match s {
			"amd64" | "x86_64" => Ok(Arch::X86_64),
			"386" | "x86_real" | "x86_16" | "x86_32" => Ok(Arch::X86),
			"arm64" => Ok(Arch::Aarch64),
			"arm" => Ok(Arch::Aarch32),
			"mips64le" => Ok(Arch::Mips64le),
			"ppc64le" | "ppc64" => Ok(Arch::Ppc64le),
			"riscv64" => Ok(Arch::Riscv64),
			"s390x" => Ok(Arch::S390x),
			"target" => Ok(Arch::Native),
			_ => Err(Error::InvalidString(s.to_string())),
		}
	}
}

/// Arbitrary value for some option
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Value {
	/// Integer
	Int(i64),

	/// String that was enclosed in quotes
	String(String),

	/// Some identifier, can be known type or unknown reference to flag, etc.
	Ident(Identifier),

	/// Used when we see '???' in the source files
	Unknown,
}

impl Value {
	fn _parse_as_value(src: &str, base: u32) -> Result<Self> {
		log::debug!("as value {src} base {base}");
		if let Ok(v) = i64::from_str_radix(src, base) {
			Ok(Self::Int(v))
		} else if let Ok(v) = u64::from_str_radix(src, base) {
			if v & (1 << 63) != 0 {
				let rval = if v == i64::MIN as u64 {
					i64::MIN
				} else {
					let twos = -(v as i64) as u64;
					let twos = twos as i64;
					-twos
				};
				trace!("orig: {v:x} | twos {rval:x} {rval}");
				Ok(Self::Int(rval))
			} else {
				// This shouldn't be possible, I think
				panic!("unable to parse as i64, but able to parse as u64, but top-most bit not set {src} {base}");
			}
		} else if let Some(s) = src.strip_prefix("0x") {
			assert!(!s.starts_with("0x"));
			Self::_parse_as_value(s, 16)
		} else if base == 10 && src.starts_with('"') && src.ends_with('"') {
			let src = &src[1..src.len() - 1];
			Ok(Self::String(src.to_string()))
		} else {
			// Only give warning here because caller may try Value before
			// setting as Ident
			generror!(format!("Unable to parse {src}:{base} as Value"), warn)
		}
	}
	/// Try and parse a string as fixed value
	///
	/// ```
	/// use syzlang_parser::parser::Value;
	/// assert_eq!(Value::parse_as_value("0x10").unwrap(), Value::Int(16));
	/// assert_eq!(Value::parse_as_value(r#""abcd""#).unwrap(), Value::String(String::from("abcd")));
	/// ```
	pub fn parse_as_value(src: &str) -> Result<Self> {
		Self::_parse_as_value(src, 10)
	}
}

impl TryFrom<&Value> for i64 {
	type Error = Error;

	fn try_from(value: &Value) -> std::result::Result<Self, Self::Error> {
		if let Value::Int(n) = value {
			Ok(*n)
		} else {
			Err(Error::Error(format!("cannot parse {value:?} as int")))
		}
	}
}

impl TryFrom<Value> for serde_json::Value {
	type Error = Error;

	fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
		let v = &value;
		v.try_into()
	}
}

impl TryFrom<&Value> for serde_json::Value {
	type Error = Error;

	fn try_from(value: &Value) -> std::result::Result<Self, Self::Error> {
		let r = match value {
			Value::Int(v) => serde_json::to_value(*v)?,
			Value::String(v) => serde_json::to_value(v)?,
			Value::Ident(n) => {
				return generror!(format!("unable to load ident {n:?} as value"));
			}
			Value::Unknown => {
				return Err(Error::Error(String::from(
					"cannot parse Unknown to serde_json::Value",
				)))
			}
		};
		Ok(r)
	}
}

impl FromStr for Value {
	type Err = Error;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		if s == "???" {
			Ok(Value::Unknown)
		} else if let Ok(n) = Self::parse_as_value(s) {
			Ok(n)
		} else {
			let ident = Identifier::from_str(s)?;
			Ok(Value::Ident(ident))
		}
	}
}

impl std::fmt::Display for &Value {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Value::Int(_) => todo!(),
			Value::String(_) => todo!(),
			Value::Ident(n) => f.write_str(&n.safe_name()),
			Value::Unknown => todo!(),
		}
	}
}

impl TryFrom<&Token> for Value {
	type Error = Error;

	fn try_from(value: &Token) -> std::result::Result<Self, Self::Error> {
		match value {
			Token::Char(n) => Ok(Value::Int(*n as i64)),
			Token::String(n) => Ok(Value::String(n.clone())),
			Token::Name(n) => Value::from_str(n),
			_ => generror!(format!("value {value:?} not parsed")),
		}
	}
}

impl TryFrom<Token> for Value {
	type Error = Error;

	fn try_from(value: Token) -> std::result::Result<Self, Self::Error> {
		match value {
			Token::Char(n) => Ok(Value::Int(n as i64)),
			Token::String(n) => Ok(Value::String(n)),
			Token::Name(n) => Value::from_str(n.as_str()),
			_ => generror!(format!("value {value:?} not parsed")),
		}
	}
}

/// A named constant tied to one or more architectures
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Const {
	/// The name
	pub name: String,

	/// A value, which should be resolved
	pub value: Value,

	/// The architectures where this value is valid
	pub arch: Vec<Arch>,
}

impl Const {
	pub fn new<S: Into<String>>(name: S, value: Value, arch: Vec<Arch>) -> Self {
		Self {
			name: name.into(),
			value,
			arch,
		}
	}
	/// Create a new const for all defined architectures.
	pub fn new_allarch(name: String, value: Value) -> Self {
		let arch = Arch::all();
		Self { name, value, arch }
	}
	pub fn as_uint(&self) -> Result<u64> {
		match &self.value {
			Value::Int(a) => Ok(*a as u64),
			_ => Err(Error::UnexpectedValue),
		}
	}

	/// Get name of the constant
	pub fn name(&self) -> &str {
		&self.name
	}

	/// Get value of the constant
	pub fn value(&self) -> &Value {
		&self.value
	}

	/// Check if constant is valid for a given value
	pub fn is_for_arch(&self, arch: &Arch) -> bool {
		self.arch.contains(arch)
	}

	/// Iterate all the arches, the constant is valid for
	pub fn arches(&self) -> std::slice::Iter<'_, Arch> {
		self.arch.iter()
	}

	/// Parse all tokens into a vector of [Const] values.
	///
	/// * `tokens` - All tokens which should be parsed
	/// * `arches` - An optionally specified architecture, if it isn't contained in the tokens
	pub fn from_tokens(mut tokens: Vec<Token>, arches: Option<Arch>) -> Result<Vec<Self>> {
		debug!(
			"getting const from {} tokens | arches {arches:?}",
			tokens.len()
		);
		Statement::while_comments(&mut tokens)?;
		if tokens.is_empty() {
			return Ok(Vec::new());
		}

		let next = consume!(tokens);

		let mut defarches = if let Ok(n) = next.to_name() {
			if n == "arches" && matches!(consume!(tokens), Token::Equal) {
				let mut rem = Statement::until_newline(&mut tokens);
				let mut ret = Vec::new();

				debug!("tokens bef {rem:?}");
				let _ = rem.extract_if(|x| *x == Token::Comma).collect::<Vec<_>>();
				debug!("tokens aft {rem:?}");
				while !rem.is_empty() {
					let r = consume!(rem);
					let r = r.to_name()?;
					let a = Arch::from_str(r)?;
					ret.push(a);
				}
				ret
			} else {
				tokens.insert(0, next);
				Vec::new()
			}
		} else {
			tokens.insert(0, next);
			Vec::new()
		};

		if defarches.is_empty() {
			defarches = if let Some(n) = arches {
				vec![n]
			} else {
				Vec::new()
			};
		}
		debug!("defarches {defarches:?}");
		let mut consts = Vec::new();

		while !tokens.is_empty() {
			let next = consume!(tokens);
			trace!("next {next:?}");
			match next {
				Token::Newline => {}
				Token::Comment(_) => {}
				Token::Name(name) => {
					let mut arches = defarches.clone();
					let mut rem = Statement::until_newline(&mut tokens);
					let n = consume!(rem);
					assert!(matches!(n, Token::Equal));
					let mut fval = None;

					for parts in rem.split(|x| *x == Token::Comma) {
						if parts.is_empty() {
							continue;
						}
						let l = parts.len();
						if let Some(nvalue) = parts.last() {
							let nvalue: Value = nvalue.try_into()?;
							let mut narches = Vec::new();
							for arch in parts[..l - 1].iter() {
								if matches!(arch, Token::Colon) {
									continue;
								}
								let n = arch.to_name()?;
								let narch = Arch::from_str(n)?;
								let _ = arches.extract_if(|x| *x == narch).collect::<Vec<_>>();
								narches.push(narch);
							}
							if nvalue != Value::Unknown {
								if narches.is_empty() {
									fval = Some(nvalue);
								} else {
									let ins = Self {
										value: nvalue,
										name: name.clone(),
										arch: narches,
									};
									consts.push(ins);
								}
							}
						} else {
							error!("no elements, which indicate multiple successive commas");
							todo!();
						}
					}

					if let Some(value) = std::mem::take(&mut fval) {
						let ins = Self {
							value,
							name: name.clone(),
							arch: arches,
						};
						consts.push(ins);
					}
				}
				_ => {
					error!("unable to parse {next:?}");
					todo!()
				}
			}
		}
		Ok(consts)
	}
}

/// Wrapper around a vector of [Const] with some helper functions.
#[derive(Default, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Consts {
	pub consts: Vec<Const>,
}

impl Consts {
	pub fn new(consts: Vec<Const>) -> Self {
		Self { consts }
	}
	/// Try and resolve a system call number by name, like `write`
	pub fn find_sysno(&self, name: &str, arch: &Arch) -> Option<usize> {
		let name1 = format!("__NR_{name}");
		let name2 = format!("SYS_{name}");
		if let Some(n) = self
			.consts
			.iter()
			.position(|x| (x.name == name1 || x.name == name2) && x.arch.contains(arch))
		{
			if let Some(v) = self.consts.get(n) {
				if let Ok(q) = TryInto::<i64>::try_into(&v.value) {
					Some(q as usize)
				} else {
					None
				}
			} else {
				None
			}
		} else {
			None
		}
	}

	/// Iterate over all the consts
	pub fn consts(&self) -> std::slice::Iter<Const> {
		self.consts.iter()
	}

	/// Push new value without checking if this element is new
	pub fn push(&mut self, c: Const) {
		self.consts.push(c)
	}

	/// Find value based on name and architecture
	pub fn find_name_arch(&self, name: &str, arch: &Arch) -> Option<&Const> {
		// self.consts.iter().find(|&c| c.name == name && c.arch.contains(arch) )
		self.consts
			.iter()
			.find(|&c| c.name == name && c.is_for_arch(arch))
	}

	/// Architecture can be specified on the filename, like:
	/// `<name>_amd64.const`. This function tries to extract it.
	pub fn get_arch_from_path(file: &Path) -> Result<Option<Arch>> {
		let r = if let Some(name) = file.to_str() {
			let mut parts: Vec<&str> = name.split('.').collect();
			parts.pop(); // const
			if let Some(n) = parts.pop() {
				if n == "txt" {
					None
				} else if let Ok(arch) = Arch::from_str(n) {
					Some(arch)
				} else if let Some(last) = n.split('_').last() {
					let arch = Arch::from_str(last)?;
					debug!("using arch {arch:?}");
					Some(arch)
				} else {
					let m = format!("Unable to find arch in {n}");
					return generror!(m);
				}
			} else {
				let m = format!("Unable to get arch from {parts:?}");
				return generror!(m);
			}
		} else {
			let m = format!("unable to get str from path {file:?}");
			return generror!(m);
		};
		Ok(r)
	}

	/// Parse constants from file
	pub fn create_from_file(&mut self, p: &Path) -> Result<()> {
		debug!("parsing const file {p:?}");
		let arch = Consts::get_arch_from_path(p)?;
		let data = std::fs::read(p)?;
		let data = std::str::from_utf8(&data)?;
		let n = Self::create_from_str(data, arch)?;
		self.add_vec(n);
		Ok(())
	}

	/// Create constants from string
	pub fn create_from_str(s: &str, arch: Option<Arch>) -> Result<Vec<Const>> {
		let tokens = Token::create_from_str(s)?;
		let consts = Const::from_tokens(tokens, arch)?;
		Ok(consts)
	}

	/// Same as [Self::push], but only add if the element is unique
	pub fn add_if_new(&mut self, c: Const) -> bool {
		if let Some(idx) = self
			.consts
			.iter()
			.position(|x| x.name == c.name && x.value == c.value)
		{
			if let Some(x) = self.consts.get_mut(idx) {
				for arch in c.arch {
					if !x.arch.contains(&arch) {
						x.arch.push(arch);
						return true;
					}
				}
				false
			} else {
				panic!("Unable to get index we just retrieved");
			}
		} else {
			self.consts.push(c);
			true
		}
	}

	/// Add from a vector, uses [Self::add_if_new] on each element
	pub fn add_vec(&mut self, mut consts: Vec<Const>) -> usize {
		let mut ret = 0;
		while !consts.is_empty() {
			if self.add_if_new(consts.remove(0)) {
				ret += 1;
			}
		}
		ret
	}

	/// Remove all consts not relevant for the specified architecture.
	///
	/// Not necessary, but can be used to save memory.
	pub fn filter_arch(&mut self, arch: &Arch) {
		let _ = self
			.consts
			.extract_if(|x| !x.arch.contains(arch))
			.collect::<Vec<_>>();
	}
}

/// All the different basic types supported in Syzlang
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ArgType {
	#[serde(rename = "intptr")]
	Intptr,
	#[serde(rename = "int8")]
	Int8,
	#[serde(rename = "int16")]
	Int16,
	#[serde(rename = "int32")]
	Int32,
	#[serde(rename = "int64")]
	Int64,
	#[serde(rename = "bool")]
	Bool,
	#[serde(rename = "csum")]
	Csum,
	#[serde(rename = "int16be")]
	Int16be,
	#[serde(rename = "int32be")]
	Int32be,
	#[serde(rename = "int64be")]
	Int64be,
	#[serde(rename = "string")]
	String,
	#[serde(rename = "stringnoz")]
	StringNoz,
	#[serde(rename = "strconst")]
	StringConst,
	#[serde(rename = "len")]
	Len,
	#[serde(rename = "proc")]
	Proc,
	#[serde(rename = "glob")]
	Glob,
	#[serde(rename = "bitsize")]
	Bitsize,
	#[serde(rename = "bytesize")]
	Bytesize,
	#[serde(rename = "vma")]
	Vma,
	#[serde(rename = "vma64")]
	Vma64,
	#[serde(rename = "offsetof")]
	OffsetOf,
	#[serde(rename = "fmt")]
	Fmt,
	#[serde(rename = "ptr")]
	Ptr,
	#[serde(rename = "ptr64")]
	Ptr64,
	#[serde(rename = "flags")]
	Flags,
	#[serde(rename = "const")]
	Const,
	#[serde(rename = "text")]
	Text,
	#[serde(rename = "void")]
	Void,
	#[serde(rename = "array")]
	Array,
	#[serde(rename = "compressed_image")]
	CompressedImage,
	Ident(Identifier),
	Template(Identifier),
}

impl ArgType {
	pub fn refers_c_string(&self) -> bool {
		match self {
			Self::Ident(n) => n.name == "filename",
			Self::String | Self::StringConst => true,
			_ => false,
		}
	}
	pub fn is_filename(&self) -> bool {
		match self {
			Self::Ident(n) => n.name == "filename",
			_ => false,
		}
	}
}

impl std::fmt::Display for ArgType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let v: String = serde_json::to_string(self).unwrap();
		// Cut enclosing quotes
		f.write_str(&v[1..v.len() - 1])
	}
}

impl TryFrom<Value> for ArgType {
	type Error = Error;

	fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
		match value {
			Value::Ident(n) => Ok(ArgType::Ident(n)),
			_ => generror!(format!("unable to convert {value:?} to ArgType")),
		}
	}
}

impl FromStr for ArgType {
	type Err = Error;

	fn from_str(os: &str) -> std::result::Result<Self, Self::Err> {
		let s = format!(r#""{os}""#);
		if let Ok(r) = serde_json::from_str(&s) {
			Ok(r)
		} else {
			// This will happen for every single custom struct/union/resource/type
			debug!("No ArgType found, treating as ident '{os}'");
			let mut parts: Vec<String> = os.split('$').map(|x| x.to_string()).collect();
			let name = parts.remove(0);
			Ok(ArgType::Ident(Identifier::new(name, parts)))
		}
	}
}

impl ArgType {
	pub fn is_int(&self) -> bool {
		matches!(
			self,
			ArgType::Intptr | ArgType::Int8 |
			ArgType::Int16  | ArgType::Int32 |
			ArgType::Int64 /*| ArgType::Bool*/ | ArgType::Int16be |
			ArgType::Int32be | ArgType::Int64be
		)
	}
	pub fn is_ptr(&self) -> bool {
		matches!(self, ArgType::Ptr | ArgType::Ptr64)
	}
	pub fn is_vma(&self) -> bool {
		matches!(self, ArgType::Vma | ArgType::Vma64)
	}
	pub fn is_array(&self) -> bool {
		matches!(self, ArgType::Array)
	}
	pub fn bytes_as_int(&self, bytes: &[u8]) -> Result<serde_json::Number> {
		let v = match self {
			ArgType::Intptr => isize::from_ne_bytes(bytes.try_into().expect("")).into(),
			ArgType::Int64 => i64::from_ne_bytes(bytes.try_into().expect("")).into(),
			ArgType::Int32 => i32::from_ne_bytes(bytes.try_into().expect("")).into(),
			ArgType::Int16 => i16::from_ne_bytes(bytes.try_into().expect("")).into(),
			ArgType::Int8 => i8::from_ne_bytes(bytes.try_into().expect("")).into(),
			ArgType::Int64be => i64::from_be_bytes(bytes.try_into().expect("")).into(),
			ArgType::Int32be => i32::from_be_bytes(bytes.try_into().expect("")).into(),
			ArgType::Int16be => i16::from_be_bytes(bytes.try_into().expect("")).into(),
			_ => return Err(Error::Unsupported),
		};
		Ok(v)
	}
	pub fn matches_name(&self, name: &str) -> bool {
		if let Self::Ident(n) = self {
			n.subname.is_empty() && n.name == name
		} else {
			false
		}
	}
	pub fn arg_size(&self, ptrsize: usize) -> Result<usize> {
		match self {
			ArgType::Intptr => Ok(ptrsize),
			ArgType::Ptr => Ok(ptrsize),
			ArgType::Ptr64 => Ok(8),
			ArgType::Vma => Ok(ptrsize),
			ArgType::Vma64 => Ok(8),
			ArgType::Int8 => Ok(1),
			ArgType::Int16 => Ok(2),
			ArgType::Int32 => Ok(4),
			ArgType::Int64 => Ok(8),
			ArgType::Bool => Ok(1),
			ArgType::Int16be => Ok(2),
			ArgType::Int32be => Ok(4),
			ArgType::Int64be => Ok(8),
			_ => Err(Error::Unsupported),
		}
	}
	#[cfg(feature = "unstable")]
	pub fn num_bytes(&self, target: &dyn Target) -> Result<usize> {
		match self {
			ArgType::Intptr => Ok(target.target_size()),
			ArgType::Ptr => Ok(target.target_size()),
			ArgType::Ptr64 => Ok(8),
			ArgType::Vma => Ok(target.target_size()),
			ArgType::Vma64 => Ok(8),
			ArgType::Int8 => Ok(1),
			ArgType::Int16 => Ok(2),
			ArgType::Int32 => Ok(4),
			ArgType::Int64 => Ok(8),
			ArgType::Bool => Ok(1),
			ArgType::Int16be => Ok(2),
			ArgType::Int32be => Ok(4),
			ArgType::Int64be => Ok(8),
			_ => todo!(),
		}
	}
	pub fn big_endian(&self) -> Result<bool> {
		if self.is_int() || self.is_ptr() || self.is_vma() {
			Ok(matches!(
				self,
				ArgType::Int16be | ArgType::Int32be | ArgType::Int64be
			))
		} else {
			Err(Error::Unsupported)
		}
	}
	#[cfg(feature = "unstable")]
	pub fn little_endian(&self) -> Result<bool> {
		Ok(!self.big_endian()?)
	}
}

/// Optional arguments to a field in a struct or union.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FieldOpt {
	Dir(Direction),
	OutOverlay,
	Opt,
}

impl FieldOpt {
	pub fn from_tokens(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		while !tokens.is_empty() {
			let t = consume!(tokens);
			match t {
				Token::Name(n) => {
					if let Ok(dir) = Direction::from_str(n.as_str()) {
						ret.push(Self::Dir(dir));
					} else if n == "out_overlay" {
						ret.push(Self::OutOverlay);
					} else {
						error!("no parsed {n}");
						todo!();
					}
				}
				_ => todo!(),
			}
		}
		Ok(ret)
	}
}

/// Attributes to struct or union
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum StructAttr {
	Packed,
	Varlen,
	Align(Value),
	Size(Value),
}

impl StructAttr {
	fn from_tokens(tokens: Vec<Token>) -> Result<Vec<Self>> {
		trace!("tokens {tokens:?}");
		let mut ret = Vec::new();
		for part in tokens.split(|x| *x == Token::Comma) {
			let mut part = part.to_vec();
			let token = consume!(part);
			let ins = StructAttr::from_token(token, part)?;
			ret.push(ins);
		}
		Ok(ret)
	}
	fn from_token(token: Token, mut tokens: Vec<Token>) -> Result<Self> {
		match token {
			Token::Name(n) => match n.as_str() {
				"varlen" => {
					assert!(tokens.is_empty());
					Ok(Self::Varlen)
				}
				"packed" => {
					assert!(tokens.is_empty());
					Ok(Self::Packed)
				}
				"align" | "size" => {
					consume!(tokens, Token::SquareOpen);
					let v: Value = consume!(tokens).try_into()?;
					consume!(tokens, Token::SquareClose);
					check_empty!(tokens);
					Ok(if n == "align" {
						Self::Align(v)
					} else {
						Self::Size(v)
					})
				}
				_ => todo!(),
			},
			_ => {
				error!("token {token:?} is unknown as struct attr");
				todo!();
			}
		}
	}
}

/// All the different options we can specify on an argument type
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ArgOpt {
	Dir(Direction),
	StructAttr(Vec<StructAttr>),
	FieldOpt(Vec<FieldOpt>),
	Fmt(usize),
	Csum(String),
	CsumOf(String),

	// Argument is optional
	Opt,
	Len(Value, Value),
	FullArg(Box<Argument>),
	Value(Value),
	Bits(Value),
	Ident(Identifier),
	SubIdent(Vec<Identifier>),
	Range(Value, Value, Value),

	/// Series of tokens not yet parsed. Hapens when we have type templates.
	Tokens(Vec<Token>),
	Arch(Arch),
	ProcOpt(Value, Value),
}

// macro_rules! find_entry {
//     ($name:ident, $entry:ident, $value:ty) => {
//         #[allow(unused)]
//         pub(crate) fn $name(opts: &[ArgOpt]) -> Option<&$value> {
//             for opt in opts.iter() {
//                 if let ArgOpt::$entry(n) = opt {
//                     return Some(n);
//                 }
//             }
//             None
//         }
//     };
// }

impl ArgOpt {
	fn direction(opts: &[Self], def: &Direction) -> Direction {
		for opt in opts.iter() {
			if let ArgOpt::Dir(n) = opt {
				return *n;
			}
		}
		*def
	}
	pub fn same_direction(opts: &[Self], curr: &Direction) -> bool {
		for opt in opts.iter() {
			if let ArgOpt::Dir(n) = opt {
				return n == curr || *n == Direction::InOut;
			}
		}
		*curr == Direction::In
	}
	pub fn get_subarg(opts: &[Self]) -> Option<&Argument> {
		for opt in opts.iter() {
			if let ArgOpt::FullArg(n) = opt {
				return Some(n);
			}
		}
		None
	}

	// find_entry! { find_arg, Arg, ArgType }

	// pub(crate) fn filter_struct_attr(opts: &[Self]) -> Option<Vec<StructAttr>> {
	// 	for opt in opts.iter() {
	// 		if let Self::StructAttr(n) = opt {
	// 			return Some(n.clone());
	// 		}
	// 	}
	// 	None
	// }
	// pub(crate) fn filter_field_opt(opts: &[Self]) -> Option<Vec<FieldOpt>> {
	// 	for opt in opts.iter() {
	// 		if let Self::FieldOpt(n) = opt {
	// 			return Some(n.clone());
	// 		}
	// 	}
	// 	None
	// }

	// pub(crate) fn into_ident(self) -> Result<String> {
	// 	match self {
	// 		ArgOpt::Ident(n) => Ok(n.unique_name()),
	// 		ArgOpt::SubIdent(n) => {
	// 			let parts: Vec<String> = n.iter().map(|x| { x.unique_name() }).collect();
	// 			let s = parts.join(":");
	// 			Ok(s)
	// 		},
	// 		_ => {
	// 			error!("Unable to parse {self:?} as ident");
	// 			todo!();
	// 		},
	// 	}
	// }
	fn simplify(opts: &mut Vec<Self>, at: &IdentType, argname: &Identifier) -> Result<usize> {
		let mut ret = 0;
		match at {
			IdentType::Resource | IdentType::Struct | IdentType::Union | IdentType::Flag => {
				let tokens = Self::remove_tokens(opts);
				for tokens in tokens.into_iter() {
					for token in tokens.into_iter() {
						match &token {
							Token::Name(n) => {
								if n == "opt" {
									opts.push(ArgOpt::Opt);
									ret += 1;
								} else {
									error!("Don't know how to simplify {n}");
									todo!();
								}
							}
							_ => {
								error!("token {token:?}");
								todo!();
							}
						}
					}
				}
			}
			IdentType::Template | IdentType::Alias => {
				if argname.name == "fileoff" && opts.is_empty() {
					opts.push(ArgOpt::Tokens(vec![Token::Name("int32".to_string())]));
					ret += 1;
				}
			}
			IdentType::Function => todo!(),
		}
		Ok(ret)
	}
	fn remove_tokens(opts: &mut Vec<Self>) -> Vec<Vec<Token>> {
		let rem: Vec<Vec<Token>> = opts
			.extract_if(|x| matches!(x, ArgOpt::Tokens(_)))
			.map(|x| {
				if let ArgOpt::Tokens(n) = x {
					n
				} else {
					panic!("");
				}
			})
			.collect();
		rem
	}

	fn from_tokens_const(tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		for (i, part) in tokens.split(|x| *x == Token::Comma).enumerate() {
			let mut part = part.to_vec();

			if i == 0 {
				let r = consume!(part);
				check_empty!(part);
				let v: Value = r.try_into()?;
				ret.push(Self::Value(v));
			} else if i == 1 {
				let r = consume!(part);

				let a = Self::parse_argtype(r)?;
				let extra = Self::parse_arg_opts(&a, &mut part)?;
				let inarg = Argument::new_fake(a, extra);
				ret.push(Self::FullArg(Box::new(inarg)));
				assert!(part.is_empty());
			} else {
				todo!();
			}
		}
		Ok(ret)
	}
	fn parse_direction(token: Token) -> Result<Self> {
		match token {
			Token::Name(n) => match n.as_str() {
				"in" => Ok(ArgOpt::Dir(Direction::In)),
				"out" => Ok(ArgOpt::Dir(Direction::Out)),
				"inout" => Ok(ArgOpt::Dir(Direction::InOut)),
				_ => Ok(Self::Ident(Identifier::new(n, vec![]))),
			},
			_ => generror!(format!("Unable to parse {token:?} as direction")),
		}
	}
	#[cfg(feature = "unstable")]
	fn get_argtype_or(opts: &[Self], def: ArgType) -> ArgType {
		for opt in opts.iter() {
			if let Self::FullArg(a) = opt {
				return a.argtype.clone();
			}
		}
		def
	}
	fn parse_argtype(token: Token) -> Result<ArgType> {
		match token {
			Token::Name(n) => {
				let a = ArgType::from_str(n.as_str())?;
				Ok(a)
			}
			_ => generror!(format!("Unable to parse {token:?} as argtype")),
		}
	}
	fn parse_str(token: Token) -> Result<String> {
		match token {
			Token::Char(n) => Ok(format!("{n}")),
			Token::String(n) => Ok(n),
			Token::Name(n) => Ok(n),
			_ => generror!(format!("Unable to parse {token:?} as str")),
		}
	}
	fn parse_arg_opts(a: &ArgType, tokens: &mut Vec<Token>) -> Result<Vec<Self>> {
		trace!("arg opts {tokens:?}");
		let mut ret = Vec::new();
		if !tokens.is_empty() && a.is_int() {
			consume!(tokens, Token::Colon);
			let v: Value = consume!(tokens).try_into()?;
			ret.push(Self::Bits(v));
		}
		Ok(ret)
	}
	fn from_tokens_str(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		let rem = consume!(tokens);
		let v: Value = rem.try_into()?;
		ret.push(Self::Value(v));
		trace!("rem {tokens:?}");
		if let Some(Token::Comma) = tokens.first() {
			consume!(tokens, Token::Comma);
			let v: Value = consume!(tokens).try_into()?;
			ret.push(Self::Value(v));
		}
		trace!("rem {tokens:?} | got {ret:?}");
		assert!(tokens.is_empty());
		Ok(ret)
	}
	fn _name_and_utype(tokens: &mut Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();

		let name = Statement::parse_nameid(tokens)?;
		trace!("found name {name:?}");
		let mut namepushed = false;

		while !tokens.is_empty() {
			trace!("rem {tokens:?}");
			let rem = consume!(tokens);
			if rem == Token::Colon {
				let sn = Statement::parse_nameid(tokens)?;
				let mut subnames = vec![name.clone(), sn];

				while let Some(Token::Colon) = tokens.first() {
					consume!(tokens); // remove :
					let sn = Statement::parse_nameid(tokens)?;
					subnames.push(sn);
				}
				ret.push(Self::SubIdent(subnames));
				namepushed = true;
			} else if rem == Token::Comma {
				let a = Statement::parse_nameid(tokens)?;
				let a = a.unique_name();
				let a = ArgType::from_str(&a)?;
				let extra = Self::parse_arg_opts(&a, tokens)?;
				let inarg = Argument::new_fake(a, extra);
				ret.push(Self::FullArg(Box::new(inarg)));
			} else {
				panic!("unknown follow {rem:?} {tokens:?} {ret:?}");
			}
		}
		if !namepushed {
			ret.insert(0, Self::Ident(name));
		}

		Ok(ret)
	}
	fn from_tokens_flags(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let ret = Self::_name_and_utype(&mut tokens)?;
		trace!("tokens {tokens:?}");
		assert!(tokens.is_empty());
		Ok(ret)
	}
	fn from_tokens_len(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let ret = Self::_name_and_utype(&mut tokens)?;
		assert!(tokens.is_empty());
		Ok(ret)
	}
	fn from_tokens_array(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		let atype = Statement::parse_nameid(&mut tokens)?.unique_name();
		let atype = ArgType::from_str(&atype)?;

		if let Some(Token::SquareOpen) = tokens.first() {
			let sidx = Statement::find_stop(&Token::SquareOpen, &tokens).unwrap();
			let rem = tokens.drain(0..=sidx).collect();
			let subopts = Self::from_tokens(rem, &atype)?;
			let inarg = Argument::new_fake(atype, subopts);
			let ins = Self::FullArg(Box::new(inarg));
			ret.push(ins);
		} else {
			let inarg = Argument::new_fake(atype, vec![]);
			ret.push(Self::FullArg(Box::new(inarg)))
		}

		if !tokens.is_empty() {
			consume!(tokens, Token::Comma);
			let from: Value = consume!(tokens).try_into()?;
			let to = if !tokens.is_empty() {
				consume!(tokens, Token::Colon);
				let to: Value = consume!(tokens).try_into()?;
				to
			} else {
				Value::Unknown
			};
			ret.push(Self::Len(from, to));
		}
		trace!("rem {tokens:?}");
		assert!(tokens.is_empty());
		Ok(ret)
	}
	fn from_tokens_ptr(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		let dir = Self::parse_direction(consume!(tokens))?;
		ret.push(dir);
		consume!(tokens, Token::Comma);
		let atype = Statement::parse_nameid(&mut tokens)?.unique_name();
		let atype = ArgType::from_str(&atype)?;
		ret.push(Self::FullArg(Box::new(Argument::new_fake(
			atype.clone(),
			vec![],
		))));
		while let Some(n) = tokens.first() {
			match n {
				Token::Comma => {
					consume!(tokens, Token::Comma);
				}
				Token::SquareOpen => {
					// We create new argument, so pop what we pushed earlier
					assert!(matches!(ret.pop().unwrap(), Self::FullArg(_)));
					let sidx = Statement::find_stop(n, &tokens).unwrap();
					let rem = tokens.drain(0..=sidx).collect();
					let a = atype.clone();
					let subopts = Self::from_tokens(rem, &a)?;
					let inarg = Argument::new_fake(a, subopts);
					let ins = Self::FullArg(Box::new(inarg));
					ret.push(ins);
				}
				Token::Name(n) => match n.as_str() {
					"opt" => {
						consume!(tokens);
						ret.push(Self::Opt)
					}
					_ => todo!(),
				},
				_ => {
					error!("remaining {tokens:?}");
					todo!()
				}
			}
		}
		Ok(ret)
	}
	fn from_tokens_generic(tokens: Vec<Token>) -> Result<Vec<Self>> {
		trace!("generic {tokens:?}");
		let ret = vec![Self::Tokens(tokens)];
		Ok(ret)
	}
	fn from_tokens_offsetof(tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		for (i, part) in tokens.split(|x| *x == Token::Comma).enumerate() {
			let mut part = part.to_vec();
			if i == 0 {
				let mut name = Vec::new();
				while !part.is_empty() {
					let t = consume!(part);
					let s = Self::parse_str(t)?;
					name.push(Identifier::new(s, vec![]));

					if !part.is_empty() {
						consume!(part, Token::Colon);
					}
				}
				ret.push(Self::SubIdent(name));
			} else if i == 1 {
				let t = consume!(part);
				check_empty!(part);
				let a = Self::parse_argtype(t)?;
				let inarg = Argument::new_fake(a, vec![]);
				ret.push(Self::FullArg(Box::new(inarg)));
			} else {
				todo!();
			}
		}
		Ok(ret)
	}
	fn from_tokens_int(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		while !tokens.is_empty() {
			let rem = consume!(tokens);
			if rem == Token::Name(String::from("opt")) {
				ret.push(Self::Opt);
			} else {
				let start: Value = rem.try_into()?;
				consume!(tokens, Token::Colon);
				let stop: Value = consume!(tokens).try_into()?;
				let align = if !tokens.is_empty() {
					consume!(tokens, Token::Comma);
					let align: Value = consume!(tokens).try_into()?;
					align
				} else {
					Value::Unknown
				};
				let ins = Self::Range(start, stop, align);
				ret.push(ins);
			}
		}
		Ok(ret)
	}
	fn parse_text_arch(t: Token) -> Result<Arch> {
		let n = Self::parse_str(t)?;
		Arch::from_str(n.as_str())
	}
	fn from_tokens_vma(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		let val: Value = consume!(tokens).try_into()?;
		ret.push(Self::Value(val));
		Ok(ret)
	}
	fn from_tokens_text(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		let arch = Self::parse_text_arch(consume!(tokens))?;
		ret.push(Self::Arch(arch));
		Ok(ret)
	}
	fn from_tokens_glob(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		let pattern = Self::parse_str(consume!(tokens))?;
		ret.push(Self::Value(Value::String(pattern)));
		assert!(tokens.is_empty());
		Ok(ret)
	}
	fn from_tokens_proc(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		let start: Value = consume!(tokens).try_into()?;
		consume!(tokens, Token::Comma);
		let perproc: Value = consume!(tokens).try_into()?;
		ret.push(Self::ProcOpt(start, perproc));

		if let Some(Token::Comma) = tokens.first() {
			consume!(tokens, Token::Comma);
			let atype = Self::parse_argtype(consume!(tokens))?;
			let inarg = Argument::new_fake(atype, vec![]);
			ret.push(Self::FullArg(Box::new(inarg)));
		}
		assert!(tokens.is_empty());
		Ok(ret)
	}
	fn from_tokens_fmt(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		let val = Self::parse_str(consume!(tokens))?;
		let fmt = match val.as_str() {
			"hex" => Self::Fmt(16),
			"oct" => Self::Fmt(8),
			"dec" => Self::Fmt(10),
			_ => todo!(),
		};
		ret.push(fmt);
		if let Some(Token::Comma) = tokens.first() {
			consume!(tokens, Token::Comma);
			trace!("rem {tokens:?}");
			let r = consume!(tokens);
			let a = Self::parse_argtype(r)?;
			let ins = if let Some(Token::SquareOpen) = tokens.first() {
				let lidx = Statement::find_stop(&Token::SquareOpen, &tokens).unwrap();
				let rem = tokens.drain(0..=lidx).collect();
				let extra = Self::from_tokens(rem, &a)?;
				let inarg = Argument::new_fake(a, extra);
				Self::FullArg(Box::new(inarg))
			} else {
				let inarg = Argument::new_fake(a, vec![]);
				Self::FullArg(Box::new(inarg))
			};
			ret.push(ins);
		}
		assert!(tokens.is_empty());
		Ok(ret)
	}
	fn from_tokens_csum(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let first = Self::parse_str(consume!(tokens))?;
		consume!(tokens, Token::Comma);
		let mut sumtype = Self::parse_str(consume!(tokens))?;
		consume!(tokens, Token::Comma);
		if sumtype == "pseudo" {
			let other = Self::parse_str(consume!(tokens))?;
			consume!(tokens, Token::Comma);
			sumtype.push(':');
			sumtype.push_str(other.as_str());
		}

		let argtype = Self::parse_argtype(consume!(tokens))?;
		verify!(tokens.is_empty(), UnexpectedToken);
		let inarg = Argument::new_fake(argtype, vec![]);
		let ret = vec![
			ArgOpt::CsumOf(first),
			ArgOpt::Csum(sumtype),
			ArgOpt::FullArg(Box::new(inarg)),
		];
		Ok(ret)
	}
	pub fn from_tokens(mut tokens: Vec<Token>, utype: &ArgType) -> Result<Vec<Self>> {
		trace!("as opts {tokens:?} utype {utype:?}");
		if tokens.is_empty() {
			return Ok(Vec::new());
		}

		let lidx = Statement::find_stop(&Token::SquareOpen, &tokens).unwrap();
		let mut ntokens: Vec<Token> = tokens.drain(0..=lidx).collect();

		consume!(ntokens, Token::SquareOpen);

		let r = ntokens.pop().unwrap();
		assert_eq!(r, Token::SquareClose);
		let mut ret = match utype {
			ArgType::Const => Self::from_tokens_const(ntokens),
			ArgType::Ptr | ArgType::Ptr64 => Self::from_tokens_ptr(ntokens),
			ArgType::String | ArgType::StringNoz => Self::from_tokens_str(ntokens),
			ArgType::Flags => Self::from_tokens_flags(ntokens),
			ArgType::Array => Self::from_tokens_array(ntokens),
			ArgType::Csum => Self::from_tokens_csum(ntokens),
			ArgType::Len | ArgType::Bitsize | ArgType::Bytesize => Self::from_tokens_len(ntokens),
			ArgType::Ident(_n) => Self::from_tokens_generic(ntokens),

			ArgType::Void => {
				let r = FieldOpt::from_tokens(ntokens)?;
				Ok(vec![ArgOpt::FieldOpt(r)])
			}
			ArgType::OffsetOf => Self::from_tokens_offsetof(ntokens),
			ArgType::Fmt => Self::from_tokens_fmt(ntokens),
			ArgType::Vma | ArgType::Vma64 => Self::from_tokens_vma(ntokens),
			ArgType::Text => Self::from_tokens_text(ntokens),
			ArgType::Proc => Self::from_tokens_proc(ntokens),
			ArgType::Glob => Self::from_tokens_glob(ntokens),
			ArgType::Int64
			| ArgType::Int32
			| ArgType::Int16
			| ArgType::Int8
			| ArgType::Intptr
			| ArgType::Int64be
			| ArgType::Int32be
			| ArgType::Int16be => Self::from_tokens_int(ntokens),
			_ => todo!(),
		}?;
		if let Some(Token::ParenOpen) = tokens.first() {
			let lidx = Statement::find_stop(&Token::ParenOpen, &tokens).unwrap();
			let mut ntokens: Vec<Token> = tokens.drain(0..=lidx).collect();
			consume!(ntokens, Token::ParenOpen);
			assert_eq!(ntokens.pop(), Some(Token::ParenClose));
			let n = consume!(ntokens);
			let dir = Self::parse_direction(n)?;
			ret.push(dir);
			trace!("rem {ntokens:?}");
			assert!(ntokens.is_empty());
		}
		Ok(ret)
	}
}

macro_rules! try_from_argopt {
	($enum:ident, $t:ident) => {
		impl TryFrom<ArgOpt> for $t {
			type Error = Error;

			fn try_from(value: ArgOpt) -> std::result::Result<Self, Self::Error> {
				match value {
					ArgOpt::$enum(v) => Ok(v),
					_ => {
						generror!(format!("unable to parse {value:?} to Value"))
					}
				}
			}
		}
	};
}

try_from_argopt! { Value, Value }
try_from_argopt! { Arch, Arch }
try_from_argopt! { Dir, Direction }
try_from_argopt! { Ident, Identifier }
// try_from_argopt! { Arg, ArgType }

/// Information about what a custom named entity refers to
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ArgIdent {
	#[default]
	Unknown,
	Resource(String, ArgType),
	Union(String),
	Struct(String),
	Alias(Identifier),
	Template(Statement),
}

/// Incoming or outgoing named argument
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Argument {
	pub name: Identifier,
	pub argtype: ArgType,
	pub opts: Vec<ArgOpt>,
	aident: Option<ArgIdent>,
	sourceidents: Vec<Identifier>,
}
impl Argument {
	/// Construct a "fake" argument, which is essentially just an argument with
	/// empty name and no options. Can be used for return values when we need to
	/// convert them.
	pub fn new_fake(argtype: ArgType, opts: Vec<ArgOpt>) -> Self {
		Self {
			name: Identifier::default(),
			argtype,
			opts,
			aident: None,
			sourceidents: Vec::new(),
		}
	}
	pub fn new<S: Into<String>, T: Into<String>>(name: S, argtype: T, opts: Vec<ArgOpt>) -> Self {
		let argtype: String = argtype.into();
		let name: String = name.into();
		let name = Identifier::new(name, vec![]);
		let argtype = ArgType::from_str(&argtype).unwrap();
		Self {
			name,
			argtype,
			opts,
			aident: None,
			sourceidents: Vec::new(),
		}
	}
	pub fn is_ident(&self) -> bool {
		matches!(self.argtype, ArgType::Ident(_))
	}

	#[cfg(feature = "unstable")]
	fn read_from_argtype_basic(
		atype: &ArgType,
		ptr: u64,
		force_indirect: bool,
		_parsed: &Parsed,
		target: &dyn Target,
	) -> Result<u64> {
		match atype {
			ArgType::Intptr
			| ArgType::Int8
			| ArgType::Int16
			| ArgType::Int32
			| ArgType::Int64
			| ArgType::Bool
			| ArgType::Int16be
			| ArgType::Int32be
			| ArgType::Int64be
			| ArgType::Ptr
			| ArgType::Ptr64
			| ArgType::Vma
			| ArgType::Vma64 => {
				let sz = atype.num_bytes(target)?;
				let convert = atype.big_endian()? != target.big_endian();
				let val = if force_indirect {
					let mut data = Vec::with_capacity(sz);
					target.read_bytes(ptr, &mut data)?;
					let mut buf = bytebuffer::ByteBuffer::from(data);
					match sz {
						1 => buf.read_u8()? as u64,
						2 => buf.read_u16()? as u64,
						4 => buf.read_u32()? as u64,
						8 => buf.read_u64()?,
						_ => todo!(),
					}
				} else {
					ptr
				};
				let val = if convert {
					todo!();
				} else {
					val
				};
				Ok(val)
			}
			_ => todo!(),
		}
	}
	#[cfg(feature = "unstable")]
	fn find_length(&self, idents: &Vec<Identifier>, actions: &[Action]) -> Result<Option<usize>> {
		for (i, action) in actions.iter().enumerate() {
			let Action::SetLen(_val, ident, _lt) = action;
			debug!("checking if {ident:?} == {:?} | {idents:?}", self.name);

			// TODO: Probably want to do a more thorough check
			let ismatch = if let Some(oid) = idents.first() {
				ident == oid
			} else {
				*ident == self.name
			};
			if ismatch {
				debug!("found length {i}");
				return Ok(Some(i));
			}
		}
		Ok(None)
	}
	#[cfg(feature = "unstable")]
	pub fn read_from(
		&self,
		ptr: u64,
		force_indirect: bool,
		dir: &Direction,
		parsed: &Parsed,
		target: &dyn Target,
		actions: &mut Vec<Action>,
	) -> Result<(serde_json::Value, usize)> {
		let mut idents = Vec::new();
		let r = self.read_from_int(
			ptr,
			force_indirect,
			dir,
			parsed,
			target,
			actions,
			&mut idents,
		)?;
		assert!(idents.is_empty());
		Ok(r)
	}
	#[cfg(feature = "unstable")]
	#[allow(clippy::too_many_arguments)]
	fn read_from_int(
		&self,
		ptr: u64,
		force_indirect: bool,
		dir: &Direction,
		parsed: &Parsed,
		target: &dyn Target,
		actions: &mut Vec<Action>,
		idents: &mut Vec<Identifier>,
	) -> Result<(serde_json::Value, usize)> {
		// TODO: This is not calculated correctly It only makes sense to use it
		// if we are indirect, but what about when we have multiple
		// indirections? What value should be returned?

		use serde_json::json;
		let mut bytes_read = 0;
		debug!("reading {:?} | {:?}", self.argtype, self.name);
		let ret = match &self.argtype {
			ArgType::Intptr
			| ArgType::Int8
			| ArgType::Int16
			| ArgType::Int32
			| ArgType::Int64
			| ArgType::Bool
			| ArgType::Int16be
			| ArgType::Int32be
			| ArgType::Int64be
			| ArgType::Vma
			| ArgType::Vma64 => {
				let r = Self::read_from_argtype_basic(
					&self.argtype,
					ptr,
					force_indirect,
					parsed,
					target,
				)?;
				let key = self.argtype.to_string();
				json!({key: r})
			}

			ArgType::String | ArgType::StringConst => {
				let s = target.read_c_string(ptr)?;
				serde_json::to_value(s)?
			}
			ArgType::StringNoz | ArgType::Array => {
				debug!("parsing array");
				let itemsz = match &self.argtype {
					ArgType::StringNoz => 1,
					ArgType::Array => {
						if let Some(sub) = ArgOpt::get_subarg(&self.opts) {
							if sub.argtype.is_int() {
								sub.argtype.num_bytes(target)?
							} else {
								warn!("array of unknown underlying size, cannot process");
								return Err(Error::Unsupported);
							}
						} else {
							error!("Have array, but don't know of what???");
							return Err(Error::Unsupported);
						}
					}
					_ => panic!("impossible"),
				};
				if let Some(idx) = self.find_length(idents, actions)? {
					let Action::SetLen(val, _b, lt) = actions.remove(idx);
					let len: usize = serde_json::from_value(val)?;
					let fsize = match lt {
						LenType::Len => len * itemsz,
						LenType::Bytes => len,
						LenType::Bits => len / 8,
						LenType::Offset => len,
					};
					let mut data = Vec::with_capacity(fsize);
					target.read_bytes(ptr, &mut data)?;

					// TODO: Should parse it properly
					match &self.argtype {
						ArgType::Array => json!({"array": data}),
						ArgType::StringNoz => json!({"string": data}),
						_ => todo!(),
					}
				} else {
					serde_json::Value::Null
				}
			}
			ArgType::OffsetOf | ArgType::Len | ArgType::Bitsize | ArgType::Bytesize => {
				let atype = ArgOpt::get_argtype_or(&self.opts, ArgType::Int32);
				let v = Self::read_from_argtype_basic(&atype, ptr, force_indirect, parsed, target)?;
				let v = serde_json::to_value(v)?;
				if let Some(fieldopt) = self.opts.first() {
					let ident: Identifier = fieldopt.clone().try_into()?;
					let ltype = match &self.argtype {
						ArgType::Len => LenType::Len,
						ArgType::Bitsize => LenType::Bits,
						ArgType::Bytesize => LenType::Bytes,
						ArgType::OffsetOf => LenType::Offset,
						_ => panic!("Impossible"),
					};
					actions.push(Action::SetLen(v.clone(), ident, ltype))
				} else {
					error!("Unable to determine field of for len")
				}
				let key = self.argtype.to_string();
				json!({key: v})
			}

			ArgType::Ptr | ArgType::Ptr64 => {
				if ArgOpt::same_direction(&self.opts, dir) {
					let ptr = Self::read_from_argtype_basic(
						&self.argtype,
						ptr,
						force_indirect,
						parsed,
						target,
					)?;
					if let Some(narg) = ArgOpt::get_subarg(&self.opts) {
						idents.push(self.name.clone());
						let (ins, bread) =
							narg.read_from_int(ptr, true, dir, parsed, target, actions, idents)?;
						idents.pop();
						bytes_read += bread;
						json!({"ptr": ins})
					} else {
						return Err(Error::Unsupported);
					}
				} else {
					serde_json::Value::Null
				}
			}
			ArgType::Csum => return Err(Error::Unsupported),
			ArgType::Flags => return Err(Error::Unsupported),
			ArgType::Const => return Err(Error::Unsupported),
			ArgType::Text => return Err(Error::Unsupported),
			ArgType::Proc => return Err(Error::Unsupported),
			ArgType::Glob => return Err(Error::Unsupported),
			ArgType::Fmt => return Err(Error::Unsupported),
			ArgType::CompressedImage => return Err(Error::Unsupported),
			ArgType::Void => serde_json::Value::Null,
			ArgType::Ident(ident) => {
				let key = ident.to_string();
				if let Some(it) = parsed.identifier_to_ident_type(ident) {
					match it {
						IdentType::Resource => {
							if let Some(stype) = parsed.resource_to_basic_type(ident) {
								let r = Self::read_from_argtype_basic(
									&stype,
									ptr,
									force_indirect,
									parsed,
									target,
								)?;
								serde_json::to_value(r)?;
								json!({key: r})
							} else {
								return Err(Error::Unsupported);
							}
						}
						IdentType::Struct => {
							if let Some(s) = parsed.get_struct(ident) {
								let mut ins = HashMap::new();
								let mut nptr = ptr;
								for arg in s.args() {
									let (v, bread) = arg.read_from(
										ptr,
										force_indirect,
										dir,
										parsed,
										target,
										actions,
									)?;
									nptr += bread as u64;
									let name = arg.name.safe_name();
									ins.insert(name, v);
								}
								bytes_read += (nptr - ptr) as usize;
								serde_json::to_value(ins)?
							} else {
								return Err(Error::Unsupported);
							}
						}
						IdentType::Union => return Err(Error::Unsupported),
						IdentType::Flag => return Err(Error::Unsupported),
						IdentType::Template | IdentType::Alias | IdentType::Function => {
							return Err(Error::Unsupported)
						}
					}
				} else {
					return Err(Error::Unsupported);
				}
			}
			ArgType::Template(_) => return Err(Error::Unsupported),
		};
		Ok((ret, bytes_read))
	}
	fn fill_in_alias(&mut self, alias: &TypeAlias) -> Result<()> {
		self.argtype = alias.utype.clone();
		self.opts = alias.opts.clone();
		self.aident = Some(ArgIdent::Alias(alias.identifier().clone()));
		Ok(())
	}
	fn fill_in_alias_single(&mut self, aliases: &[TypeAlias]) -> Result<usize> {
		let mut ret = 0;
		if let ArgType::Ident(name) = &self.argtype {
			if let Some(alias) = TypeAlias::find_ident(aliases, name) {
				self.fill_in_alias(alias)?;
				ret += 1;
			}
		}
		for opt in self.opts.iter_mut() {
			if let ArgOpt::FullArg(arg) = opt {
				ret += arg.fill_in_alias_single(aliases)?;
			}
		}
		if let Some(ArgIdent::Template(stmt)) = &mut self.aident {
			match stmt {
				Statement::Struct(a) => ret += Self::fill_in_aliases(&mut a.args, aliases)?,
				Statement::Union(a) => ret += Self::fill_in_aliases(&mut a.args, aliases)?,
				_ => {}
			}
		}
		Ok(ret)
	}
	fn fill_in_aliases(args: &mut [Argument], aliases: &[TypeAlias]) -> Result<usize> {
		let mut ret = 0;
		for arg in args.iter_mut() {
			ret += arg.fill_in_alias_single(aliases)?;
		}
		Ok(ret)
	}
	fn simplify_single(&mut self, idents: &HashMap<Identifier, IdentType>) -> Result<usize> {
		let mut ret = 0;
		if let ArgType::Ident(n) = &self.argtype {
			if let Some(at) = idents.get(n) {
				ret += ArgOpt::simplify(&mut self.opts, at, n)?;
			} else {
				warn!("ident {n:?} was not found in ident map");
			}
		}
		for opt in self.opts.iter_mut() {
			if let ArgOpt::FullArg(arg) = opt {
				ret += arg.simplify_single(idents)?;
			}
		}
		if let Some(ArgIdent::Template(stmt)) = &mut self.aident {
			match stmt {
				Statement::Struct(a) => ret += Self::simplify(&mut a.args, idents)?,
				Statement::Union(a) => ret += Self::simplify(&mut a.args, idents)?,
				_ => {}
			}
		}
		Ok(ret)
	}
	fn simplify(args: &mut [Argument], idents: &HashMap<Identifier, IdentType>) -> Result<usize> {
		let mut ret = 0;
		for arg in args.iter_mut() {
			ret += arg.simplify_single(idents)?;
		}
		Ok(ret)
	}

	fn fill_in_template_single(&mut self, tmpl: &TypeRaw) -> Result<usize> {
		let mut tokens = ArgOpt::remove_tokens(&mut self.opts);
		if !tokens.is_empty() {
			let args = tokens.remove(0);
			assert!(tokens.is_empty());
			let mut ntokens = Parsed::unpack_template(tmpl, &args)?;
			let insname = if let Some(f) = ntokens.first() {
				matches!(f, Token::SquareOpen) || matches!(f, Token::BracketOpen)
			} else {
				false
			};
			if insname {
				ntokens.insert(0, Token::Name(String::from("VIRTUAL")));
				let mut stmts = Statement::from_tokens(ntokens)?;
				assert!(stmts.len() == 1);
				self.argtype = ArgType::Template(tmpl.name.clone());
				self.aident = Some(ArgIdent::Template(stmts.remove(0)));
				self.sourceidents.push(tmpl.name.clone());
				Ok(1)
			} else {
				ntokens.insert(0, Token::Name(self.name.name.clone()));
				let mut arg = Statement::as_argument(ntokens)?;
				self.argtype = arg.argtype;
				self.opts.append(&mut arg.opts);
				self.sourceidents.push(tmpl.name.clone());
				Ok(1)
			}
		} else {
			Ok(0)
		}
	}
	fn fill_in_template(&mut self, templates: &[TypeRaw]) -> Result<usize> {
		let mut ret = 0;

		// First fix up this argument, if we need to
		if let ArgType::Ident(name) = &self.argtype {
			if let Some(tmpl) = TypeRaw::find_ident(templates, name) {
				let plus = self.fill_in_template_single(tmpl)?;
				ret += plus;
			}
		}

		// We then look for sub-arguments, this happens if this is a pointer, array, etc.
		for (i, opt) in self.opts.iter_mut().enumerate() {
			if let ArgOpt::FullArg(arg) = opt {
				let plus = arg.fill_in_template(templates)?;
				if plus > 0 {
					self.opts.remove(i);
					return Ok(ret + plus + self.fill_in_template(templates)?);
				}
			}
		}

		// If we have created our own template struct, we also try and fix up that
		if let Some(ArgIdent::Template(stmt)) = &mut self.aident {
			match stmt {
				Statement::Struct(a) => ret += Self::fill_in_templates(&mut a.args, templates)?,
				Statement::Union(a) => ret += Self::fill_in_templates(&mut a.args, templates)?,
				_ => {}
			}
		}
		Ok(ret)
	}

	pub fn fill_in_templates(args: &mut [Argument], templates: &[TypeRaw]) -> Result<usize> {
		let mut ret = 0;
		for arg in args.iter_mut() {
			if let Ok(add) = arg.fill_in_template(templates) {
				ret += add;
			} else {
				error!("unable to fill in template on arg {arg:?}");
			}
		}
		Ok(ret)
	}

	// pub(crate) fn into_inner(self) -> (Identifier, ArgType, Vec<ArgOpt>, Option<ArgIdent>) {
	//     (self.name, self.argtype, self.opts, self.aident)
	// }
	gen_get_ident! { name }
	gen_get_iter! { opts, ArgOpt }
	gen_get! { arg_type, argtype, ArgType }

	/// Parse opts to find direction
	pub fn direction(&self) -> Direction {
		ArgOpt::direction(&self.opts, &Direction::In)
	}

	/// Find out what the argument refers to, resource, struct, etc.
	pub fn arg_refers_to(&self) -> &Option<ArgIdent> {
		&self.aident
	}

	fn split_tokens(tokens: &Vec<Token>, sep: &Token) -> Result<Vec<Vec<Token>>> {
		trace!("Splitting {tokens:?}");
		let mut ret = Vec::new();
		let mut curr = Vec::new();
		let mut paren = 0;
		let mut bracket = 0;
		let mut square = 0;
		for t in tokens.iter() {
			if paren == 0 && bracket == 0 && square == 0 && *t == *sep {
				ret.push(std::mem::take(&mut curr));
				continue;
			}
			match t {
				Token::ParenOpen => paren += 1,
				Token::ParenClose => paren -= 1,
				Token::BracketOpen => bracket += 1,
				Token::BracketClose => bracket -= 1,
				Token::SquareOpen => square += 1,
				Token::SquareClose => square -= 1,
				_ => {}
			}
			curr.push(t.clone());
		}
		// We should never have trailing separator, so shold always be something here
		ret.push(curr);
		Ok(ret)
	}
}

/// Information about defined struct
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Struct {
	name: Identifier,
	args: Vec<Argument>,
	opts: Vec<ArgOpt>,
}

impl Struct {
	gen_get_ident! { name }
	gen_get_ident_matches! { name }
	gen_get_iter! { args, Argument }
	gen_get_iter! { opts, ArgOpt }

	// pub(crate) fn into_inner(self) -> (Identifier, Vec<Argument>, Vec<ArgOpt>) {
	//     (self.name, self.args, self.opts)
	// }
}

impl Postproc for Struct {
	fn fill_in_aliases(&mut self, aliases: &[TypeAlias]) -> Result<usize> {
		Argument::fill_in_aliases(&mut self.args, aliases)
	}

	fn fill_in_templates(&mut self, tmpls: &[TypeRaw]) -> Result<usize> {
		Argument::fill_in_templates(&mut self.args, tmpls)
	}

	fn simplify(&mut self, idents: &HashMap<Identifier, IdentType>) -> Result<usize> {
		Argument::simplify(&mut self.args, idents)
	}
}

/// Information about defined union
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Union {
	name: Identifier,
	args: Vec<Argument>,
	opts: Vec<ArgOpt>,
}

impl Union {
	gen_get_ident! { name }
	gen_get_ident_matches! { name }
	gen_get_iter! { args, Argument }
	gen_get_iter! { opts, ArgOpt }

	// pub(crate) fn into_inner(self) -> (Identifier, Vec<Argument>, Vec<ArgOpt>) {
	//     (self.name, self.args, self.opts)
	// }
}
impl Postproc for Union {
	fn fill_in_aliases(&mut self, aliases: &[TypeAlias]) -> Result<usize> {
		Argument::fill_in_aliases(&mut self.args, aliases)
	}
	fn fill_in_templates(&mut self, tmpls: &[TypeRaw]) -> Result<usize> {
		Argument::fill_in_templates(&mut self.args, tmpls)
	}
	fn simplify(&mut self, idents: &HashMap<Identifier, IdentType>) -> Result<usize> {
		Argument::simplify(&mut self.args, idents)
	}
}

/// Identifier for any named entity
#[derive(Debug, Default, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Identifier {
	pub name: String,

	/// Subnames each separated by '$' in Syzlang
	pub subname: Vec<String>,
}
impl std::fmt::Display for &Identifier {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.unique_name())
	}
}

impl From<&str> for Identifier {
	fn from(value: &str) -> Self {
		Identifier::new(value, vec![])
	}
}

impl FromStr for Identifier {
	type Err = Error;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		Ok(Self {
			name: s.to_string(),
			subname: vec![],
		})
	}
}
impl From<&Identifier> for String {
	fn from(value: &Identifier) -> Self {
		value.to_string()
	}
}
// impl TryFrom<ArgOpt> for Identifier {
//     type Error = Error;

//     fn try_from(value: ArgOpt) -> std::result::Result<Self, Self::Error> {
// 		if let ArgOpt::Ident(n) = value {
// 			Ok(n)
// 		} else {
// 			todo!();
// 		}
//     }
// }

impl Identifier {
	pub fn new<S: Into<String>>(name: S, subname: Vec<String>) -> Self {
		Self {
			name: name.into(),
			subname,
		}
	}
	pub fn unique_name(&self) -> String {
		let mut ret = self.name.clone();
		for sub in self.subname.iter() {
			ret.push('$');
			ret.push_str(sub);
		}
		ret
	}
	fn as_safe(c: char) -> char {
		c
	}
	pub fn safify(s: &str) -> String {
		let mut ret = String::from("");
		for c in s.chars() {
			ret.push(Self::as_safe(c));
		}
		ret
	}
	pub fn safe_name(&self) -> String {
		let mut ret = Self::safify(&self.name);
		for sub in self.subname.iter() {
			ret.push('_');
			ret.push_str(Self::safify(sub).as_str());
		}
		ret
	}
}

/// An Include statement, both file and directory
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Include {
	name: String,
	is_file: bool,
}

impl Include {
	/// The file or directory which should be included
	pub fn name(&self) -> &str {
		&self.name
	}

	/// This is specified with `incdir <...>` in Syzlang
	pub fn is_dir(&self) -> bool {
		!self.is_file
	}

	/// This is a regular `include <..>` entry
	pub fn is_file(&self) -> bool {
		self.is_file
	}
}

/// Complex types are often given aliases. This struct contains what the real
/// type is (already procecced).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TypeAlias {
	name: Identifier,
	utype: ArgType,
	opts: Vec<ArgOpt>,
}
impl TypeAlias {
	gen_get_ident! { name }
	gen_get! { underlying_type, utype, ArgType }
	gen_get_iter! { opts, ArgOpt }
	gen_find_ident! { name }
}

/// Different types than a type template might create.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum CreateType {
	CreateUnion,
	CreateStruct,
	CreateEntity,
}

/// [TypeRaw] is more complex than [TypeAlias] because it can declare arbitrary
/// new input, as opposed to just type options.
///
/// In this struct we therefore store a vector of [Token] so that they can be
/// processed as usual when we need to declare the new element.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TypeRaw {
	name: Identifier,
	tokens: Vec<Token>,
	replace: Vec<ArgType>,
	ttype: CreateType,
}
impl TypeRaw {
	pub fn new(
		name: Identifier,
		tokens: Vec<Token>,
		replace: Vec<ArgType>,
		ttype: CreateType,
	) -> Self {
		Self {
			name,
			tokens,
			replace,
			ttype,
		}
	}
	gen_find_ident! { name }
	gen_get_ident! { name }
	gen_get_iter! { tokens, Token }
	gen_get_iter! { replace, ArgType }
	gen_get! { create_type, ttype, CreateType }

	/// Find out which index `name` has in the argument list
	///
	/// So if entry is `type ABC[X,Y] { ... }`, then `argument_index("Y")` would
	/// return Some(1).
	pub fn argument_index(&self, name: &str) -> Option<usize> {
		for (i, r) in self.replace.iter().enumerate() {
			if r.matches_name(name) {
				return Some(i);
			}
		}
		None
	}
}

/// Information about a resource
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Resource {
	name: Identifier,
	atype: ArgType,
	consts: Vec<Value>,
}

impl Resource {
	// pub(crate) fn into_inner(self) -> (Identifier, ArgType, Vec<Value>) {
	//     (self.name, self.atype, self.consts)
	// }
	gen_get_ident! { name }
	gen_get_iter! { specials, consts, Value }
	gen_get! { arg_type, atype, ArgType }
}

/// Information about a function
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Function {
	pub name: Identifier,
	pub args: Vec<Argument>,
	pub output: ArgType,
}

impl Function {
	pub fn new(name: Identifier, args: Vec<Argument>, output: ArgType) -> Self {
		Self { name, args, output }
	}
	/// Wehther this function is virtual to Syzkaller or actually exist on the target OS
	pub fn is_virtual(&self) -> bool {
		self.name.name.starts_with("syz_")
	}
	gen_get_ident! { name }
	gen_get_ident_matches! { name }
	gen_get_iter! { args, Argument }
	gen_get! { output, ArgType }
	// pub(crate) fn into_inner(self) -> (Identifier, Vec<Argument>, ArgType) {
	//     (self.name, self.args, self.output)
	// }
}
impl Postproc for Function {
	fn fill_in_aliases(&mut self, aliases: &[TypeAlias]) -> Result<usize> {
		Argument::fill_in_aliases(&mut self.args, aliases)
	}
	fn fill_in_templates(&mut self, tmpls: &[TypeRaw]) -> Result<usize> {
		Argument::fill_in_templates(&mut self.args, tmpls)
	}
	fn simplify(&mut self, idents: &HashMap<Identifier, IdentType>) -> Result<usize> {
		Argument::simplify(&mut self.args, idents)
	}
}

/// One flag which specifies one of several possible values
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Flag {
	pub name: Identifier,
	pub args: Vec<Value>,
}

impl Flag {
	pub fn new<I: Into<Identifier>>(name: I, args: Vec<Value>) -> Self {
		let name = name.into();
		Self { name, args }
	}
	gen_get_ident! { name }
	gen_get_ident_matches! { name }
	gen_get_iter! { args, Value }
	// pub(crate) fn into_inner(self) -> (Identifier, Vec<Value>) {
	//     (self.name, self.args)
	// }
}

/// A define statement which can be sent to a C preprocessor
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Define {
	name: String,
	expr: Vec<Token>,
}

impl Define {
	gen_get! { name, str }
	gen_get_iter! { tokens, expr, Token }
	pub fn first_token(&self) -> Option<&Token> {
		self.expr.first()
	}
}

/// All the different type of statements
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Statement {
	Include(Include),
	TypeAlias(TypeAlias),
	TypeRaw(TypeRaw),
	Resource(Resource),
	Function(Function),
	Struct(Struct),
	Union(Union),
	Flag(Flag),
	Define(Define),
}

macro_rules! impl_try_from {
	($s:ident) => {
		impl TryFrom<Statement> for $s {
			type Error = Error;

			fn try_from(value: Statement) -> std::result::Result<Self, Self::Error> {
				match value {
					Statement::$s(n) => Ok(n),
					_ => generror!(format!("expected {} got {value:?}", stringify!($n))),
				}
			}
		}
	};
}
impl_try_from! { Include }
impl_try_from! { TypeAlias }
impl_try_from! { TypeRaw }
impl_try_from! { Resource }
impl_try_from! { Function }
impl_try_from! { Struct }
impl_try_from! { Union }
impl_try_from! { Flag }
impl_try_from! { Define }

impl Statement {
	/// Parse in [Statement]s from file.
	pub fn from_file(p: &Path) -> Result<Vec<Self>> {
		debug!("parsing stmt file {p:?}");
		let data = std::fs::read(p)?;
		let data = std::str::from_utf8(&data)?;
		let n = Self::parse_from_str(data)?;
		Ok(n)
	}
	pub fn identifier(&self) -> Option<&Identifier> {
		match self {
			Statement::Include(_) => None,
			Statement::TypeAlias(a) => Some(&a.name),
			Statement::TypeRaw(a) => Some(&a.name),
			Statement::Resource(a) => Some(&a.name),
			Statement::Function(a) => Some(&a.name),
			Statement::Struct(a) => Some(&a.name),
			Statement::Union(a) => Some(&a.name),
			Statement::Flag(a) => Some(&a.name),
			Statement::Define(_) => None,
		}
	}
	pub fn find_by_id<'a>(stmts: &'a [Statement], name: &Identifier) -> Option<&'a Statement> {
		for stmt in stmts.iter() {
			if let Some(n) = stmt.identifier() {
				if n == name {
					return Some(stmt);
				}
			}
		}
		None
	}
	/// Convert from [Token]s to [Statement]s
	pub fn from_tokens(mut tokens: Vec<Token>) -> Result<Vec<Self>> {
		let mut ret = Vec::new();
		while !tokens.is_empty() {
			let next = consume!(tokens);

			match &next {
				Token::Include => ret.push(Self::parse_include(true, &mut tokens)?),
				Token::Incdir => ret.push(Self::parse_include(false, &mut tokens)?),
				Token::Resource => ret.push(Self::parse_resource(&mut tokens)?),
				Token::Type => ret.push(Self::parse_type(&mut tokens)?),
				Token::Define => ret.push(Self::parse_define(&mut tokens)?),
				Token::Meta => Self::parse_meta(&mut tokens)?,
				Token::Name(_n) => ret.append(&mut Self::parse_generic_name(next, &mut tokens)?),
				Token::Comment(c) => trace!("ignoring comment {c}"),
				Token::CrocOpen
				| Token::CrocClose
				| Token::ParenOpen
				| Token::ParenClose
				| Token::BracketOpen
				| Token::BracketClose
				| Token::SquareOpen
				| Token::SquareClose
				| Token::Colon
				| Token::Comma
				| Token::Equal
				| Token::Dollar => return parsererror!(format!("unexpected token {next:?}")),
				Token::Newline => {}
				Token::String(_) | Token::Char(_) => {
					return parsererror!(format!("unexpected token {next:?}"))
				}
			}
		}
		Ok(ret)
	}

	/// Parse a string as a vector of [Statement]s
	pub fn parse_from_str(s: &str) -> Result<Vec<Statement>> {
		let tokens = Token::create_from_str(s)?;
		let stmts = Self::from_tokens(tokens)?;
		Ok(stmts)
	}

	fn while_comments(tokens: &mut Vec<Token>) -> Result<()> {
		while !tokens.is_empty() {
			let n = consume!(tokens);
			match n {
				Token::Comment(_) => {}
				Token::Newline => {}
				_ => {
					tokens.insert(0, n);
					break;
				}
			}
		}
		Ok(())
	}
	fn opposite(token: &Token) -> Option<Token> {
		match *token {
			Token::BracketOpen => Some(Token::BracketClose),
			Token::ParenOpen => Some(Token::ParenClose),
			Token::CrocOpen => Some(Token::CrocClose),
			Token::SquareOpen => Some(Token::SquareClose),
			_ => None,
		}
	}
	fn until_newline(tokens: &mut Vec<Token>) -> Vec<Token> {
		let sidx = if let Some(s) = tokens.iter().position(|x| *x == Token::Newline) {
			s
		} else {
			tokens.len()
		};
		let rem = tokens.drain(..sidx).collect();
		rem
	}
	fn find_stop(start: &Token, tokens: &[Token]) -> Option<usize> {
		let mut level = 0;
		let opposite = Self::opposite(start).unwrap();
		for (i, t) in tokens.iter().enumerate() {
			if *t == *start {
				level += 1;
			} else if *t == opposite {
				level -= 1;
				if level == 0 {
					return Some(i);
				}
			}
		}
		None
	}

	fn find_real_token(tokens: &[Token], t: &Token) -> Option<usize> {
		let mut croc = 0;
		let mut bracket = 0;
		let mut paren = 0;
		let mut square = 0;
		for (i, tok) in tokens.iter().enumerate() {
			if *tok == *t {
				if croc == 0 && bracket == 0 && paren == 0 && square == 0 {
					return Some(i);
				}
			} else {
				match tok {
					Token::CrocOpen => croc += 1,
					Token::BracketOpen => bracket += 1,
					Token::ParenOpen => paren += 1,
					Token::SquareOpen => square += 1,
					Token::CrocClose => croc -= 1,
					Token::BracketClose => bracket -= 1,
					Token::ParenClose => paren -= 1,
					Token::SquareClose => square -= 1,
					_ => {}
				}
			}
		}
		if !tokens.is_empty() {
			Some(tokens.len())
		} else {
			None
		}
	}

	fn parse_as_arg_opts(mut tokens: Vec<Token>, arg: &ArgType) -> Result<Vec<ArgOpt>> {
		let opts = if let Some(Token::SquareOpen) = tokens.first() {
			ArgOpt::from_tokens(tokens, arg)?
		} else if !tokens.is_empty() {
			let next = consume!(tokens);
			if arg.is_int() && next == Token::Colon {
				let num: Value = consume!(tokens).try_into()?;

				let mut ret = vec![ArgOpt::Bits(num)];
				if !tokens.is_empty() {
					ret.append(&mut Self::parse_as_arg_opts(tokens, arg)?);
				}
				ret
			} else if next == Token::ParenOpen {
				tokens.insert(0, next);
				let rem = Statement::extract_section(&mut tokens, true)?;
				let r = FieldOpt::from_tokens(rem)?;
				let r = ArgOpt::FieldOpt(r);
				check_empty!(tokens);
				vec![r]
			} else {
				error!("next {next:?} + {tokens:?}");
				todo!();
			}
		} else {
			check_empty!(tokens);
			Vec::new()
		};
		Ok(opts)
	}
	fn as_argument(mut parts: Vec<Token>) -> Result<Argument> {
		trace!("rest {parts:?}");
		let name = Statement::parse_nameid(&mut parts)?.unique_name();
		let v = Statement::parse_nameid(&mut parts)?;
		let utype = v.unique_name();
		let nutype = ArgType::from_str(&utype)?;
		let opts = Self::parse_as_arg_opts(parts, &nutype)?;

		let arg = Argument::new(name, utype, opts);
		Ok(arg)
	}
	fn as_arguments(mut tokens: Vec<Token>, splitter: &Token) -> Result<Vec<Argument>> {
		trace!("as args {splitter:?} {tokens:?}");
		let mut ret = Vec::new();
		if tokens.is_empty() {
			return Ok(ret);
		}

		trace!("starting to parse as args {tokens:?}");
		while let Some(nsplit) = Self::find_real_token(&tokens, splitter) {
			trace!("comma @ {nsplit}");
			let parts: Vec<Token> = tokens.drain(..nsplit).collect();

			// There is no trailing comma, so don't do this in the last one
			if !tokens.is_empty() {
				let t = consume!(tokens); // ,
				verify!(t == Token::Comma || t == Token::Newline, UnexpectedToken);
			}
			trace!("ARG: {parts:?}");
			if parts.is_empty() {
				continue;
			} else if let Some(idx) = parts.iter().position(|x| matches!(*x, Token::Comment(_))) {
				// TODO: Should be a bit more clever here
				assert!(idx == 0);
				debug!("ignoring all because comment: {idx} {parts:?}");
				continue;
			}
			let arg = Self::as_argument(parts)?;
			ret.push(arg);
		}
		Ok(ret)
	}

	fn parse_as_opts(tokens: &mut Vec<Token>) -> Result<Vec<ArgOpt>> {
		while let Some(Token::Newline) = tokens.first() {
			consume!(tokens, Token::Newline);
		}
		trace!("trying to parse opts");
		let nopts = if tokens.first() == Some(&Token::SquareOpen) {
			let rem = Statement::extract_section(tokens, true)?;

			let r = StructAttr::from_tokens(rem)?;
			vec![ArgOpt::StructAttr(r)]
		} else {
			trace!("No opts, got {:?}", tokens.first());
			Vec::new()
		};
		Ok(nopts)
	}
	fn parse_generic_name(name: Token, tokens: &mut Vec<Token>) -> Result<Vec<Self>> {
		trace!("parse name {name:?}");
		let mut ret = Vec::new();
		tokens.insert(0, name);
		let name = Self::parse_nameid(tokens)?;

		let first = consume!(tokens);
		if first == Token::Equal {
			let rem = Self::until_newline(tokens);
			let args = Self::parse_values_with_sep(rem, Token::Comma)?;
			let flag = Flag { name, args };
			ret.push(Statement::Flag(flag));
		} else {
			tokens.insert(0, first.clone());
			let parse = Self::extract_section(tokens, true)?;
			trace!("parsing as struct/union/func {parse:?}");
			if first == Token::ParenOpen {
				trace!("parsing as function");
				let args = Self::as_arguments(parse, &Token::Comma)?;
				let mut rem = Self::until_newline(tokens);

				trace!("rem to newline: {rem:?}");
				let output = if let Some(n) = rem.first() {
					if *n != Token::ParenOpen {
						let tok = consume!(rem);
						let n = tok.to_name()?;
						ArgType::from_str(n)?
					} else {
						// If we have no return argument and function attributes, we may hit this
						ArgType::Void
					}
				} else {
					ArgType::Void
				};
				if let Some(Token::ParenOpen) = rem.first() {
					let rargs = Self::extract_section(&mut rem, true)?;
					warn!("ignoring function attributes {rargs:?}");
				}
				check_empty!(rem);
				let func = Function { name, args, output };
				ret.push(Statement::Function(func));
			} else if first == Token::BracketOpen || first == Token::SquareOpen {
				let is_struct = first == Token::BracketOpen;
				trace!("parsing as struct/union {is_struct:?}");

				let args = Self::as_arguments(parse, &Token::Newline)?;
				trace!("getting struct/union opts");
				let opts = Self::parse_as_opts(tokens)?;
				trace!("arg entries {args:?}");
				let ins = if is_struct {
					let ins = Struct { name, args, opts };
					trace!("struct {ins:?}");
					Statement::Struct(ins)
				} else {
					let ins = Union { name, args, opts };
					trace!("union {ins:?}");
					Statement::Union(ins)
				};
				ret.push(ins);
			} else {
				todo!();
			}
		}

		Ok(ret)
	}
	fn parse_include(is_file: bool, tokens: &mut Vec<Token>) -> Result<Self> {
		consume!(tokens, Token::CrocOpen);
		let name = Self::parse_nameid(tokens)?;
		assert!(name.subname.is_empty());
		let name = name.name;
		trace!("include {name}");
		consume!(tokens, Token::CrocClose);
		let inc = Include { name, is_file };
		Ok(Statement::Include(inc))
	}
	fn extract_section(tokens: &mut Vec<Token>, remextra: bool) -> Result<Vec<Token>> {
		if let Some(first) = tokens.first() {
			trace!("first {first:?}");
			verify!(
				matches!(first, Token::SquareOpen)
					|| matches!(first, Token::ParenOpen)
					|| matches!(first, Token::BracketOpen)
					|| matches!(first, Token::CrocOpen),
				UnexpectedToken
			);
			if let Some(lidx) = Self::find_stop(first, tokens) {
				let mut rem: Vec<Token> = tokens.drain(0..=lidx).collect();
				if remextra {
					consume!(rem);
					rem.pop().unwrap();
				}
				trace!("rem {rem:?}");

				Ok(rem)
			} else {
				parsererror!(format!("unable to close for {first:?}"))
			}
		} else {
			warn!("no data in tokens, ret empty");
			Ok(Vec::new())
		}
	}
	fn parse_nameid(tokens: &mut Vec<Token>) -> Result<Identifier> {
		let tok = consume!(tokens);
		let name = tok.to_name()?;

		trace!("nameid parsing {name}");
		let mut sname = String::default();
		while let Some(Token::Dollar) = tokens.first() {
			trace!("got dollar");
			consume!(tokens, Token::Dollar);
			if !sname.is_empty() {
				sname.push('$');
			}
			sname.push_str(consume!(tokens).to_name()?);
		}
		let sname = if sname.is_empty() {
			vec![]
		} else {
			vec![sname]
		};
		Ok(Identifier::new(name, sname))
	}
	fn parse_values_with_sep(mut tokens: Vec<Token>, sep: Token) -> Result<Vec<Value>> {
		let mut ret = Vec::new();
		while !tokens.is_empty() {
			let ins: Value = consume!(tokens).try_into()?;
			ret.push(ins);

			if !tokens.is_empty() {
				consume!(tokens, sep);
			}
		}
		check_empty!(tokens);
		Ok(ret)
	}
	fn parse_meta(tokens: &mut Vec<Token>) -> Result<()> {
		let rem = Self::until_newline(tokens);
		warn!("ignoring meta comments {rem:?}");
		Ok(())
	}
	fn parse_define(tokens: &mut Vec<Token>) -> Result<Self> {
		let name = consume!(tokens).to_name()?.clone();
		trace!("define {name}");
		let rem = Self::until_newline(tokens);
		warn!("define ignoring {rem:?}");

		let ins = Define { name, expr: rem };
		Ok(Statement::Define(ins))
	}
	fn parse_type(tokens: &mut Vec<Token>) -> Result<Self> {
		trace!("parsing type");
		let mut opts = Vec::new();
		let name = Self::parse_nameid(tokens)?;

		trace!("type {name:?}");
		let replace = if let Some(Token::SquareOpen) = tokens.first() {
			let tmpls = Self::extract_section(tokens, true)?;
			let mut vals = Self::parse_values_with_sep(tmpls, Token::Comma)?;
			let mut repls = Vec::new();
			while !vals.is_empty() {
				let ins: ArgType = vals.remove(0).try_into()?;
				repls.push(ins);
			}
			repls
		} else {
			Vec::new()
		};
		let is_alias = replace.is_empty();
		let n = consume!(tokens);

		let r = if n == Token::BracketOpen || n == Token::SquareOpen {
			trace!("is struct or union alias: {is_alias}");
			let ttype = if n == Token::BracketOpen {
				CreateType::CreateStruct
			} else {
				CreateType::CreateUnion
			};
			tokens.insert(0, n);

			let mut instokens = Vec::new();
			let mut contents = Self::extract_section(tokens, false)?;
			instokens.append(&mut contents);
			let first = tokens.first();
			if first == Some(&Token::SquareOpen) {
				let mut attr = Self::extract_section(tokens, false)?;
				instokens.append(&mut attr);
			} else {
				trace!("next {:?}", tokens.first());
			}

			let ins = TypeRaw::new(name, instokens, replace, ttype);
			Statement::TypeRaw(ins)
		} else {
			tokens.insert(0, n);
			trace!("tokens {tokens:?}");
			let mut rem = Self::until_newline(tokens);
			trace!("tokens {rem:?}");
			trace!("is_alias {is_alias}");

			if !is_alias {
				let ins = TypeRaw::new(name, rem, replace, CreateType::CreateEntity);
				Statement::TypeRaw(ins)
			} else {
				let utype = Statement::parse_nameid(&mut rem)?;
				let stype = ArgType::from_str(&utype.unique_name())?;
				assert!(replace.is_empty());
				trace!("getting alias opts {stype:?} {rem:?}");

				let mut nopts = if let Some(Token::SquareOpen) = rem.first() {
					ArgOpt::from_tokens(rem, &stype)?
				} else {
					if !rem.is_empty() {
						warn!("ignoring extra data {rem:?}");
						todo!();
					}
					Vec::new()
				};
				opts.append(&mut nopts);
				let alias = TypeAlias {
					name,
					utype: stype,
					opts,
				};
				trace!("alias {alias:?}");
				Statement::TypeAlias(alias)
			}
		};
		Ok(r)
	}
	fn parse_resource(tokens: &mut Vec<Token>) -> Result<Self> {
		let mut rem = Self::until_newline(tokens);
		trace!("resource {rem:?}");
		let tok = consume!(rem);
		let name = tok.to_name()?;
		let mut opts = Self::extract_section(&mut rem, true)?;
		let opt = consume!(opts);
		let utype = opt.to_name()?;
		let atype = ArgType::from_str(utype)?;
		let consts = if let Some(Token::Colon) = rem.first() {
			consume!(rem, Token::Colon);
			// let rem = Self::until_newline(rem);
			Self::parse_values_with_sep(rem, Token::Comma)?
		} else {
			Vec::new()
		};
		let name = Identifier::new(name, vec![]);

		let ins = Resource {
			name,
			atype,
			consts,
		};
		Ok(Statement::Resource(ins))
	}
}

// macro_rules! gen_get_filter {
//     ($name:ident, $stmts:ident, $entry:ident, $rval:ty) => {
//         pub fn $name(&self) -> Vec<&$rval> {
//             self.$stmts
//                 .iter()
//                 .filter_map(|x| {
//                     if let Statement::$entry(f) = x {
//                         Some(f)
//                     } else {
//                         None
//                     }
//                 })
//                 .collect()
//         }
//     };
// }

/// All the different statements we define for [Identifier]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IdentType {
	Resource,
	Struct,
	Union,
	Flag,
	Template,
	Alias,
	Function,
}

#[cfg(feature = "unstable")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LenType {
	Len,
	Bytes,
	Bits,
	Offset,
}

#[cfg(feature = "unstable")]
#[derive(Clone, Debug)]
pub enum Action {
	SetLen(serde_json::Value, Identifier, LenType),
}

#[cfg(feature = "unstable")]
pub trait Target {
	fn read_bytes(&self, ptr: u64, data: &mut Vec<u8>) -> Result<usize>;
	fn read_c_string(&self, ptr: u64) -> Result<String>;
	fn target_size(&self) -> usize;
	fn big_endian(&self) -> bool;
}

/// Final output object after parsing all files.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Parsed {
	pub consts: Consts,
	includes: Vec<Include>,
	aliases: Vec<TypeAlias>,
	templates: Vec<TypeRaw>,
	pub resources: Vec<Resource>,
	pub functions: Vec<Function>,
	pub structs: Vec<Struct>,
	unions: Vec<Union>,
	pub flags: Vec<Flag>,
	defines: Vec<Define>,

	#[serde(skip)]
	idtypes: HashMap<Identifier, IdentType>,

	#[serde(skip)]
	idbanned: Vec<Identifier>,
}

impl Parsed {
	/// Construct a new [Parsed] object
	pub fn new(consts: Consts, stmts: Vec<Statement>) -> Result<Self> {
		let includes = Vec::new();
		let aliases = Vec::new();
		let templates = Vec::new();
		let resources = Vec::new();
		let functions = Vec::new();
		let structs = Vec::new();
		let unions = Vec::new();
		let flags = Vec::new();
		let defines = Vec::new();
		let idtypes = HashMap::new();
		let idbanned = Vec::new();
		let mut ret = Self {
			consts,
			includes,
			aliases,
			templates,
			resources,
			functions,
			structs,
			unions,
			flags,
			defines,
			idtypes,
			idbanned,
		};
		ret.insert_stmts(stmts);
		// ret.insert_builtin()?;
		Ok(ret)
	}
	gen_get_iter! { includes, Include }
	gen_get_iter! { aliases, TypeAlias }
	gen_get_iter! { templates, TypeRaw }
	gen_get_iter! { resources, Resource }
	gen_get_iter! { functions, Function }
	gen_get_iter! { structs, Struct }
	gen_get_iter! { unions, Union }
	gen_get_iter! { flags, Flag }
	gen_get_iter! { defines, Define }
	gen_get! { consts, Consts }
	gen_get_mut! { consts_mut, consts, Consts }

	/// Figure out which [IdentType] a certain identifier has.
	pub fn identifier_to_ident_type(&self, ident: &Identifier) -> Option<&IdentType> {
		self.idtypes.get(ident)
	}
	/// Figure out which [IdentType] a certain identifier has.
	pub fn name_to_ident_type(&self, name: &str) -> Option<&IdentType> {
		let ident = Identifier::new(name, vec![]);
		self.idtypes.get(&ident)
	}
	gen_find_by_ident! { get_flag, flags, Flag }
	gen_find_by_ident! { get_struct, structs, Struct }
	gen_find_by_ident! { get_union, unions, Union }
	gen_find_by_ident! { get_resource, resources, Resource }
	gen_find_by_ident! { get_function, functions, Function }

	gen_find_by_name! { get_named_struct, structs, Struct }
	gen_find_by_name! { get_named_union, unions, Union }
	gen_find_by_name! { get_named_resource, resources, Resource }
	gen_find_by_name! { get_named_function, functions, Function }

	fn _resource_to_basics(&self, ident: &Identifier, data: &mut Vec<ArgType>) {
		debug!("resolving {ident:?}");
		for res in self.resources.iter() {
			if res.name == *ident {
				let res = res.arg_type();
				debug!("found {res:?}");
				data.push(res.clone());
				if let ArgType::Ident(n) = res {
					self._resource_to_basics(n, data)
				}
			}
		}
	}
	pub fn resource_to_basics(&self, ident: &Identifier) -> Vec<ArgType> {
		let mut ret = Vec::new();
		self._resource_to_basics(ident, &mut ret);
		ret
	}

	/// Find out the underlying basic type of some resource.
	pub fn resource_to_basic_type(&self, ident: &Identifier) -> Option<ArgType> {
		debug!("resolving {ident:?}");
		for res in self.resources.iter() {
			if res.name == *ident {
				let res = res.arg_type();
				debug!("found {res:?}");
				match res {
					ArgType::Ident(n) => return self.resource_to_basic_type(n),
					_ => return Some(res.clone()),
				}
			}
		}
		None
	}

	/// Remove all functions defined as virtual
	pub fn remove_virtual_functions(&mut self) {
		let q = self
			.functions
			.extract_if(|x| x.is_virtual())
			.collect::<Vec<_>>();
		debug!("rem(virt): {}", q.len());
	}
	pub fn remove_func_no_sysno(&mut self, arch: &Arch) {
		let q = self
			.functions
			.extract_if(|x| self.consts.find_sysno(&x.name.name, arch).is_none())
			.collect::<Vec<_>>();
		debug!("rem(sysno): {}", q.len());
	}
	pub fn remove_subfunctions(&mut self) {
		let q = self
			.functions
			.extract_if(|x| !x.name.subname.is_empty())
			.collect::<Vec<_>>();
		debug!("rem(sub): {}", q.len());
	}
	pub fn remove_aliases(&mut self) {
		self.aliases.clear();
	}
	pub fn remove_templates(&mut self) {
		self.templates.clear();
	}
	pub fn remove_defines(&mut self) {
		self.defines.clear();
	}
	pub fn remove_unions(&mut self) {
		self.unions.clear();
	}
	pub fn remove_structs(&mut self) {
		self.structs.clear();
	}

	/// Insert builtin aliases and templates.
	///
	/// This is necessary, if one uses data from Syzkaller and want to call [Self::postprocess].
	pub fn insert_builtin(&mut self) -> Result<()> {
		let builtins = r#"
type bool8	int8[0:1]
type bool16	int16[0:1]
type bool32	int32[0:1]
type bool64	int64[0:1]
type boolptr	intptr[0:1]

type fileoff[BASE] BASE

type filename string[filename]

type buffer[DIR] ptr[DIR, array[int8]]

# These are not documented, men seems to be standard
type optional[ARG] ARG
# TODO: openbsd also uses this with a single argument, B is presumably
# then some default value
type bytesize4[A,B] bytesize[A, B]
type bytesize8[A,B] bytesize[A, B]
"#;

		let tokens = Token::create_from_str(builtins)?;
		let stmts = Statement::from_tokens(tokens)?;
		self.insert_stmts(stmts);

		Ok(())
	}
	fn insert_idtype(&mut self, ident: &Identifier, it: IdentType) {
		if !self.idbanned.contains(ident) {
			if let Some(old) = self.idtypes.insert(ident.clone(), it.clone()) {
				if old != it {
					// TODO: Might need to use a vector in hashmap
					warn!("equal ident for multiple different types {ident:?} {old:?} -> {it:?}");
					self.idtypes.remove(ident);
					self.idbanned.push(ident.clone());
				}
			}
		} else {
			warn!("not inserting {ident:?} because it has caused problems");
		}
	}
	fn insert_stmts(&mut self, stmts: Vec<Statement>) {
		for stmt in stmts.into_iter() {
			match stmt {
				Statement::Include(a) => self.includes.push(a),
				Statement::TypeAlias(a) => {
					self.insert_idtype(&a.name, IdentType::Alias);
					self.aliases.push(a);
				}
				Statement::TypeRaw(a) => {
					self.insert_idtype(&a.name, IdentType::Template);
					self.templates.push(a)
				}
				Statement::Resource(a) => {
					self.insert_idtype(&a.name, IdentType::Resource);
					self.resources.push(a)
				}
				Statement::Function(a) => {
					self.insert_idtype(&a.name, IdentType::Function);
					self.functions.push(a)
				}
				Statement::Struct(a) => {
					self.insert_idtype(&a.name, IdentType::Struct);
					self.structs.push(a)
				}
				Statement::Union(a) => {
					self.insert_idtype(&a.name, IdentType::Union);
					self.unions.push(a)
				}
				Statement::Flag(a) => {
					self.insert_idtype(&a.name, IdentType::Flag);
					self.flags.push(a)
				}
				Statement::Define(a) => self.defines.push(a),
			}
		}
	}

	fn process_aliases_gen<P: Postproc>(args: &mut [P], aliases: &[TypeAlias]) -> Result<usize> {
		let mut ret = 0;
		for arg in args.iter_mut() {
			ret += arg.fill_in_aliases(aliases)?;
		}
		Ok(ret)
	}
	fn process_templates_gen<P: Postproc>(args: &mut [P], tmpls: &[TypeRaw]) -> Result<usize> {
		let mut ret = 0;
		for arg in args.iter_mut() {
			ret += arg.fill_in_templates(tmpls)?;
		}
		Ok(ret)
	}
	fn simplify_gen<P: Postproc>(
		args: &mut [P],
		idents: &HashMap<Identifier, IdentType>,
	) -> Result<usize> {
		let mut ret = 0;
		for arg in args.iter_mut() {
			ret += arg.simplify(idents)?;
		}
		Ok(ret)
	}
	/// Simplify / correct statements since there can be some ambiguity when
	/// parsing.
	///
	/// If for instance, we see `some_id[...]`, we don't really know what
	/// `some_id` refers to and therefore don't know how to parse the contents
	/// in brackets.
	pub fn simplify_and_fix(&mut self) -> Result<usize> {
		let mut ret = 0;
		let idents = std::mem::take(&mut self.idtypes);
		ret += Self::simplify_gen(&mut self.structs, &idents)?;
		ret += Self::simplify_gen(&mut self.unions, &idents)?;
		ret += Self::simplify_gen(&mut self.functions, &idents)?;
		self.idtypes = idents;
		Ok(ret)
	}

	/// Parse and replace all aliases.
	pub fn process_aliases(&mut self) -> Result<usize> {
		let mut ret = 0;
		ret += Self::process_aliases_gen(&mut self.structs, &self.aliases)?;
		ret += Self::process_aliases_gen(&mut self.unions, &self.aliases)?;
		ret += Self::process_aliases_gen(&mut self.functions, &self.aliases)?;
		Ok(ret)
	}
	/// Unpack templates and create the necessary entities specific for the
	/// configured template.
	///
	/// This step may create new entities, so previous postproceccing may need
	/// to be redone based on this. Since this unpacks templates, the size of
	/// the data will increase. On Linux, it goes from about 8MB of JSON to 14MB
	/// of JSON.
	pub fn process_templates(&mut self) -> Result<usize> {
		let mut ret = 0;
		ret += Self::process_templates_gen(&mut self.structs, &self.templates)?;
		ret += Self::process_templates_gen(&mut self.unions, &self.templates)?;
		ret += Self::process_templates_gen(&mut self.functions, &self.templates)?;
		Ok(ret)
	}

	/// Perform post-processing on all the defined statements.
	///
	/// This function does 3 different things in a loop until there is nothing
	/// more to do:
	///
	/// 1. [Self::simplify_and_fix]
	/// 2. [Self::process_aliases]
	/// 3. [Self::process_templates]
	///
	/// The function returns the number of items replaced
	pub fn postprocess(&mut self) -> Result<usize> {
		let mut ret = 0;
		let mut i = 0;
		loop {
			let mut r = 0;
			r += self.simplify_and_fix()?;
			debug!("PARSED[{i}]: SIMPLIFIED: {r}");
			r += self.process_aliases()?;
			debug!("PARSED[{i}]: ALIASES: {r}");
			r += self.process_templates()?;
			debug!("PARSED[{i}]: TEMPLATE {r}");
			if r == 0 {
				break;
			}
			ret += r;
			i += 1;
		}
		Ok(ret)
	}

	/// Is post-processing has been done, we can remove various aliases and
	/// temporary structures we don't need.
	pub fn clear_unneeded(&mut self) -> Result<()> {
		self.aliases.clear();
		self.templates.clear();
		self.idtypes.clear();
		Ok(())
	}

	/// Unpack a template with the given arguments and return a new token
	/// vector.
	///
	/// The returning vector can be passed to [Statement::from_tokens] to get
	/// one or more new statements.
	pub fn unpack_template(tmpl: &TypeRaw, args: &Vec<Token>) -> Result<Vec<Token>> {
		trace!("template token {tmpl:?} | {args:?}");
		let args = Argument::split_tokens(args, &Token::Comma)?;
		trace!("args: {args:?}");
		verify!(args.len() == tmpl.replace.len(), UnexpectedLength);
		let mut ret = Vec::with_capacity(tmpl.tokens.len());
		for token in tmpl.tokens.iter() {
			match token {
				Token::Name(n) => {
					if let Some(idx) = tmpl.argument_index(n) {
						verify!(idx < args.len(), UnexpectedLength);
						ret.append(&mut args[idx].clone());
					} else {
						ret.push(token.clone())
					}
				}
				_ => ret.push(token.clone()),
			}
		}
		Ok(ret)
	}

	#[cfg(test)]
	fn assemble(stmts: &str, consts: &str, arch: Option<Arch>) -> Result<Parsed> {
		let consts = Self::get_consts(consts, arch)?;
		trace!("consts {consts:?}");
		let stmts = Self::get_stmts(stmts)?;
		trace!("stmts {stmts:?} {consts:?}");
		let consts = Consts::new(consts);
		let mut parsed = Parsed::new(consts, stmts)?;
		parsed.insert_builtin()?;
		parsed.postprocess()?;
		Ok(parsed)
	}
	#[cfg(test)]
	fn get_consts(s: &str, arch: Option<Arch>) -> Result<Vec<Const>> {
		let tokens = Token::create_from_str(s)?;
		trace!("tokens {tokens:?}");
		let consts = Const::from_tokens(tokens, arch)?;
		trace!("consts {consts:?}");
		Ok(consts)
	}
	#[cfg(test)]
	fn get_stmts(s: &str) -> Result<Vec<Statement>> {
		let tokens = Token::create_from_str(s)?;
		let stmts = Statement::from_tokens(tokens)?;
		Ok(stmts)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;
	use test::Bencher;
	extern crate test;

	#[bench]
	fn bench_load_text(b: &mut Bencher) {
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
	}

	#[test]
	fn parse_types() {
		assert_eq!(Direction::from_str("in").unwrap(), Direction::In);
		let os = Os::from_str("lINux").unwrap();
		assert_eq!(os.to_string(), "linux");
		assert_eq!(Arch::from_str("amd64").unwrap(), Arch::X86_64);

		assert_eq!(ArgType::Intptr.to_string(), "intptr");

		assert_eq!(Arch::all().len(), 8);
		assert_eq!(Os::all().len(), 9);
		assert_eq!(Os::Akaros.to_string(), "akaros");
		assert_eq!(Os::Trusty, Os::from_str("trusty").unwrap());
		assert_eq!(Os::Netbsd, Os::from_str("NetBsd").unwrap());

		assert_eq!(
			serde_json::Value::try_from(Value::Int(2))
				.unwrap()
				.to_string(),
			"2"
		);

		let opts = vec![ArgOpt::Dir(Direction::In)];

		assert_eq!(ArgOpt::direction(&opts, &Direction::Out), Direction::In);
		assert!(!ArgOpt::same_direction(&opts, &Direction::Out));
	}

	#[test]
	fn single_include0() {
		let s1 = r#"arches = amd64"#;
		let s2 = r#"
include <linux/socket.h>
include <linux/ptrace.h>
include <linux/resource.h>		
		"#;
		let _p = Parsed::assemble(s2, s1, None).unwrap();
	}

	#[test]
	fn single_ints0() {
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
		let p = Parsed::assemble(s2, s1, None).unwrap();
		let _r = p.consts.find_name_arch("__NR_fake", &Arch::X86_64).unwrap();
		assert!(p.consts.find_name_arch("__NR_fake", &Arch::X86).is_none());
		assert_eq!(p.consts.find_sysno("fake", &Arch::X86_64).unwrap(), 1);
		assert!(p.consts.find_sysno("fake", &Arch::X86).is_none());
	}

	#[test]
	fn path0() {
		let p = PathBuf::from("abcd_amd64.const");
		assert_eq!(
			Consts::get_arch_from_path(p.as_path()).unwrap().unwrap(),
			Arch::X86_64
		);
		let p = PathBuf::from("abcd_qwer.const");
		assert!(Consts::get_arch_from_path(p.as_path()).is_err());
	}

	#[test]
	fn single_calls0() {
		let s1 = r#"
arches = amd64
__NR_fake = 1
"#;
		let s2 = r#"
# Should be ignored
meta arches["386", "amd64", "arm", "arm64"]
meta noextract

abcd {
	a int32
}

resource fd[int32]
syz_func(a fd)
fake(a fd)
fake(a ptr[in, abcd])
fake(a ptr[in, array[int32]])
		"#;
		let _p = Parsed::assemble(s2, s1, None).unwrap();
	}

	#[test]
	fn single_const0() {
		let s1 = r#"arches = amd64"#;
		let s2 = r#"
abcd {
	a0 const[42, int32]
	a1 const["hello_world", string]
}
		"#;
		let _p = Parsed::assemble(s2, s1, None).unwrap();
	}

	#[test]
	fn single_const1() {
		let s1 = r#"
# Code generated by syz-sysgen. DO NOT EDIT.
arches = 386, amd64, arm, arm64, mips64le, ppc64le, riscv64, s390x
ACL_EXECUTE = 1
AT_FDCWD = 18446744073709551516
__NR_lgetxattr = 9, 386:arm:230, amd64:192, mips64le:5184, ppc64le:213, s390x:228
		"#;
		let consts = Parsed::get_consts(s1, None).unwrap();
		let mut consts = Consts { consts };
		assert_eq!(consts.find_sysno("lgetxattr", &Arch::X86).unwrap(), 230);
		assert_eq!(consts.find_sysno("lgetxattr", &Arch::X86_64).unwrap(), 192);
		assert_eq!(consts.find_sysno("lgetxattr", &Arch::Riscv64).unwrap(), 9);

		let _r = consts.find_name_arch("AT_FDCWD", &Arch::X86_64).unwrap();

		let ins = Const::new("ACL_EXECUTE", Value::Int(1), vec![Arch::X86_64]);
		assert!(!consts.add_if_new(ins));

		let ins = Const::new("SOME_OTHER_VAL", Value::Int(2), vec![Arch::X86_64]);
		assert_eq!(consts.add_vec(vec![ins]), 1);
	}
	#[test]
	fn single_const2() {
		let s1 = r#"
# Code generated by syz-sysgen. DO NOT EDIT.
arches = amd64
AT_FDCWD = ???
CONS_GETVERS = amd64:1074029386
KDDISABIO = amd64:536890173
		"#;
		let _consts = Parsed::get_consts(s1, None).unwrap();
	}

	#[test]
	fn single_struct0() {
		let s1 = r#"arches = amd64"#;
		let s2 = r#"
type qwerty int32
type asdfgh int64[0:5, 8]
type zxcv[T] int32[T:100]
type hjkl[T,Y] int32[T:Y]
flagvals = 1, 42, 84
abcd {
	a0 qwerty
	a1 asdfgh
	a2 zxcv[9]
	a3 hjkl[1,5]
	a4 int64 (out_overlay)
	a5 ptr[in, int64]
	a6 ptr[out, int32],
	a7 buffer[out]
	a8 len[a7, intptr]
	a9 offsetof[a3, int32]
	aa ptr[in, string["abcd"]]
	ab ptr[in, text[target], opt]
	ac vma64
	ad proc[1, 100, int16]
	ae fmt[oct, int64]
	af array[int8, 16]
	b0 int32[0:2]
	b1 int32:12
	b2 flags[flagvals, int32]
	b3 ptr[in, glob["/sys/**/*:-/sys/power/state"]]
	b4 ptr[in, compressed_image]
	b5 fileoff[intptr]
} [packed]

jkh [
	b0 intptr
	b1 int8
] [varlen]
		"#;
		let p = Parsed::assemble(s2, s1, None).unwrap();
		let _n = serde_json::to_string(&p).unwrap();
	}

	#[test]
	fn single_resource0() {
		let s1 = r#"arches = amd64"#;
		let s2 = r#"
resource fd[int32]
resource afd[fd]: -1

ioctl$BINDER_SET_CONTEXT_MGR_EXT(fd fd_binder, cmd const[BINDER_SET_CONTEXT_MGR_EXT], arg ptr[in, flat_binder_object_t[BINDER_TYPE_BINDER, binder_node]])
		"#;
		let p = Parsed::assemble(s2, s1, None).unwrap();
		let r = serde_json::to_value(&p).unwrap();
		let _r = serde_json::to_string(&r).unwrap();
	}

	#[test]
	fn single_typealias0() {
		let s1 = r#"arches = amd64"#;
		let s2 = r#"
type bool32 int32[0:1]
		"#;
		let _p = Parsed::assemble(s2, s1, None).unwrap();
	}

	#[test]
	fn single_flags0() {
		let s1 = r#"arches = amd64"#;
		let s2 = r#"
name1 = 1, 2, 4
name1 = 1,2,4
name2 = "hello"
name3 = "hello", "world", "!"
name4 = "hello","world","!"
name5 = "hello world"
		"#;
		let _p = Parsed::assemble(s2, s1, None).unwrap();
	}

	#[test]
	fn single_typetemplate0() {
		let s1 = r#"arches = amd64"#;
		let s2 = r#"
type alignptr[T] {
	v   T
} [align[PTR_SIZE]]

some_struct {
	a0 alignptr[int32]
	csum csum[tcp_packet, pseudo, IPPROTO_TCP, int16be]
}
		"#;
		let _p = Parsed::assemble(s2, s1, None).unwrap();
	}

	#[test]
	fn single_syscall0() {
		let s1 = r#"
arches = amd64
__NR_fake1 = 1
		"#;
		let s2 = r#"
# Same function name, but different args is not allowed in Syzlang, but we
# don't care during testing
fake1()
fake1$sub() int32
fake1(val int64)
fake1(val const[0]) (timeout[3000], prog_timeout[3000])
fake1(addr vma)
		"#;
		let _p = Parsed::assemble(s2, s1, None).unwrap();
	}

	#[test]
	fn single_define() {
		let s1 = r#"
arches = amd64
__NR_fake1 = 1
AT_FDCWD = 18446744073709551516
		"#;
		let s2 = r#"
define ABCD 1
"#;
		let _p = Parsed::assemble(s2, s1, None).unwrap();
	}

	#[test]
	fn test_empty() {
		let consts = r#"
		"#;
		let stmts = r#"
		"#;
		let p = Parsed::assemble(stmts, consts, None).unwrap();

		assert!(p.consts.consts.is_empty());
	}

	#[test]
	fn test_arches() {
		let s = r#"arches = 386, amd64, arm, arm64, mips64le, ppc64le, riscv64, s390x
ADDR_COMPAT_LAYOUT = 2097152
ARCH_SHSTK_UNLOCK = 20484, arm:arm64:mips64le:ppc64le:riscv64:s390x:???
"#;
		let tokens = Token::create_from_str(s).unwrap();
		let _arches = Const::from_tokens(tokens, None).unwrap();
	}

	#[test]
	fn test_statements() {
		let s = "include <asm/prctl.h>";
		let tokens = Token::create_from_str(s).unwrap();
		debug!("tokens: {tokens:?}");
		let stmts = Statement::from_tokens(tokens).unwrap();
		debug!("stmts: {stmts:?}");

		let s = "resource fd[int32]: AT_FDCWD";
		let tokens = Token::create_from_str(s).unwrap();
		debug!("tokens: {tokens:?}");
		let stmts = Statement::from_tokens(tokens).unwrap();
		debug!("stmts: {stmts:?}");

		let s = "resource gid[int32]: 0, -1, 0xee00, 0xee01";
		let tokens = Token::create_from_str(s).unwrap();
		debug!("tokens: {tokens:?}");
		let stmts = Statement::from_tokens(tokens).unwrap();
		debug!("stmts: {stmts:?}");

		let s = "type signalno int32[0:65]";
		let tokens = Token::create_from_str(s).unwrap();
		let _stmts = Statement::from_tokens(tokens).unwrap();

		let s = r#"type iovec[DIR, T] { 
			addr    ptr[DIR, T]
			len len[addr, intptr]
		}"#;

		let tokens = Token::create_from_str(s).unwrap();
		debug!("tokens: {tokens:?}");
		let stmts = Statement::from_tokens(tokens).unwrap();
		debug!("stmts: {stmts:?}");

		let s = "pkey_alloc(flags const[0]) pkey";
		let tokens = Token::create_from_str(s).unwrap();
		let _stmts = Statement::from_tokens(tokens).unwrap();

		let s = r#"openat$sysfs(dir ptr[in, glob["/sys/**/*:-/sys/power/state"]]) fd"#;
		let tokens = Token::create_from_str(s).unwrap();
		let _stmts = Statement::from_tokens(tokens).unwrap();

		let s = "readv(fd fd, vec ptr[in, array[iovec_out]], vlen len[vec])";
		let tokens = Token::create_from_str(s).unwrap();
		let _stmts = Statement::from_tokens(tokens).unwrap();

		let s = "open(file ptr[in, filename], flags flags[open_flags], mode flags[open_mode]) fd";
		let tokens = Token::create_from_str(s).unwrap();
		let _stmts = Statement::from_tokens(tokens).unwrap();

		let s = r#"rseq {
			cpu_id_start    const[0, int32]
			cpu_id      const[0, int32]
			rseq_cs     ptr64[in, rseq_cs, opt] 
			flags       flags[rseq_cs_flags, int32]
			int         int32 (in)
		} [align[32]]"#;
		let tokens = Token::create_from_str(s).unwrap();
		let _stmts = Statement::from_tokens(tokens).unwrap();

		let s = r#"sigevent_u [
			tid pid
			thr sigevent_thread
		]"#;
		let tokens = Token::create_from_str(s).unwrap();
		let _stmts = Statement::from_tokens(tokens).unwrap();

		let s = "fid_type = FILEID_ROOT, FILEID_INO32_GEN, FILEID_INO32_GEN_PARENT, FILEID_BTRFS_WITHOUT_PARENT, FILEID_BTRFS_WITH_PARENT, FILEID_BTRFS_WITH_PARENT_ROOT, FILEID_UDF_WITHOUT_PARENT, FILEID_UDF_WITH_PARENT, FILEID_NILFS_WITHOUT_PARENT, FILEID_NILFS_WITH_PARENT, FILEID_FAT_WITHOUT_PARENT, FILEID_FAT_WITH_PARENT, FILEID_LUSTRE, FILEID_KERNFS";
		let tokens = Token::create_from_str(s).unwrap();
		let _stmts = Statement::from_tokens(tokens).unwrap();

		let s = "define SIGEVENT_SIZE    sizeof(struct sigevent)";
		let tokens = Token::create_from_str(s).unwrap();
		let _stmts = Statement::from_tokens(tokens).unwrap();
	}
}
