use std::{
    array::TryFromSliceError,
    io::{self, Read as _, Write as _},
    net::IpAddr,
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

use chrono::{DateTime, Utc};
use thiserror::Error;

const REQUEST_MAGIC: u32 = 0x50304601;
const RESPONSE_MAGIC: u32 = 0x50304602;

const REQUEST_SIZE: usize = 21;
const RESPONSE_SIZE: usize = 232;

const STR_MAX: usize = 31;
const STR_SIZE: usize = STR_MAX + 1;

const STATUS_BADQUERY: u32 = 0x00;
const STATUS_OK: u32 = 0x10;
const STATUS_NOMATCH: u32 = 0x20;

const ADDRESS_IPV4: u8 = 0x04;
const ADDRESS_IPV6: u8 = 0x06;

const MATCH_NORMAL: u8 = 0x00;
const MATCH_FUZZY: u8 = 0x01;
const MATCH_GENERIC: u8 = 0x02;
const MATCH_FUZZY_GENERIC: u8 = 0x03;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid magic")]
    InvalidMagic,
    #[error("bad query")]
    BadQuery,
    #[error("timestamp out of range: {0}")]
    TimestampOutOfRange(&'static str),
    #[error("missing data: {0}")]
    MissingData(&'static str),
    #[error("invalid data: {0}")]
    InvalidData(#[from] TryFromSliceError),
}

pub struct P0f(UnixStream);

impl P0f {
    pub fn new<T: AsRef<Path>>(path: T) -> io::Result<Self> {
        let socket = UnixStream::connect(path)?;

        Ok(P0f(socket))
    }

    pub fn query<T: Into<IpAddr>>(&mut self, address: T) -> Result<Option<Response>, Error> {
        let address = address.into();

        let mut request = Vec::with_capacity(REQUEST_SIZE);
        request.extend_from_slice(&REQUEST_MAGIC.to_ne_bytes());

        match address {
            IpAddr::V4(address) => {
                request.push(ADDRESS_IPV4);
                request.extend_from_slice(&address.octets());
                request.extend_from_slice(&[0; 12]);
            }
            IpAddr::V6(address) => {
                request.push(ADDRESS_IPV6);
                request.extend_from_slice(&address.octets());
            }
        }

        self.0.write_all(&request)?;
        let mut response = [0; RESPONSE_SIZE];
        self.0.read_exact(&mut response)?;
        let mut response = BufferReader::new(&response);

        let magic = u32::from_ne_bytes(*response.read_array().ok_or(Error::MissingData("magic"))?);
        if magic != RESPONSE_MAGIC {
            return Err(Error::InvalidMagic);
        }
        let status =
            u32::from_ne_bytes(*response.read_array().ok_or(Error::MissingData("status"))?);
        match status {
            STATUS_BADQUERY => return Err(Error::BadQuery),
            STATUS_OK => {}
            STATUS_NOMATCH => return Ok(None),
            _ => unreachable!(),
        }

        let first_seen = DateTime::from_timestamp(
            u32::from_ne_bytes(
                *response
                    .read_array()
                    .ok_or(Error::MissingData("first_seen"))?,
            ) as i64,
            0,
        )
        .ok_or(Error::TimestampOutOfRange("first_seen"))?;
        let last_seen = DateTime::from_timestamp(
            u32::from_ne_bytes(
                *response
                    .read_array()
                    .ok_or(Error::MissingData("last_seen"))?,
            ) as i64,
            0,
        )
        .ok_or(Error::TimestampOutOfRange("last_seen"))?;
        let total_conn = u32::from_ne_bytes(
            *response
                .read_array()
                .ok_or(Error::MissingData("total_conn"))?,
        );

        let uptime_min = match u32::from_ne_bytes(
            *response
                .read_array()
                .ok_or(Error::MissingData("uptime_min"))?,
        ) {
            0 => None,
            uptime => Some(Duration::from_secs(uptime as u64 * 60)),
        };
        let up_mod_days = Duration::from_secs(
            u32::from_ne_bytes(
                *response
                    .read_array()
                    .ok_or(Error::MissingData("up_mod_days"))?,
            ) as u64
                * 86400,
        );

        let last_nat = match u32::from_ne_bytes(
            *response
                .read_array()
                .ok_or(Error::MissingData("last_nat"))?,
        ) {
            0 => None,
            last_nat => Some(
                DateTime::from_timestamp(last_nat as i64, 0)
                    .ok_or(Error::TimestampOutOfRange("last_seen"))?,
            ),
        };

        let last_chg = match u32::from_ne_bytes(
            *response
                .read_array()
                .ok_or(Error::MissingData("last_chg"))?,
        ) {
            0 => None,
            last_chg => Some(
                DateTime::from_timestamp(last_chg as i64, 0)
                    .ok_or(Error::TimestampOutOfRange("last_chg"))?,
            ),
        };
        let distance = match i16::from_ne_bytes(
            *response
                .read_array()
                .ok_or(Error::MissingData("distance"))?,
        ) {
            -1 => None,
            distance => Some(distance),
        };

        let bad_sw =
            match u8::from_ne_bytes(*response.read_array().ok_or(Error::MissingData("bad_sw"))?) {
                0 => None,
                1 => Some(BadSw::OsDifference),
                2 => Some(BadSw::OutrightMismatch),
                d => {
                    println!("bad_sw: {}", d);
                    unreachable!();
                }
            };
        let os_match_q = match u8::from_ne_bytes(
            *response
                .read_array()
                .ok_or(Error::MissingData("os_match_q"))?,
        ) {
            MATCH_NORMAL => OsMatchQuality::Normal,
            MATCH_FUZZY => OsMatchQuality::Fuzzy,
            MATCH_GENERIC => OsMatchQuality::Generic,
            MATCH_FUZZY_GENERIC => OsMatchQuality::FuzzyGeneric,
            _ => unreachable!(),
        };

        let os_name = match response.get_buffer()[0] {
            0 => None,
            _ => Some(
                String::from_utf8_lossy(
                    &response
                        .read_array::<STR_SIZE>()
                        .ok_or(Error::MissingData("os_name"))?[..STR_SIZE],
                )
                .trim_end_matches('\0')
                .to_string(),
            ),
        };

        let os_flavor = match response.get_buffer()[0] {
            0 => None,
            _ => Some(
                String::from_utf8_lossy(
                    &response
                        .read_array::<STR_SIZE>()
                        .ok_or(Error::MissingData("os_flavor"))?[..STR_SIZE],
                )
                .trim_end_matches('\0')
                .to_string(),
            ),
        };

        let http_name = match response.get_buffer()[0] {
            0 => None,
            _ => Some(
                String::from_utf8_lossy(
                    &response
                        .read_array::<STR_SIZE>()
                        .ok_or(Error::MissingData("http_name"))?[..STR_SIZE],
                )
                .trim_end_matches('\0')
                .to_string(),
            ),
        };

        let http_flavor = match response.get_buffer()[0] {
            0 => None,
            _ => Some(
                String::from_utf8_lossy(
                    &response
                        .read_array::<STR_SIZE>()
                        .ok_or(Error::MissingData("http_flavor"))?[..STR_SIZE],
                )
                .trim_end_matches('\0')
                .to_string(),
            ),
        };

        let link_type = match response.get_buffer()[0] {
            0 => None,
            _ => Some(
                String::from_utf8_lossy(
                    &response
                        .read_array::<STR_SIZE>()
                        .ok_or(Error::MissingData("link_type"))?[..STR_SIZE],
                )
                .trim_end_matches('\0')
                .to_string(),
            ),
        };

        let language = match response.get_buffer()[0] {
            0 => None,
            _ => Some(
                String::from_utf8_lossy(
                    &response
                        .read_array::<STR_SIZE>()
                        .ok_or(Error::MissingData("language"))?[..STR_SIZE],
                )
                .trim_end_matches('\0')
                .to_string(),
            ),
        };

        Ok(Some(Response {
            first_seen,
            last_seen,
            total_conn,
            uptime_min,
            up_mod_days,
            last_nat,
            last_chg,
            distance,
            bad_sw,
            os_match_q,
            os_name,
            os_flavor,
            http_name,
            http_flavor,
            link_type,
            language,
        }))
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Response {
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_conn: u32,
    pub uptime_min: Option<Duration>,
    pub up_mod_days: Duration,
    pub last_nat: Option<DateTime<Utc>>,
    pub last_chg: Option<DateTime<Utc>>,
    pub distance: Option<i16>,
    pub bad_sw: Option<BadSw>,
    pub os_match_q: OsMatchQuality,
    pub os_name: Option<String>,
    pub os_flavor: Option<String>,
    pub http_name: Option<String>,
    pub http_flavor: Option<String>,
    pub link_type: Option<String>,
    pub language: Option<String>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BadSw {
    OsDifference,
    OutrightMismatch,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OsMatchQuality {
    Normal,
    Fuzzy,
    Generic,
    FuzzyGeneric,
}

struct BufferReader<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> BufferReader<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        BufferReader { buffer, pos: 0 }
    }

    fn read_array<const N: usize>(&mut self) -> Option<&'a [u8; N]> {
        if self.pos + N <= self.buffer.len() {
            let slice = &self.buffer[self.pos..self.pos + N];
            self.pos += N;
            // SAFETY: We know that the slice has exactly N elements
            Some(slice.try_into().unwrap())
        } else {
            None
        }
    }

    fn get_buffer(&self) -> &'a [u8] {
        &self.buffer[self.pos..]
    }
}
