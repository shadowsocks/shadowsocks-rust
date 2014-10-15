extern crate serialize;

use serialize::{Decodable, Encodable};
use serialize::json;
use std::io::{File, Read, Open};

use std::to_string::ToString;
use std::fmt::{Show, Formatter, mod};

use std::option::Option;

#[deriving(Encodable, Clone)]
pub struct Config {
    pub server: String,
    pub local: String,
    pub server_port: u16,
    pub local_port: u16,
    pub password: String,
    pub method: String,
    pub timeout: Option<u64>,
    pub fast_open: bool,
}

impl Config {
    pub fn new() -> Config {
        Config{
            server: "127.0.0.1".to_string(),
            local: "127.0.0.1".to_string(),
            server_port: 8000,
            local_port: 8000,
            password: "".to_string(),
            method: "aes-256-cfb".to_string(),
            timeout: None,
            fast_open: false,
        }
    }

    fn parse_json_object(o: &json::JsonObject) -> Config {
        let mut config = Config::new();

        for (key, value) in o.iter() {
            match key.as_slice() {
                "server" => {
                    config.server = value.as_string().unwrap().to_string();
                },
                "server_port" => {
                    config.server_port = value.as_i64().unwrap() as u16;
                },
                "local_port" => {
                    config.local_port = value.as_i64().unwrap() as u16;
                },
                "password" => {
                    config.password = value.as_string().unwrap().to_string();
                },
                "method" => {
                    config.method = value.as_string().unwrap().to_string();
                },
                "timeout" => {
                    config.timeout = Some(value.as_i64().unwrap() as u64);
                },
                "fast_open" => {
                    config.fast_open = value.as_boolean().unwrap();
                },
                _ => (),
            }
        }

        config
    }

    pub fn load_from_str(s: &str) -> Config {
        let object = json::from_str(s).unwrap();
        let json_object = object.as_object().unwrap();
        Config::parse_json_object(json_object)
    }

    pub fn load_from_file(filename: &str) -> Config {
        let reader = &mut File::open_mode(&Path::new(filename), Open, Read).unwrap();

        let object = json::from_reader(reader).unwrap();
        let json_object = object.as_object().unwrap();
        Config::parse_json_object(json_object)
    }
}

impl Show for Config {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", json::encode(self))
    }
}
