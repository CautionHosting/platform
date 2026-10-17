use crate::{PortSpec, TrafficRule};
use serde::{Deserialize, Deserializer};

/// Missing optional attributes default to `None`; present nulls are not omissions.
pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    strict(deserializer).map(Some)
}

pub(crate) fn strict<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    T::deserialize(value).map_err(serde::de::Error::custom)
}

impl<'de> Deserialize<'de> for TrafficRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(deserialize_with = "strict")]
            cidr_ipv4: String,
            #[serde(default, deserialize_with = "present")]
            port: Option<u16>,
            #[serde(default, deserialize_with = "present")]
            start_port: Option<u16>,
            #[serde(default, deserialize_with = "present")]
            end_port: Option<u16>,
            #[serde(default, deserialize_with = "present")]
            ip_protocol: Option<String>,
        }

        let fields = Fields::deserialize(deserializer)?;
        let port_spec = match (fields.port, fields.start_port, fields.end_port) {
            (None, None, None) => None,
            (Some(port), None, None) if port > 0 => Some(PortSpec::Exact { port }),
            (None, Some(start_port), Some(end_port))
                if start_port > 0 && start_port <= end_port =>
            {
                Some(PortSpec::FromTo {
                    start_port,
                    end_port,
                })
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "use a nonzero port or a complete, ordered nonzero start_port/end_port range, not both",
                ));
            }
        };
        Ok(TrafficRule {
            cidr_ipv4: fields.cidr_ipv4,
            port_spec,
            ip_protocol: fields.ip_protocol,
        })
    }
}
