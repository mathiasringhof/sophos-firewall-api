use quick_xml::escape::escape;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::{Action, Error, Result, SophosConnection, SophosRequest};

pub fn build_request_xml(connection: &SophosConnection, request: &SophosRequest) -> Result<String> {
    validate_tag(&request.resource)?;
    if let Some(object_key) = &request.object_key {
        validate_tag(object_key)?;
    }
    if let Some(set_operation) = &request.set_operation {
        validate_set_operation(set_operation)?;
    }
    validate_object_name(request.object_name.as_deref())?;
    let object_key = request.object_key.as_deref().unwrap_or("Name");

    let login = format!(
        "<Login><Username>{}</Username><Password>{}</Password></Login>",
        text(&connection.username),
        text(&connection.password),
    );

    let body = match request.action {
        Action::Read => build_get_xml(
            &request.resource,
            request.object_name.as_deref(),
            object_key,
        ),
        Action::Create => build_set_xml(
            request.set_operation.as_deref().unwrap_or("add"),
            &request.resource,
            request.object_name.as_deref(),
            object_key,
            &request.payload,
        )?,
        Action::Update => build_set_xml(
            request.set_operation.as_deref().unwrap_or("update"),
            &request.resource,
            request.object_name.as_deref(),
            object_key,
            &request.payload,
        )?,
        Action::Delete => build_remove_xml(
            &request.resource,
            request.object_name.as_deref(),
            object_key,
        )?,
    };

    Ok(format!("<Request>{login}{body}</Request>"))
}

fn build_get_xml(resource: &str, object_name: Option<&str>, object_key: &str) -> String {
    match object_name {
        Some(name) => format!(
            "<Get><{resource}><Filter><key name=\"{object_key}\" criteria=\"=\">{}</key></Filter></{resource}></Get>",
            text(name),
        ),
        None => format!("<Get><{resource}/></Get>"),
    }
}

fn build_set_xml(
    operation: &str,
    resource: &str,
    object_name: Option<&str>,
    object_key: &str,
    payload: &Value,
) -> Result<String> {
    let mut fields: BTreeMap<String, Value> = match payload {
        Value::Null => BTreeMap::new(),
        Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => {
            return Err(Error::InvalidRequest(
                "payload must be a JSON object".to_string(),
            ));
        }
    };

    if let Some(name) = object_name {
        fields
            .entry(object_key.to_string())
            .or_insert_with(|| Value::String(name.to_string()));
    }

    let mut inner = String::new();
    for (key, value) in fields {
        validate_tag(&key)?;
        value_to_xml(&mut inner, &key, &value)?;
    }

    Ok(format!(
        "<Set operation=\"{operation}\"><{resource}>{inner}</{resource}></Set>"
    ))
}

fn build_remove_xml(resource: &str, object_name: Option<&str>, object_key: &str) -> Result<String> {
    let name = object_name
        .ok_or_else(|| Error::InvalidRequest("delete requires object_name".to_string()))?;
    Ok(format!(
        "<Remove><{resource}><{object_key}>{}</{object_key}></{resource}></Remove>",
        text(name)
    ))
}

fn value_to_xml(out: &mut String, tag: &str, value: &Value) -> Result<()> {
    match value {
        Value::Null => out.push_str(&format!("<{tag}/>")),
        Value::Bool(value) => out.push_str(&format!("<{tag}>{value}</{tag}>")),
        Value::Number(value) => out.push_str(&format!("<{tag}>{value}</{tag}>")),
        Value::String(value) => out.push_str(&format!("<{tag}>{}</{tag}>", text(value))),
        Value::Array(values) => {
            for value in values {
                value_to_xml(out, tag, value)?;
            }
        }
        Value::Object(map) => {
            out.push_str(&format!("<{tag}>"));
            for (child_tag, child_value) in map {
                validate_tag(child_tag)?;
                value_to_xml(out, child_tag, child_value)?;
            }
            out.push_str(&format!("</{tag}>"));
        }
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<()> {
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return Err(Error::InvalidRequest("empty XML tag".to_string()));
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(Error::InvalidRequest(format!("invalid XML tag {tag:?}")));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(Error::InvalidRequest(format!("invalid XML tag {tag:?}")));
    }
    Ok(())
}

fn validate_object_name(object_name: Option<&str>) -> Result<()> {
    if let Some(name) = object_name
        && name.trim().is_empty()
    {
        return Err(Error::InvalidRequest(
            "object_name must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_set_operation(operation: &str) -> Result<()> {
    if matches!(operation, "add" | "update" | "set") {
        Ok(())
    } else {
        Err(Error::InvalidRequest(format!(
            "invalid Set operation {operation:?}"
        )))
    }
}

fn text(value: &str) -> String {
    escape(value).into_owned()
}
