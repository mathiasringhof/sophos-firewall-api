use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::{Map, Value};

use crate::{
    Action, Error, ResourceResponse, Result, SophosClient, SophosRequest, SophosTransport,
};

pub(super) type FieldMap = Map<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ApiObject {
    name: String,
    fields: FieldMap,
}

impl ApiObject {
    pub(super) fn new(name: String, fields: FieldMap) -> Self {
        Self { name, fields }
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn fields(&self) -> &FieldMap {
        &self.fields
    }

    pub(super) fn field(&self, path: &str) -> Option<&str> {
        let mut current = ValueRef::Map(&self.fields);
        for part in path.split('.') {
            current = match current {
                ValueRef::Map(map) => map.get(part).map(ValueRef::Value)?,
                ValueRef::Value(Value::Object(map)) => map.get(part).map(ValueRef::Value)?,
                ValueRef::Value(Value::Array(values)) => {
                    values.first().and_then(|value| match value {
                        Value::Object(map) => map.get(part).map(ValueRef::Value),
                        _ => None,
                    })?
                }
                ValueRef::Value(_) => return None,
            };
        }

        match current {
            ValueRef::Value(Value::String(value)) => Some(value),
            _ => None,
        }
    }
}

enum ValueRef<'a> {
    Map(&'a FieldMap),
    Value(&'a Value),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ObjectFields {
    name: String,
    fields: FieldMap,
}

impl ObjectFields {
    pub(super) fn new(label: &str, name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            name: normalize_name(label, name.as_ref())?,
            fields: FieldMap::new(),
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn fields(&self) -> &FieldMap {
        &self.fields
    }

    pub(super) fn into_parts(self) -> (String, FieldMap) {
        (self.name, self.fields)
    }

    pub(super) fn with_field(
        mut self,
        field: impl AsRef<str>,
        value: impl Into<Value>,
    ) -> Result<Self> {
        let field = normalize_field_name(field.as_ref())?;
        let value = value.into();
        validate_value_tags(&value)?;
        self.fields.insert(field, value);
        Ok(self)
    }
}

pub(super) fn normalize_name(label: &str, value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(Error::InvalidRequest(format!("{label} must not be empty")));
    }
    Ok(normalized.to_string())
}

pub(super) fn payload_with_key(key: &str, name: &str, fields: &FieldMap) -> Value {
    let mut payload = fields.clone();
    payload.insert(key.to_string(), Value::String(name.to_string()));
    Value::Object(payload)
}

pub(super) fn merge_fields(base: &mut FieldMap, updates: FieldMap) {
    for (key, value) in updates {
        match (base.get_mut(&key), value) {
            (Some(Value::Object(base_object)), Value::Object(update_object)) => {
                merge_fields(base_object, update_object);
            }
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

pub(super) fn first_named_resource(
    resources: Vec<ResourceResponse>,
    resource_name: &str,
) -> Result<ResourceResponse> {
    resources
        .into_iter()
        .find(|resource| resource.name == resource_name)
        .ok_or_else(|| Error::ResponseParse(format!("missing {resource_name} response")))
}

pub(super) fn objects_from_response(
    resources: &[ResourceResponse],
    resource_name: &str,
    object_key: &str,
    label: &str,
) -> Result<Vec<ApiObject>> {
    let mut objects = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == resource_name)
    {
        let nodes = parse_xml_nodes(&resource.body_xml)?;
        for node in nodes.iter().filter(|node| node.name == resource_name) {
            if let Some(object) = object_from_node(node, object_key, label)? {
                objects.push(object);
            }
        }
    }
    Ok(objects)
}

pub(super) fn singleton_from_response(
    resources: &[ResourceResponse],
    resource_name: &str,
) -> Result<ApiObject> {
    for resource in resources
        .iter()
        .filter(|resource| resource.name == resource_name)
    {
        let nodes = parse_xml_nodes(&resource.body_xml)?;
        if let Some(node) = nodes.iter().find(|node| node.name == resource_name) {
            return Ok(ApiObject::new(
                resource_name.to_string(),
                fields_from_node(node),
            ));
        }
    }

    Err(Error::ResponseParse(format!(
        "missing {resource_name} response"
    )))
}

pub(super) fn validated_field(
    field: impl AsRef<str>,
    value: impl Into<Value>,
) -> Result<(String, Value)> {
    let field = normalize_field_name(field.as_ref())?;
    let value = value.into();
    validate_value_tags(&value)?;
    Ok((field, value))
}

pub(super) fn list_objects<T, O>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    label: &str,
    wrap: impl Fn(ApiObject) -> O,
) -> Result<Vec<O>>
where
    T: SophosTransport,
{
    match client.execute(&SophosRequest::read(resource)) {
        Ok(response) => Ok(
            objects_from_response(&response.resources, resource, key, label)?
                .into_iter()
                .map(wrap)
                .collect(),
        ),
        Err(Error::ZeroRecords {
            resource: empty_resource,
        }) if empty_resource == resource => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

pub(super) fn get_object<T, O>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    label: &str,
    name: impl AsRef<str>,
    wrap: impl Fn(ApiObject) -> O,
) -> Result<Option<O>>
where
    T: SophosTransport,
{
    let name = normalize_name(label, name.as_ref())?;
    let request = SophosRequest::read(resource)
        .for_object(name.clone())
        .with_object_key(key);

    match client.execute(&request) {
        Ok(response) => Ok(
            objects_from_response(&response.resources, resource, key, label)?
                .into_iter()
                .find(|object| object.name() == name)
                .map(wrap),
        ),
        Err(Error::ZeroRecords {
            resource: empty_resource,
        }) if empty_resource == resource => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn create_object<T>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    fields: ObjectFields,
) -> Result<ResourceResponse>
where
    T: SophosTransport,
{
    let request = SophosRequest::new(Action::Create, resource)
        .for_object(fields.name())
        .with_object_key(key)
        .with_payload(payload_with_key(key, fields.name(), fields.fields()));
    first_named_resource(client.execute(&request)?.resources, resource)
}

pub(super) fn update_object<T>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    name: &str,
    mut existing: FieldMap,
    updates: FieldMap,
) -> Result<ResourceResponse>
where
    T: SophosTransport,
{
    merge_fields(&mut existing, updates);
    let request = SophosRequest::new(Action::Update, resource)
        .for_object(name)
        .with_object_key(key)
        .with_payload(payload_with_key(key, name, &existing));
    first_named_resource(client.execute(&request)?.resources, resource)
}

pub(super) fn delete_object<T>(
    client: &SophosClient<T>,
    resource: &str,
    key: &str,
    name: &str,
) -> Result<ResourceResponse>
where
    T: SophosTransport,
{
    let request = SophosRequest::new(Action::Delete, resource)
        .for_object(name)
        .with_object_key(key);
    first_named_resource(client.execute(&request)?.resources, resource)
}

pub(super) fn get_singleton<T>(client: &SophosClient<T>, resource: &str) -> Result<ApiObject>
where
    T: SophosTransport,
{
    let response = client.execute(&SophosRequest::read(resource))?;
    singleton_from_response(&response.resources, resource)
}

pub(super) fn update_singleton<T>(
    client: &SophosClient<T>,
    resource: &str,
    mut existing: FieldMap,
    updates: FieldMap,
) -> Result<ResourceResponse>
where
    T: SophosTransport,
{
    merge_fields(&mut existing, updates);
    let request =
        SophosRequest::new(Action::Update, resource).with_payload(Value::Object(existing));
    first_named_resource(client.execute(&request)?.resources, resource)
}

fn object_from_node(node: &XmlNode, object_key: &str, label: &str) -> Result<Option<ApiObject>> {
    let Some(name) = node.child_text(object_key) else {
        return Ok(None);
    };
    let name = normalize_name(label, name)?;
    let fields = fields_from_node(node);
    Ok(Some(ApiObject::new(name, fields)))
}

fn fields_from_node(node: &XmlNode) -> FieldMap {
    let mut fields = FieldMap::new();
    for child in &node.children {
        let value = value_from_node(child);
        insert_grouped_value(&mut fields, child.name.clone(), value);
    }
    fields
}

fn value_from_node(node: &XmlNode) -> Value {
    if node.children.is_empty() {
        Value::String(node.text.trim().to_string())
    } else {
        Value::Object(fields_from_node(node))
    }
}

fn insert_grouped_value(fields: &mut FieldMap, key: String, value: Value) {
    match fields.remove(&key) {
        None => {
            fields.insert(key, value);
        }
        Some(Value::Array(mut values)) => {
            values.push(value);
            fields.insert(key, Value::Array(values));
        }
        Some(existing) => {
            fields.insert(key, Value::Array(vec![existing, value]));
        }
    }
}

fn normalize_field_name(field: &str) -> Result<String> {
    let field = field.trim();
    validate_xml_tag(field)?;
    Ok(field.to_string())
}

fn validate_value_tags(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                validate_xml_tag(key)?;
                validate_value_tags(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_value_tags(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn validate_xml_tag(tag: &str) -> Result<()> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct XmlNode {
    name: String,
    text: String,
    children: Vec<XmlNode>,
}

impl XmlNode {
    fn new(name: String) -> Self {
        Self {
            name,
            text: String::new(),
            children: Vec::new(),
        }
    }

    fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|child| child.name == name)
    }

    fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).and_then(|child| {
            let text = child.text.trim();
            if text.is_empty() { None } else { Some(text) }
        })
    }
}

fn parse_xml_nodes(xml: &str) -> Result<Vec<XmlNode>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut roots = Vec::new();
    let mut stack: Vec<XmlNode> = Vec::new();

    loop {
        match reader
            .read_event()
            .map_err(|error| Error::ResponseParse(error.to_string()))?
        {
            Event::Start(element) => {
                let name = std::str::from_utf8(element.name().as_ref())
                    .map_err(|error| Error::ResponseParse(error.to_string()))?
                    .to_string();
                stack.push(XmlNode::new(name));
            }
            Event::Empty(element) => {
                let name = std::str::from_utf8(element.name().as_ref())
                    .map_err(|error| Error::ResponseParse(error.to_string()))?
                    .to_string();
                push_node(XmlNode::new(name), &mut stack, &mut roots);
            }
            Event::Text(text) => {
                if let Some(node) = stack.last_mut() {
                    let content = text
                        .xml_content()
                        .map_err(|error| Error::ResponseParse(error.to_string()))?;
                    node.text.push_str(&content);
                }
            }
            Event::CData(text) => {
                if let Some(node) = stack.last_mut() {
                    let content = text
                        .xml_content()
                        .map_err(|error| Error::ResponseParse(error.to_string()))?;
                    node.text.push_str(&content);
                }
            }
            Event::End(element) => {
                let name = std::str::from_utf8(element.name().as_ref())
                    .map_err(|error| Error::ResponseParse(error.to_string()))?
                    .to_string();
                let node = stack.pop().ok_or_else(|| {
                    Error::ResponseParse(format!("unexpected closing XML tag {name:?}"))
                })?;
                if node.name != name {
                    return Err(Error::ResponseParse(format!(
                        "unexpected closing XML tag {name:?}"
                    )));
                }
                push_node(node, &mut stack, &mut roots);
            }
            Event::Eof => break,
            Event::Decl(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::Comment(_)
            | Event::GeneralRef(_) => {}
        }
    }

    if let Some(node) = stack.last() {
        return Err(Error::ResponseParse(format!(
            "unexpected end of XML inside {:?}",
            node.name
        )));
    }

    Ok(roots)
}

fn push_node(node: XmlNode, stack: &mut [XmlNode], roots: &mut Vec<XmlNode>) {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else {
        roots.push(node);
    }
}
