use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SophosResponse {
    pub resources: Vec<ResourceResponse>,
    pub raw_xml: String,
}

impl SophosResponse {
    pub fn resource(&self, name: &str) -> Option<&ResourceResponse> {
        self.resources.iter().find(|resource| resource.name == name)
    }

    pub fn first_resource(&self) -> Option<&ResourceResponse> {
        self.resources.first()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceResponse {
    pub name: String,
    pub status: ResourceStatus,
    pub body_xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceStatus {
    pub code: Option<String>,
    pub text: String,
}

struct CurrentResource {
    name: String,
    status: Option<ResourceStatus>,
    body: Writer<Vec<u8>>,
    depth: usize,
    in_status: bool,
    status_depth: usize,
    status_code: Option<String>,
    status_text: String,
}

impl CurrentResource {
    fn new(name: String) -> Self {
        Self {
            name,
            status: None,
            body: Writer::new(Vec::new()),
            depth: 0,
            in_status: false,
            status_depth: 0,
            status_code: None,
            status_text: String::new(),
        }
    }

    fn write_event<'a>(&mut self, event: impl Into<Event<'a>>) -> Result<()> {
        self.body
            .write_event(event)
            .map_err(|error| Error::ResponseParse(error.to_string()))
    }

    fn finish(self) -> Result<ResourceResponse> {
        let body_xml = String::from_utf8(self.body.into_inner())
            .map_err(|error| Error::ResponseParse(error.to_string()))?;
        let status = self.status.unwrap_or_else(|| ResourceStatus {
            code: None,
            text: String::new(),
        });
        Ok(ResourceResponse {
            name: self.name,
            status,
            body_xml,
        })
    }
}

pub fn parse_response_xml(xml: &str) -> Result<SophosResponse> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut resources: Vec<ResourceResponse> = Vec::new();
    let mut current: Option<CurrentResource> = None;

    loop {
        match reader
            .read_event()
            .map_err(|error| Error::ResponseParse(error.to_string()))?
        {
            Event::Start(element) => {
                let name = element_name(&element)?;
                if let Some(resource) = current.as_mut() {
                    resource.depth += 1;
                    if name == "Status" && resource.depth == 2 {
                        resource.in_status = true;
                        resource.status_depth = resource.depth;
                        resource.status_code = status_code(&element)?;
                        resource.status_text.clear();
                    }
                    resource.write_event(Event::Start(element.borrow()))?;
                } else if is_resource_start(&stack, &name) {
                    let mut resource = CurrentResource::new(name.clone());
                    resource.depth = 1;
                    resource.write_event(Event::Start(element.borrow()))?;
                    current = Some(resource);
                }
                stack.push(name);
            }
            Event::Empty(element) => {
                let name = element_name(&element)?;
                if let Some(resource) = current.as_mut() {
                    if name == "Status" && resource.depth == 1 {
                        resource.status = Some(ResourceStatus {
                            code: status_code(&element)?,
                            text: String::new(),
                        });
                    }
                    resource.write_event(Event::Empty(element.borrow()))?;
                } else if is_resource_start(&stack, &name) {
                    let mut resource = CurrentResource::new(name.clone());
                    resource.depth = 1;
                    resource.write_event(Event::Empty(element.borrow()))?;
                    resources.push(resource.finish()?);
                }
            }
            Event::Text(text) => {
                if let Some(resource) = current.as_mut() {
                    if resource.in_status {
                        let content = text
                            .xml_content()
                            .map_err(|error| Error::ResponseParse(error.to_string()))?;
                        resource.status_text.push_str(&content);
                    }
                    resource.write_event(Event::Text(text.borrow()))?;
                }
            }
            Event::CData(cdata) => {
                if let Some(resource) = current.as_mut() {
                    if resource.in_status {
                        let content = cdata
                            .xml_content()
                            .map_err(|error| Error::ResponseParse(error.to_string()))?;
                        resource.status_text.push_str(&content);
                    }
                    resource.write_event(Event::CData(cdata.borrow()))?;
                }
            }
            Event::End(element) => {
                let name = String::from_utf8_lossy(element.name().as_ref()).into_owned();
                let mut finished = None;

                if let Some(resource) = current.as_mut() {
                    resource.write_event(Event::End(element.borrow()))?;

                    if resource.in_status
                        && resource.depth == resource.status_depth
                        && name == "Status"
                    {
                        resource.in_status = false;
                        resource.status = Some(ResourceStatus {
                            code: resource.status_code.take(),
                            text: resource.status_text.trim().to_string(),
                        });
                    }

                    if resource.depth == 1 && name == resource.name {
                        finished = current.take();
                    } else {
                        resource.depth = resource.depth.saturating_sub(1);
                    }
                }

                let popped = stack.pop();
                if popped.as_deref() != Some(&name) {
                    return Err(Error::ResponseParse(format!(
                        "unexpected closing XML tag {name:?}"
                    )));
                }

                if let Some(resource) = finished {
                    let response = resource.finish()?;
                    validate_resource_status(&response)?;
                    resources.push(response);
                }
            }
            Event::Comment(comment) => {
                if let Some(resource) = current.as_mut() {
                    resource.write_event(Event::Comment(comment.borrow()))?;
                }
            }
            Event::PI(pi) => {
                if let Some(resource) = current.as_mut() {
                    resource.write_event(Event::PI(pi.borrow()))?;
                }
            }
            Event::DocType(doc_type) => {
                if let Some(resource) = current.as_mut() {
                    resource.write_event(Event::DocType(doc_type.borrow()))?;
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(resource) = current.as_mut() {
                    resource.write_event(Event::GeneralRef(reference.borrow()))?;
                }
            }
            Event::Decl(_) => {}
            Event::Eof => break,
        }
    }

    if current.is_some() {
        return Err(Error::ResponseParse(
            "unexpected end of XML while parsing resource".to_string(),
        ));
    }

    Ok(SophosResponse {
        resources,
        raw_xml: xml.to_string(),
    })
}

fn is_resource_start(stack: &[String], name: &str) -> bool {
    matches!(stack, [response] if response == "Response") && name != "Status"
}

fn element_name(element: &BytesStart<'_>) -> Result<String> {
    let name = element.name();
    let name = std::str::from_utf8(name.as_ref())
        .map_err(|error| Error::ResponseParse(error.to_string()))?;
    Ok(name.to_string())
}

fn status_code(element: &BytesStart<'_>) -> Result<Option<String>> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| Error::ResponseParse(error.to_string()))?;
        if attribute.key.as_ref() == b"code" {
            return Ok(Some(
                attribute
                    .unescape_value()
                    .map_err(|error| Error::ResponseParse(error.to_string()))?
                    .into_owned(),
            ));
        }
    }
    Ok(None)
}

fn validate_resource_status(response: &ResourceResponse) -> Result<()> {
    if response.status.text == "Number of records Zero." {
        return Err(Error::ZeroRecords {
            resource: response.name.clone(),
        });
    }

    if let Some(code) = &response.status.code
        && !code.starts_with('2')
    {
        return Err(Error::ApiError {
            resource: response.name.clone(),
            code: Some(code.clone()),
            message: response.status.text.clone(),
        });
    }

    Ok(())
}
