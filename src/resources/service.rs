use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    Action, Error, ResourceResponse, Result, SophosClient, SophosRequest, SophosTransport,
};

const URL_GROUP_RESOURCE: &str = "WebFilterURLGroup";
const NAME_KEY: &str = "Name";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlGroup {
    name: String,
    domains: Vec<String>,
}

impl UrlGroup {
    fn new_unchecked(name: String, domains: Vec<String>) -> Self {
        Self { name, domains }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlGroupCreate {
    name: String,
    domains: Vec<String>,
}

impl UrlGroupCreate {
    pub fn new<S, I, D>(name: S, domains: I) -> Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        Ok(Self {
            name: normalize_group_name(name.as_ref())?,
            domains: normalize_domains(domains)?,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }
}

impl From<UrlGroupCreate> for UrlGroup {
    fn from(group: UrlGroupCreate) -> Self {
        Self {
            name: group.name,
            domains: group.domains,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UrlGroupsApi<'a, T> {
    client: &'a SophosClient<T>,
}

impl<T> SophosClient<T>
where
    T: SophosTransport,
{
    pub fn url_groups(&self) -> UrlGroupsApi<'_, T> {
        UrlGroupsApi { client: self }
    }
}

impl<T> UrlGroupsApi<'_, T>
where
    T: SophosTransport,
{
    pub fn list_groups(&self) -> Result<Vec<UrlGroup>> {
        match self
            .client
            .execute(&SophosRequest::read(URL_GROUP_RESOURCE))
        {
            Ok(response) => groups_from_response(&response.resources),
            Err(Error::ZeroRecords { resource }) if resource == URL_GROUP_RESOURCE => {
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    pub fn get_group(&self, name: impl AsRef<str>) -> Result<Option<UrlGroup>> {
        let name = normalize_group_name(name.as_ref())?;
        let request = SophosRequest::read(URL_GROUP_RESOURCE)
            .for_object(name.clone())
            .with_object_key(NAME_KEY);

        match self.client.execute(&request) {
            Ok(response) => Ok(groups_from_response(&response.resources)?
                .into_iter()
                .find(|group| group.name == name)),
            Err(Error::ZeroRecords { resource }) if resource == URL_GROUP_RESOURCE => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn create_group(&self, group: UrlGroupCreate) -> Result<ResourceResponse> {
        let request = SophosRequest::new(Action::Create, URL_GROUP_RESOURCE)
            .for_object(group.name())
            .with_object_key(NAME_KEY)
            .with_set_operation("set")
            .with_payload(group_payload(group.name(), group.domains()));
        first_url_group_resource(self.client.execute(&request)?.resources)
    }

    pub fn add_domains<I, D>(&self, name: impl AsRef<str>, domains: I) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        self.update_domains(name, domains, DomainUpdateAction::Add)
    }

    pub fn remove_domains<I, D>(
        &self,
        name: impl AsRef<str>,
        domains: I,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        self.update_domains(name, domains, DomainUpdateAction::Remove)
    }

    pub fn replace_domains<I, D>(
        &self,
        name: impl AsRef<str>,
        domains: I,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        self.update_domains(name, domains, DomainUpdateAction::Replace)
    }

    pub fn delete_group(&self, name: impl AsRef<str>) -> Result<ResourceResponse> {
        let name = normalize_group_name(name.as_ref())?;
        if self.get_group(&name)?.is_none() {
            return Err(Error::InvalidRequest(format!(
                "URL group '{name}' does not exist"
            )));
        }

        let request = SophosRequest::new(Action::Delete, URL_GROUP_RESOURCE)
            .for_object(name)
            .with_object_key(NAME_KEY);
        first_url_group_resource(self.client.execute(&request)?.resources)
    }

    fn update_domains<I, D>(
        &self,
        name: impl AsRef<str>,
        domains: I,
        action: DomainUpdateAction,
    ) -> Result<ResourceResponse>
    where
        I: IntoIterator<Item = D>,
        D: AsRef<str>,
    {
        let name = normalize_group_name(name.as_ref())?;
        let requested = normalize_domains(domains)?;
        let existing = self
            .get_group(&name)?
            .ok_or_else(|| Error::InvalidRequest(format!("URL group '{name}' does not exist")))?;

        let updated_domains = match action {
            DomainUpdateAction::Add => add_unique(existing.domains, requested),
            DomainUpdateAction::Remove => remove_requested(existing.domains, &requested),
            DomainUpdateAction::Replace => requested,
        };

        let request = SophosRequest::new(Action::Update, URL_GROUP_RESOURCE)
            .for_object(&name)
            .with_object_key(NAME_KEY)
            .with_payload(group_payload(&name, &updated_domains));
        first_url_group_resource(self.client.execute(&request)?.resources)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainUpdateAction {
    Add,
    Remove,
    Replace,
}

fn normalize_group_name(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(Error::InvalidRequest(
            "URL group name must not be empty".to_string(),
        ));
    }
    Ok(normalized.to_string())
}

fn normalize_domains<I, D>(domains: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = D>,
    D: AsRef<str>,
{
    let mut normalized = Vec::new();
    for domain in domains {
        let domain = domain.as_ref().trim();
        if domain.is_empty() {
            return Err(Error::InvalidRequest(
                "domain must not be empty".to_string(),
            ));
        }
        if !normalized.iter().any(|existing| existing == domain) {
            normalized.push(domain.to_string());
        }
    }

    if normalized.is_empty() {
        return Err(Error::InvalidRequest(
            "domains must not be empty".to_string(),
        ));
    }

    Ok(normalized)
}

fn add_unique(mut existing: Vec<String>, requested: Vec<String>) -> Vec<String> {
    for domain in requested {
        if !existing.contains(&domain) {
            existing.push(domain);
        }
    }
    existing
}

fn remove_requested(existing: Vec<String>, requested: &[String]) -> Vec<String> {
    existing
        .into_iter()
        .filter(|domain| !requested.contains(domain))
        .collect()
}

fn group_payload(name: &str, domains: &[String]) -> serde_json::Value {
    json!({
        "Name": name,
        "URLlist": {
            "URL": domains,
        },
    })
}

fn groups_from_response(resources: &[ResourceResponse]) -> Result<Vec<UrlGroup>> {
    let mut groups = Vec::new();
    for resource in resources
        .iter()
        .filter(|resource| resource.name == URL_GROUP_RESOURCE)
    {
        let nodes = parse_xml_nodes(&resource.body_xml)?;
        for node in nodes.iter().filter(|node| node.name == URL_GROUP_RESOURCE) {
            if let Some(group) = group_from_node(node) {
                groups.push(group);
            }
        }
    }
    Ok(groups)
}

fn group_from_node(node: &XmlNode) -> Option<UrlGroup> {
    let name = normalize_group_name(node.child_text(NAME_KEY)?).ok()?;
    let domains = node
        .child("URLlist")
        .map(domains_from_url_list)
        .unwrap_or_default();
    Some(UrlGroup::new_unchecked(name, domains))
}

fn domains_from_url_list(url_list: &XmlNode) -> Vec<String> {
    let mut domains = Vec::new();
    for url in url_list.children_named("URL") {
        let domain = url.text.trim();
        if !domain.is_empty() && !domains.iter().any(|existing| existing == domain) {
            domains.push(domain.to_string());
        }
    }
    domains
}

fn first_url_group_resource(resources: Vec<ResourceResponse>) -> Result<ResourceResponse> {
    resources
        .into_iter()
        .find(|resource| resource.name == URL_GROUP_RESOURCE)
        .ok_or_else(|| Error::ResponseParse(format!("missing {URL_GROUP_RESOURCE} response")))
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

    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> + 'a {
        self.children.iter().filter(move |child| child.name == name)
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
