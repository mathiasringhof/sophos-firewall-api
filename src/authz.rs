use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{Action, Error, Result, SophosRequest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectScope {
    Any,
    Named(BTreeSet<String>),
}

impl ObjectScope {
    pub fn named<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Named(names.into_iter().map(Into::into).collect())
    }

    fn decide(&self, object_name: Option<&str>) -> std::result::Result<(), String> {
        match self {
            Self::Any => Ok(()),
            Self::Named(names) => {
                let Some(object_name) = object_name else {
                    return Err(
                        "rule requires a named object but request has no object".to_string()
                    );
                };
                if names.contains(object_name) {
                    Ok(())
                } else {
                    Err(format!("object {object_name:?} is outside allowed scope"))
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRule {
    pub subject: String,
    pub resource: String,
    pub objects: ObjectScope,
    pub actions: BTreeSet<Action>,
}

impl AuthorizationRule {
    pub fn allow(
        subject: impl Into<String>,
        resource: impl Into<String>,
        objects: ObjectScope,
        actions: impl IntoIterator<Item = Action>,
    ) -> Self {
        Self {
            subject: subject.into(),
            resource: resource.into(),
            objects,
            actions: actions.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationPolicy {
    pub rules: Vec<AuthorizationRule>,
}

impl AuthorizationPolicy {
    pub fn new(rules: Vec<AuthorizationRule>) -> Self {
        Self { rules }
    }

    pub fn decide(&self, subject: &str, request: &SophosRequest) -> Decision {
        if request.action == Action::RawXml {
            return Decision::Deny("raw XML requests are denied because object scope cannot be trusted without XML inspection".to_string());
        }

        let mut near_miss: Option<String> = None;
        for rule in &self.rules {
            if rule.subject != subject || rule.resource != request.resource {
                continue;
            }
            if !rule.actions.contains(&request.action) {
                near_miss = Some(format!("action {:?} is not allowed", request.action));
                continue;
            }
            match rule.objects.decide(request.object_name.as_deref()) {
                Ok(()) => return Decision::Allow,
                Err(reason) => near_miss = Some(reason),
            }
        }

        Decision::Deny(near_miss.unwrap_or_else(|| {
            format!(
                "subject {subject:?} has no rule for {:?} {} {:?}",
                request.action, request.resource, request.object_name
            )
        }))
    }

    pub fn authorize(&self, subject: &str, request: &SophosRequest) -> Result<()> {
        match self.decide(subject, request) {
            Decision::Allow => Ok(()),
            Decision::Deny(reason) => Err(Error::AuthorizationDenied(reason)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
}
