use std::{
    collections::HashMap,
    fmt::{self, Debug},
};

#[derive(Debug, Clone)]
struct DomainPart {
    included: bool,
    children: HashMap<String, DomainPart>,
}

impl DomainPart {
    fn new() -> Self {
        Self {
            included: false,
            children: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct SubDomainsTree(HashMap<String, DomainPart>);

impl Debug for SubDomainsTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SubDomainsTree {{ .. }}")
    }
}

impl SubDomainsTree {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(&mut self, value: &str) {
        let mut current_map = &mut self.0;
        let mut last_included = None;
        for part in value.rsplit('.') {
            let entry = current_map
                .entry(part.to_ascii_lowercase())
                .or_insert_with(DomainPart::new);
            // We don't need to include `a.b.c` if we already have `b.c`
            if entry.included {
                return;
            }
            current_map = &mut entry.children;
            last_included = Some(&mut entry.included);
        }
        if let Some(last_included) = last_included {
            *last_included = true;
            // Remove all subdomains to free memory. `contains` will stop here anyway.
            current_map.clear();
        }
    }

    pub fn contains(&self, value: &str) -> bool {
        let mut current_map = &self.0;
        for part in value.rsplit('.') {
            if let Some(el) = current_map.get(part) {
                if el.included {
                    return true;
                }
                current_map = &el.children;
            } else {
                break;
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
