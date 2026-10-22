use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub client: String,
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclEngine {
    pub rules: Vec<AclRule>,
}

impl AclEngine {
    pub fn new(rules: Vec<AclRule>) -> Self {
        Self { rules }
    }

    pub fn is_allowed(&self, client_id: &str, domain: &str) -> bool {
        if self.rules.is_empty() {
            return true;
        }

        let domain_lower = domain.to_lowercase();
        let clean_domain = domain_lower.split(':').next().unwrap_or(&domain_lower);

        for rule in &self.rules {
            if Self::matches_pattern(&rule.client, client_id) {
                for allowed in &rule.allow {
                    if allowed == "*" || Self::matches_pattern(allowed, clean_domain) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn matches_pattern(pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            return value.ends_with(suffix);
        }
        pattern.eq_ignore_ascii_case(value)
    }
}
