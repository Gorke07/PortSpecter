use fluent_bundle::{FluentBundle, FluentResource};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Turkish,
    English,
}
impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Turkish => "Türkçe",
            Self::English => "English",
        })
    }
}
impl Language {
    pub fn code(self) -> &'static str {
        match self {
            Self::Turkish => "tr",
            Self::English => "en",
        }
    }
    pub fn system() -> Self {
        let locale = sys_locale::get_locale().unwrap_or_default();
        if locale.to_lowercase().starts_with("tr") {
            Self::Turkish
        } else {
            Self::English
        }
    }
}
pub struct Locale {
    pub language: Language,
    bundle: FluentBundle<FluentResource>,
}
impl Locale {
    pub fn new(language: Language) -> Self {
        let source = match language {
            Language::Turkish => include_str!("../../../assets/locales/tr.ftl"),
            Language::English => include_str!("../../../assets/locales/en.ftl"),
        };
        let mut bundle = FluentBundle::new(vec![language.code().parse().expect("language code")]);
        bundle
            .add_resource(FluentResource::try_new(source.into()).expect("valid translation file"))
            .expect("unique messages");
        Self { language, bundle }
    }
    pub fn text(&self, key: &str) -> String {
        if let Some(value) = self.bundle.get_message(key).and_then(|m| m.value()) {
            self.bundle
                .format_pattern(value, None, &mut Vec::new())
                .into_owned()
        } else {
            key.into()
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn translations_match() {
        let en = Locale::new(Language::English);
        let tr = Locale::new(Language::Turkish);
        for line in include_str!("../../../assets/locales/en.ftl")
            .lines()
            .filter(|s| s.contains(" = "))
        {
            let key = line.split(" = ").next().unwrap();
            assert!(
                en.bundle.get_message(key).and_then(|m| m.value()).is_some(),
                "Missing English key: {key}"
            );
            assert!(
                tr.bundle.get_message(key).and_then(|m| m.value()).is_some(),
                "Missing Turkish key: {key}"
            );
        }
    }
}
