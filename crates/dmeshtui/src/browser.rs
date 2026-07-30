use crate::commands::{MeshCommand, ServiceInfo};
use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;

#[derive(Debug, Clone)]
pub struct PaletteEntry {
    pub kind: EntryKind,
    pub service: String,
    pub group: String,
    pub name: String,
    pub description: String,
    pub connected: bool,
    pub index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    Header,
    Command,
}

pub struct CommandBrowser {
    all_commands: Vec<MeshCommand>,
    services: Vec<ServiceInfo>,
    entries: Vec<PaletteEntry>,
    filter: String,
    selected: usize,
    matches: Vec<usize>,
    visible: bool,
}

impl CommandBrowser {
    pub fn new(commands: Vec<MeshCommand>, services: Vec<ServiceInfo>) -> Self {
        let mut browser = Self {
            all_commands: commands,
            services,
            entries: Vec::new(),
            filter: String::new(),
            selected: 0,
            matches: Vec::new(),
            visible: false,
        };
        browser.rebuild_entries();
        browser
    }

    pub fn update(&mut self, commands: Vec<MeshCommand>, services: Vec<ServiceInfo>) {
        self.all_commands = commands;
        self.services = services;
        self.rebuild_entries();
        self.rebuild_matches();
    }

    fn rebuild_entries(&mut self) {
        self.entries.clear();

        let mut grouped: Vec<(String, Vec<&MeshCommand>)> = Vec::new();
        let mut map: std::collections::HashMap<String, Vec<&MeshCommand>> =
            std::collections::HashMap::new();
        for cmd in &self.all_commands {
            map.entry(cmd.service.clone()).or_default().push(cmd);
        }
        for service in &self.services {
            if let Some(cmds) = map.remove(&service.name) {
                grouped.push((service.name.clone(), cmds));
            }
        }
        for (service, cmds) in &map {
            if !grouped.iter().any(|(s, _)| s == service) {
                grouped.push((service.clone(), cmds.clone()));
            }
        }

        let cmd_index: std::collections::HashMap<(&str, &str), usize> = self
            .all_commands
            .iter()
            .enumerate()
            .map(|(i, c)| ((c.service.as_str(), c.name.as_str()), i))
            .collect();

        for (service, cmds) in &grouped {
            let connected = self
                .services
                .iter()
                .find(|s| s.name == *service)
                .map(|s| s.connected)
                .unwrap_or(false);

            self.entries.push(PaletteEntry {
                kind: EntryKind::Header,
                service: service.clone(),
                group: String::new(),
                name: format!("── {} {} ──", service, if connected { "" } else { " (offline)" }),
                description: String::new(),
                connected,
                index: 0,
            });

            let mut grouped_cmds: Vec<(String, Vec<&&MeshCommand>)> = Vec::new();
            let mut gmap: std::collections::HashMap<String, Vec<&&MeshCommand>> =
                std::collections::HashMap::new();
            for cmd in cmds {
                gmap.entry(cmd.group.clone()).or_default().push(cmd);
            }
            for (group, gcmds) in &gmap {
                grouped_cmds.push((group.clone(), gcmds.clone()));
            }

            for (group, gcmds) in &grouped_cmds {
                for cmd in gcmds {
                    let real_idx = cmd_index
                        .get(&(service.as_str(), cmd.name.as_str()))
                        .copied()
                        .unwrap_or(0);
                    self.entries.push(PaletteEntry {
                        kind: EntryKind::Command,
                        service: service.clone(),
                        group: group.clone(),
                        name: cmd.name.clone(),
                        description: cmd.description.clone(),
                        connected,
                        index: real_idx,
                    });
                }
            }
        }
    }

    pub fn toggle(&mut self) {
        self.visible = !self.visible;
        if !self.visible {
            self.filter.clear();
        }
        self.rebuild_matches();
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }

    pub fn show(&mut self) {
        self.visible = true;
        self.rebuild_matches();
    }

    pub fn hide(&mut self) {
        self.visible = false;
        self.filter.clear();
    }

    pub fn input(&mut self, c: char) {
        self.filter.push(c);
        self.selected = 0;
        self.rebuild_matches();
    }

    pub fn backspace(&mut self) {
        self.filter.pop();
        self.selected = 0;
        self.rebuild_matches();
    }

    pub fn clear(&mut self) {
        self.filter.clear();
        self.selected = 0;
        self.rebuild_matches();
    }

    pub fn select_up(&mut self) {
        if self.matches.is_empty() {
            return;
        }
        loop {
            self.selected = if self.selected == 0 {
                self.matches.len() - 1
            } else {
                self.selected - 1
            };
            if let Some(&idx) = self.matches.get(self.selected) {
                if self.entries[idx].kind != EntryKind::Header {
                    break;
                }
            }
            if self.selected == 0 {
                break;
            }
        }
    }

    pub fn select_down(&mut self) {
        if self.matches.is_empty() {
            return;
        }
        loop {
            self.selected = (self.selected + 1).min(self.matches.len() - 1);
            if let Some(&idx) = self.matches.get(self.selected) {
                if self.entries[idx].kind != EntryKind::Header {
                    break;
                }
            }
            if self.selected == self.matches.len() - 1 {
                break;
            }
        }
    }

    pub fn selected_command(&self) -> Option<&MeshCommand> {
        let idx = self.matches.get(self.selected)?;
        let entry = self.entries.get(*idx)?;
        if entry.kind == EntryKind::Header {
            return None;
        }
        self.all_commands.get(entry.index)
    }

    pub fn filter_text(&self) -> &str {
        &self.filter
    }

    pub fn matches(&self) -> &[usize] {
        &self.matches
    }

    pub fn selected_index(&self) -> usize {
        self.selected
    }

    pub fn entries(&self) -> &[PaletteEntry] {
        &self.entries
    }

    pub fn all_commands(&self) -> &[MeshCommand] {
        &self.all_commands
    }

    pub fn services(&self) -> &[ServiceInfo] {
        &self.services
    }

    fn rebuild_matches(&mut self) {
        if self.filter.is_empty() {
            self.matches = (0..self.entries.len()).collect();
        } else {
            let matcher = SkimMatcherV2::default();
            self.matches = self
                .entries
                .iter()
                .enumerate()
                .filter_map(|(i, entry)| {
                    if entry.kind == EntryKind::Header {
                        return None;
                    }
                    if matcher.fuzzy_match(&entry.name, &self.filter).is_some()
                        || matcher
                            .fuzzy_match(&entry.description, &self.filter)
                            .is_some()
                        || matcher.fuzzy_match(&entry.service, &self.filter).is_some()
                    {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect();
        }
        self.selected = 0;
    }
}
