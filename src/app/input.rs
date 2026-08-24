//! Keyboard input dispatch and per-screen handlers.
//!
//! `handle_key` is the single entry point for the main event loop. When an
//! async op is pending only `Esc` (cancel) and `q` (force quit) work — every
//! other state delegates to a `handle_*_key` method below.

use std::net::IpAddr;

use crossterm::event::KeyCode;

use crate::config::{LanMtu, MTU_MAX, MTU_MIN};

use super::dns::{DnsEditMode, DNS_PRESETS};
use super::mtu::{MtuEditMode, Preset as MtuPreset, PRESETS as MTU_PRESETS};
use super::state::{FilterJob, FilterRow, MenuItem};
use super::{App, AppState};

impl App {
    /// Main keyboard dispatch.
    pub fn handle_key(&mut self, key: KeyCode) {
        // While an op is in flight, only Esc (cancel) and q (force-quit) work.
        if self.pending_op.is_some() {
            match key {
                KeyCode::Char('q') => self.should_quit = true,
                KeyCode::Esc => self.cancel_pending_op(),
                _ => {}
            }
            return;
        }

        match self.state {
            AppState::Menu => self.handle_menu_key(key),
            AppState::SelectingVpn => self.handle_vpn_select_key(key),
            AppState::SelectingLan => self.handle_lan_select_key(key),
            AppState::Active => self.handle_active_key(key),
            AppState::EditingDns => self.handle_dns_edit_key(key),
            AppState::EditingMtu => self.handle_mtu_edit_key(key),
            AppState::Doctor => self.handle_doctor_key(key),
            AppState::InstallDnsmasq => self.handle_install_dnsmasq_key(key),
            AppState::PreflightBlocked => self.handle_preflight_key(key),
            AppState::ViewingLists => self.handle_lists_key(key),
        }
    }

    fn handle_preflight_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('r') | KeyCode::Char('R') => self.refresh_interfaces_async(),
            KeyCode::Char('d') | KeyCode::Char('D') => self.start_doctor(),
            // No `q` here — `q` means "quit" on the menu and we don't want
            // muscle memory to surprise-route here.
            KeyCode::Esc | KeyCode::Backspace => self.state = AppState::Menu,
            _ => {}
        }
    }

    fn handle_menu_key(&mut self, key: KeyCode) {
        let items = self.menu_items();

        match key {
            KeyCode::Up | KeyCode::Char('k') if self.selected_menu_item > 0 => {
                self.selected_menu_item -= 1;
            }
            KeyCode::Down | KeyCode::Char('j') if self.selected_menu_item + 1 < items.len() => {
                self.selected_menu_item += 1;
            }
            KeyCode::Enter => {
                if let Some(item) = items.get(self.selected_menu_item) {
                    match item {
                        MenuItem::StartSharing => self.start_interface_selection(),
                        MenuItem::StopSharing => self.stop_sharing_async(),
                        MenuItem::ToggleDhcp => {
                            if self.dnsmasq_installed {
                                self.toggle_dhcp_preference();
                            } else {
                                self.open_install_dnsmasq_modal();
                            }
                        }
                        MenuItem::ToggleNatPmp => self.toggle_natpmp_preference(),
                        MenuItem::SetDns => self.start_dns_edit(),
                        MenuItem::SetMtu => self.start_mtu_edit(),
                        MenuItem::ViewLists => self.open_lists(),
                        MenuItem::RunDoctor => self.start_doctor(),
                        MenuItem::Quit => self.quit(),
                    }
                }
            }
            KeyCode::Char('1') => {
                if let Some(MenuItem::StartSharing) = items.first() {
                    self.start_interface_selection();
                } else if let Some(MenuItem::StopSharing) = items.first() {
                    self.stop_sharing_async();
                }
            }
            KeyCode::Char('2') if items.len() > 1 => match items[1] {
                MenuItem::Quit => self.quit(),
                MenuItem::StopSharing => self.stop_sharing_async(),
                _ => {}
            },
            KeyCode::Char('q') => self.quit(),
            KeyCode::Char('d') if self.is_sharing() => self.toggle_debug(),
            KeyCode::Char('l') if self.is_sharing() => self.open_lists(),
            KeyCode::Char('l') => self.logs_expanded = !self.logs_expanded,
            _ => {}
        }
    }

    fn handle_vpn_select_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(idx) = self.selected_vpn {
                    if idx > 0 {
                        self.selected_vpn = Some(idx - 1);
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(idx) = self.selected_vpn {
                    if idx < self.vpn_interfaces.len().saturating_sub(1) {
                        self.selected_vpn = Some(idx + 1);
                    }
                }
            }
            KeyCode::Enter => {
                if let Some(vpn_idx) = self.selected_vpn {
                    if let Some(vpn) = self.vpn_interfaces.get(vpn_idx) {
                        self.discover_dns_async(vpn.name.clone());
                    }
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.state = AppState::Menu;
                self.log_info("Cancelled interface selection");
            }
            _ => {}
        }
    }

    fn handle_lan_select_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(idx) = self.selected_lan {
                    if idx > 0 {
                        self.selected_lan = Some(idx - 1);
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(idx) = self.selected_lan {
                    if idx < self.lan_interfaces.len().saturating_sub(1) {
                        self.selected_lan = Some(idx + 1);
                    }
                }
            }
            KeyCode::Enter => self.confirm_lan_selection(),
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace => {
                self.state = AppState::SelectingVpn;
                self.log_info("Back to VPN selection");
            }
            _ => {}
        }
    }

    /// Validate the LAN choice (subnet-collision gate) and kick off sharing.
    fn confirm_lan_selection(&mut self) {
        let Some(vpn_idx) = self.selected_vpn else {
            return;
        };
        let Some(lan_idx) = self.selected_lan else {
            return;
        };
        let (Some(vpn), Some(lan)) = (
            self.vpn_interfaces.get(vpn_idx),
            self.lan_interfaces.get(lan_idx),
        ) else {
            return;
        };

        // Refuse to start if the selected LAN shares a subnet with another
        // active LAN interface. The routing table can't disambiguate
        // destinations in that case — sharing would be silently broken.
        // See doctor's "No overlapping LAN subnets" check for the same logic.
        if let Some(other) = self
            .lan_interfaces
            .iter()
            .enumerate()
            .find(|(i, other)| *i != lan_idx && crate::system::same_ipv4_network(lan, other))
            .map(|(_, other)| other)
        {
            self.log_error(format!(
                "Cannot share: {} and {} are on the same subnet. \
                 Change one router's subnet, then try again.",
                lan.name, other.name,
            ));
            return;
        }

        self.start_sharing_async(vpn.name.clone(), lan.name.clone(), lan.ipv4_address);
    }

    fn handle_active_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('s') | KeyCode::Enter => self.stop_sharing_async(),
            KeyCode::Char('q') => {
                self.should_quit = true;
                self.stop_sharing_async();
            }
            KeyCode::Char('d') => self.toggle_debug(),
            KeyCode::Char('l') => self.open_lists(),
            KeyCode::Esc => {
                if self.show_debug {
                    self.show_debug = false;
                    self.debug_info = None;
                } else {
                    self.state = AppState::Menu;
                }
            }
            _ => {}
        }
    }

    fn handle_doctor_key(&mut self, key: KeyCode) {
        let count = self.doctor.results.len();
        match key {
            KeyCode::Up | KeyCode::Char('k') if self.doctor.selected > 0 => {
                self.doctor.selected -= 1;
            }
            KeyCode::Down | KeyCode::Char('j') if self.doctor.selected + 1 < count => {
                self.doctor.selected += 1;
            }
            KeyCode::Enter | KeyCode::Char('r') => self.run_doctor_async(),
            KeyCode::Char('c') if self.doctor_has_stale_anchor() => self.flush_stale_anchor_async(),
            KeyCode::Esc | KeyCode::Char('q') => {
                self.state = self.doctor_return_state.take().unwrap_or(AppState::Menu);
            }
            _ => {}
        }
    }

    // ===== DNS edit screen =====

    fn handle_dns_edit_key(&mut self, key: KeyCode) {
        match self.dns.edit_mode {
            DnsEditMode::SelectingPreset => self.handle_dns_preset_key(key),
            DnsEditMode::CustomInput => self.handle_dns_custom_input_key(key),
        }
    }

    fn handle_dns_preset_key(&mut self, key: KeyCode) {
        let count = self.dns_preset_count();
        match key {
            KeyCode::Up | KeyCode::Char('k') if self.dns.preset_selected > 0 => {
                self.dns.preset_selected -= 1;
            }
            KeyCode::Down | KeyCode::Char('j') if self.dns.preset_selected < count - 1 => {
                self.dns.preset_selected += 1;
            }
            KeyCode::Char('x') => {
                // Delete the highlighted history entry. No-op on other rows.
                if let Some(h_idx) = self.dns_history_idx(self.dns.preset_selected) {
                    let removed = self.dns.history.remove(h_idx);
                    self.log_info(format!("Removed {} from DNS history", removed));
                    if self.dns.preset_selected >= self.dns_preset_count() {
                        self.dns.preset_selected = self.dns_preset_count().saturating_sub(1);
                    }
                    self.save_preferences();
                }
            }
            KeyCode::Enter => self.commit_dns_preset_choice(),
            KeyCode::Esc => {
                self.dns.input_buffer.clear();
                self.state = AppState::Menu;
            }
            _ => {}
        }
    }

    /// Apply the DNS preset/history/auto row currently highlighted, or
    /// switch to custom-input mode for the "Custom..." row.
    fn commit_dns_preset_choice(&mut self) {
        let idx = self.dns.preset_selected;
        if idx == 0 {
            self.dns.custom = None;
            self.log_info("DNS reset to auto-detect");
            self.save_preferences();
            self.state = AppState::Menu;
        } else if idx <= DNS_PRESETS.len() {
            let preset = &DNS_PRESETS[idx - 1];
            self.dns.custom = Some(preset.ip.to_string());
            self.log_success(format!("DNS set to {} ({})", preset.ip, preset.name));
            self.save_preferences();
            self.state = AppState::Menu;
        } else if let Some(h_idx) = self.dns_history_idx(idx) {
            let value = self.dns.history[h_idx].clone();
            self.dns.promote_to_history(&value);
            self.dns.custom = Some(value.clone());
            self.log_success(format!("DNS set to {} (recent)", value));
            self.save_preferences();
            self.state = AppState::Menu;
        } else {
            // Custom... row.
            self.dns.edit_mode = DnsEditMode::CustomInput;
            self.dns.input_buffer = self.dns.custom.clone().unwrap_or_default();
        }
    }

    fn handle_dns_custom_input_key(&mut self, key: KeyCode) {
        match key {
            // Digits, dots, and colons (for IPv6).
            KeyCode::Char(c) if c.is_ascii_digit() || c == '.' || c == ':' => {
                self.dns.input_buffer.push(c);
            }
            KeyCode::Backspace => {
                self.dns.input_buffer.pop();
            }
            KeyCode::Enter => {
                let input = self.dns.input_buffer.trim().to_string();
                if input.is_empty() {
                    self.dns.custom = None;
                    self.log_info("DNS reset to auto-detect");
                } else if input.parse::<IpAddr>().is_ok() {
                    self.dns.promote_to_history(&input);
                    self.dns.custom = Some(input.clone());
                    self.log_success(format!("Custom DNS set to {}", input));
                } else {
                    self.log_warning(format!("Invalid IP address: {}", input));
                }
                self.dns.input_buffer.clear();
                self.save_preferences();
                self.state = AppState::Menu;
            }
            KeyCode::Esc => self.dns.edit_mode = DnsEditMode::SelectingPreset,
            _ => {}
        }
    }

    // ===== MTU edit screen =====

    fn handle_mtu_edit_key(&mut self, key: KeyCode) {
        match self.mtu.edit_mode {
            MtuEditMode::SelectingPreset => self.handle_mtu_preset_key(key),
            MtuEditMode::CustomInput => self.handle_mtu_custom_input_key(key),
        }
    }

    fn handle_mtu_preset_key(&mut self, key: KeyCode) {
        let count = MTU_PRESETS.len();
        match key {
            KeyCode::Up | KeyCode::Char('k') if self.mtu.preset_selected > 0 => {
                self.mtu.preset_selected -= 1;
            }
            KeyCode::Down | KeyCode::Char('j') if self.mtu.preset_selected + 1 < count => {
                self.mtu.preset_selected += 1;
            }
            KeyCode::Enter => self.commit_mtu_preset_choice(),
            KeyCode::Esc => {
                self.mtu.input_buffer.clear();
                self.state = AppState::Menu;
            }
            _ => {}
        }
    }

    /// Apply the highlighted preset row, or switch to custom-input for the
    /// `Custom...` row.
    fn commit_mtu_preset_choice(&mut self) {
        match MTU_PRESETS[self.mtu.preset_selected] {
            MtuPreset::Auto => {
                self.mtu.active = LanMtu::Auto;
                self.log_info("Tunnel MTU: auto (measure path MTU at session start)");
                self.save_preferences();
                self.state = AppState::Menu;
            }
            MtuPreset::Fixed(n, label) => {
                self.mtu.active = LanMtu::Fixed(n);
                self.log_success(format!("Tunnel MTU set to {n} ({label})"));
                self.save_preferences();
                self.state = AppState::Menu;
            }
            MtuPreset::Custom => {
                self.mtu.edit_mode = MtuEditMode::CustomInput;
                self.mtu.input_buffer = match self.mtu.active {
                    LanMtu::Fixed(n) => n.to_string(),
                    _ => String::new(),
                };
            }
        }
    }

    fn handle_mtu_custom_input_key(&mut self, key: KeyCode) {
        match key {
            // u16 max is 5 digits; clamp input length to keep parse cheap
            // and the field visually predictable.
            KeyCode::Char(c) if c.is_ascii_digit() && self.mtu.input_buffer.len() < 5 => {
                self.mtu.input_buffer.push(c);
            }
            KeyCode::Backspace => {
                self.mtu.input_buffer.pop();
            }
            KeyCode::Enter => {
                let input = self.mtu.input_buffer.trim();
                match input.parse::<u16>() {
                    Ok(n) if (MTU_MIN..=MTU_MAX).contains(&n) => {
                        self.mtu.active = LanMtu::Fixed(n);
                        self.log_success(format!("Tunnel MTU set to {n}"));
                        self.mtu.input_buffer.clear();
                        self.save_preferences();
                        self.state = AppState::Menu;
                    }
                    _ => {
                        self.log_warning(format!(
                            "MTU out of range ({MTU_MIN}–{MTU_MAX}): {input}"
                        ));
                    }
                }
            }
            KeyCode::Esc => self.mtu.edit_mode = MtuEditMode::SelectingPreset,
            _ => {}
        }
    }

    /// Enter the MTU edit screen, pre-selecting the row matching the active
    /// policy. The actual VPN MTU is resolved at session start, not here —
    /// keeps the picker reactive and avoids a dependency on a selected VPN.
    fn start_mtu_edit(&mut self) {
        self.mtu.edit_mode = MtuEditMode::SelectingPreset;
        self.mtu.input_buffer = match self.mtu.active {
            LanMtu::Fixed(n) => n.to_string(),
            _ => String::new(),
        };
        let fresh = super::mtu::MtuConfig::new(self.mtu.active);
        self.mtu.preset_selected = fresh.preset_selected;
        self.state = AppState::EditingMtu;
    }

    // ===== Screen transitions / commands =====

    /// Enter VPN/LAN selection flow.
    fn start_interface_selection(&mut self) {
        self.refresh_interfaces_async();
    }

    /// Enter the DNS edit screen, pre-selecting the row matching the
    /// currently-active custom DNS.
    fn start_dns_edit(&mut self) {
        self.dns.input_buffer = self.dns.custom.clone().unwrap_or_default();
        self.dns.edit_mode = DnsEditMode::SelectingPreset;
        self.dns.preset_selected = match self.dns.custom.as_deref() {
            None => 0,
            Some(active) => {
                if let Some(i) = DNS_PRESETS.iter().position(|p| p.ip == active) {
                    1 + i
                } else if let Some(i) = self.dns.history.iter().position(|h| h == active) {
                    self.dns_history_start() + i
                } else {
                    self.dns_custom_input_idx()
                }
            }
        };
        self.state = AppState::EditingDns;
    }

    /// Enter the Doctor screen and kick off a check run. Remembers the
    /// previous state for select cases (e.g. PreflightBlocked) so Esc
    /// returns the user to where they came from instead of dumping them
    /// on the menu.
    fn start_doctor(&mut self) {
        self.doctor_return_state = match self.state {
            AppState::PreflightBlocked => Some(AppState::PreflightBlocked),
            _ => None,
        };
        self.state = AppState::Doctor;
        self.run_doctor_async();
    }

    /// Toggle the debug overlay; fetches a fresh snapshot when opening.
    fn toggle_debug(&mut self) {
        self.show_debug = !self.show_debug;
        if self.show_debug {
            self.fetch_debug_info_async();
        } else {
            self.debug_info = None;
        }
    }

    fn toggle_dhcp_preference(&mut self) {
        // Caller in handle_menu_key already gates on `dnsmasq_installed` —
        // when it's missing, the install modal is opened instead.
        self.dhcp_enabled = !self.dhcp_enabled;
        if self.dhcp_enabled {
            self.log_info("DHCP server enabled");
        } else {
            self.log_info("DHCP server disabled (manual router config required)");
        }
        self.save_preferences();
    }

    /// Enter the install-dnsmasq modal. Snapshots brew availability so the
    /// renderer and key handler don't shell out per-frame.
    fn open_install_dnsmasq_modal(&mut self) {
        self.brew_installed = crate::system::brew_installed();
        self.state = AppState::InstallDnsmasq;
    }

    fn handle_install_dnsmasq_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter if self.brew_installed => {
                self.install_dnsmasq_async();
                // Stay in the modal — the loading indicator overlays it,
                // and on_dnsmasq_installed transitions back to Menu.
            }
            KeyCode::Esc => self.state = AppState::Menu,
            _ => {}
        }
    }

    fn open_lists(&mut self) {
        self.lists_ui.return_state = if self.is_sharing() {
            AppState::Active
        } else {
            AppState::Menu
        };
        self.lists_ui.focus = FilterJob::Block;
        self.lists_ui.block_selected = 0;
        self.lists_ui.allow_selected = 0;
        self.lists_ui.adding = None;
        self.lists_ui.input_buffer.clear();
        self.state = AppState::ViewingLists;
        if self.lists_ui.block_count == 0 && self.lists_ui.allow_count == 0 {
            self.refresh_lists_async(false);
        }
    }

    fn handle_lists_key(&mut self, key: KeyCode) {
        if self.lists_ui.adding.is_some() {
            self.handle_lists_add_key(key);
            return;
        }
        let row_count = self.column_rows(self.lists_ui.focus).len();
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                let selected = self.lists_selected_mut();
                if *selected > 0 {
                    *selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let selected = self.lists_selected_mut();
                if *selected + 1 < row_count {
                    *selected += 1;
                }
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::BackTab => {
                self.lists_ui.focus = FilterJob::Block;
            }
            KeyCode::Right | KeyCode::Tab => {
                self.lists_ui.focus = FilterJob::Allow;
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.activate_filter_row(),
            KeyCode::Char('x') | KeyCode::Char('X') => self.remove_selected_custom(),
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.refresh_lists_async(self.is_sharing());
            }
            KeyCode::Esc => {
                self.state = self.lists_ui.return_state;
            }
            _ => {}
        }
    }

    fn lists_selected(&self) -> usize {
        match self.lists_ui.focus {
            FilterJob::Block => self.lists_ui.block_selected,
            FilterJob::Allow => self.lists_ui.allow_selected,
        }
    }

    fn lists_selected_mut(&mut self) -> &mut usize {
        match self.lists_ui.focus {
            FilterJob::Block => &mut self.lists_ui.block_selected,
            FilterJob::Allow => &mut self.lists_ui.allow_selected,
        }
    }

    fn clamp_lists_selection(&mut self) {
        let last = self
            .column_rows(self.lists_ui.focus)
            .len()
            .saturating_sub(1);
        let selected = self.lists_selected_mut();
        if *selected > last {
            *selected = last;
        }
    }

    fn handle_lists_add_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char(c) if !c.is_control() => {
                self.lists_ui.input_buffer.push(c);
            }
            KeyCode::Backspace => {
                self.lists_ui.input_buffer.pop();
            }
            KeyCode::Enter => self.commit_custom_source(),
            KeyCode::Esc => {
                self.lists_ui.adding = None;
                self.lists_ui.input_buffer.clear();
            }
            _ => {}
        }
    }

    fn activate_filter_row(&mut self) {
        let Some(row) = self
            .column_rows(self.lists_ui.focus)
            .get(self.lists_selected())
            .copied()
        else {
            return;
        };
        match row {
            FilterRow::Job(FilterJob::Block) => self.toggle_block_master(),
            FilterRow::Job(FilterJob::Allow) => self.toggle_allow_master(),
            FilterRow::Source { job, index } => self.toggle_source(job, index),
            FilterRow::Add { job } => {
                self.lists_ui.focus = job;
                self.lists_ui.adding = Some(job);
                self.lists_ui.input_buffer.clear();
            }
        }
    }

    fn toggle_block_master(&mut self) {
        self.lists.block.enabled = !self.lists.block.enabled;
        let state = if self.lists.block.enabled {
            "on"
        } else {
            "off"
        };
        self.log_info(format!("Block {state}"));
        self.save_preferences();
        if self.is_sharing() {
            self.push_lists_to_resolver(None, None);
        }
    }

    fn toggle_allow_master(&mut self) {
        if !self.lists.allow.enabled {
            if self.is_sharing() {
                self.enable_allowlist_live();
                return;
            }
            self.lists.allow.enabled = true;
            self.log_info("WAN bypass on");
        } else {
            self.lists.allow.enabled = false;
            self.log_info("WAN bypass off");
            if self.is_sharing() {
                self.save_preferences();
                self.reload_firewall_without_bypass_async();
                return;
            }
        }
        self.save_preferences();
        if self.is_sharing() {
            self.push_lists_to_resolver(None, None);
        }
    }

    fn toggle_source(&mut self, job: FilterJob, index: usize) {
        let setting = match job {
            FilterJob::Block => &mut self.lists.block,
            FilterJob::Allow => &mut self.lists.allow,
        };
        let Some(source) = setting.sources.get_mut(index) else {
            return;
        };
        source.enabled = !source.enabled;
        let label = source.label();
        let state = if source.enabled { "on" } else { "off" };
        self.log_info(format!("{label} {state}"));
        self.save_preferences();
        self.refresh_lists_async(self.is_sharing());
    }

    fn remove_selected_custom(&mut self) {
        let Some(row) = self
            .column_rows(self.lists_ui.focus)
            .get(self.lists_selected())
            .copied()
        else {
            return;
        };
        let FilterRow::Source { job, index } = row else {
            return;
        };
        let setting = match job {
            FilterJob::Block => &mut self.lists.block,
            FilterJob::Allow => &mut self.lists.allow,
        };
        let Some(removed) = setting.remove_custom(index) else {
            self.log_info("Built-in sources stay; disable them instead");
            return;
        };
        self.log_info(format!("Removed {}", removed.label()));
        self.clamp_lists_selection();
        self.save_preferences();
        self.refresh_lists_async(self.is_sharing());
    }

    fn commit_custom_source(&mut self) {
        let Some(job) = self.lists_ui.adding else {
            return;
        };
        let url = self.lists_ui.input_buffer.trim().to_string();
        if url.is_empty() {
            self.lists_ui.adding = None;
            self.lists_ui.input_buffer.clear();
            return;
        }
        let setting = match job {
            FilterJob::Block => &mut self.lists.block,
            FilterJob::Allow => &mut self.lists.allow,
        };
        match setting.add_custom(url.clone()) {
            Ok(()) => {
                self.log_success(format!("Added {url}"));
                self.lists_ui.focus = job;
                self.lists_ui.adding = None;
                self.lists_ui.input_buffer.clear();
                let source_index = match job {
                    FilterJob::Block => self.lists.block.sources.len().saturating_sub(1),
                    FilterJob::Allow => self.lists.allow.sources.len().saturating_sub(1),
                };
                *self.lists_selected_mut() = source_index + 1;
                self.save_preferences();
                self.refresh_lists_async(self.is_sharing());
            }
            Err(error) => self.log_warning(error),
        }
    }

    fn enable_allowlist_live(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        if let Some(wan) = session.wan.clone() {
            if let Some(server) = session.dns_server() {
                if let Err(error) = server.attach_wan(&wan) {
                    self.log_error(format!("WAN DNS attach failed: {error}"));
                    return;
                }
            }
            self.reload_firewall_for_bypass_async(wan);
            return;
        }
        self.detect_wan_async(
            session.lan_name.clone(),
            vec![session.upstream.name.clone()],
        );
    }

    fn toggle_natpmp_preference(&mut self) {
        self.natpmp_enabled = !self.natpmp_enabled;
        if self.natpmp_enabled {
            self.log_info("NAT-PMP server enabled");
        } else {
            self.log_info("NAT-PMP server disabled");
        }
        self.save_preferences();
    }

    /// Quit. If sharing is active, kicks off async teardown first — the
    /// `should_quit` flag fires once the stop completes.
    fn quit(&mut self) {
        if self.is_sharing() {
            self.should_quit = true;
            self.stop_sharing_async();
        } else {
            self.should_quit = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Find a menu item's index in the non-sharing menu layout.
    /// Tests will fail loudly if the menu layout shifts.
    fn menu_idx(app: &App, target: MenuItem) -> usize {
        app.menu_items()
            .iter()
            .position(|m| std::mem::discriminant(m) == std::mem::discriminant(&target))
            .expect("menu item must be present")
    }

    #[test]
    fn menu_navigation_clamps_at_bounds() {
        let mut app = App::new();
        let last = app.menu_items().len() - 1;

        app.handle_key(KeyCode::Up);
        assert_eq!(app.selected_menu_item, 0);

        for _ in 0..(last + 5) {
            app.handle_key(KeyCode::Down);
        }
        assert_eq!(app.selected_menu_item, last);

        app.handle_key(KeyCode::Up);
        assert_eq!(app.selected_menu_item, last - 1);
    }

    #[test]
    fn menu_enter_on_set_dns_transitions_to_editing_dns() {
        let mut app = App::new();
        app.selected_menu_item = menu_idx(&app, MenuItem::SetDns);
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.state, AppState::EditingDns);
    }

    #[test]
    fn editing_dns_esc_returns_to_menu_without_save() {
        let mut app = App::new();
        app.state = AppState::EditingDns;
        app.dns.edit_mode = DnsEditMode::SelectingPreset;
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.state, AppState::Menu);
    }

    #[test]
    fn menu_q_sets_should_quit() {
        let mut app = App::new();
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit);
    }

    #[test]
    fn active_esc_returns_to_menu_when_no_debug() {
        let mut app = App::new();
        app.state = AppState::Active;
        app.show_debug = false;
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.state, AppState::Menu);
    }

    #[test]
    fn active_esc_hides_debug_first() {
        let mut app = App::new();
        app.state = AppState::Active;
        app.show_debug = true;
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.state, AppState::Active);
        assert!(!app.show_debug);
    }

    #[test]
    fn active_stop_without_session_returns_to_menu() {
        let mut app = App::new();
        app.state = AppState::Active;
        // No session — stop_sharing_async should log and bail to Menu.
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(app.state, AppState::Menu);
    }
}
