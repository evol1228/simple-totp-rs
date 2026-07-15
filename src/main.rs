#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Align, Color32, CursorIcon, Label, RichText, Sense, TextEdit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const SYNC_PENDING: u8 = 0;
const SYNC_OK: u8 = 1;
const SYNC_FAILED: u8 = 2;

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn fetch_time_offset() -> Option<i64> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(3)))
        .build()
        .into();
    let res = agent.head("https://google.com").call().ok()?;
    let date = res.headers().get("date")?.to_str().ok()?;
    let server = httpdate::parse_http_date(date).ok()?;
    let server_secs = server.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(server_secs - unix_now())
}

fn generate_totp(secret: &str, time_offset: i64) -> String {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    if cleaned.is_empty() {
        return "--- ---".to_string();
    }

    let key = match data_encoding::BASE32_NOPAD.decode(cleaned.trim_end_matches('=').as_bytes()) {
        Ok(k) if !k.is_empty() => k,
        _ => return "INVALID".to_string(),
    };

    let counter = ((unix_now() + time_offset) / 30) as u64;
    match hotp(&key, counter) {
        Some(code) => format!("{:03} {:03}", code / 1000, code % 1000),
        None => "INVALID".to_string(),
    }
}

fn hotp(key: &[u8], counter: u64) -> Option<u32> {
    let mut mac = HmacSha1::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();

    let offset = (hash[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([hash[offset], hash[offset + 1], hash[offset + 2], hash[offset + 3]])
        & 0x7fff_ffff;
    Some(code % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 appendix D vectors (secret "12345678901234567890"), truncated to 6 digits.
    #[test]
    fn rfc4226_vectors() {
        let key = b"12345678901234567890";
        let expected = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(key, counter as u64), Some(*want));
        }
    }

    // RFC 6238: T=59 with SHA1 gives 94287082 -> 287082 at time step 1.
    #[test]
    fn rfc6238_time_59() {
        let key = b"12345678901234567890";
        assert_eq!(hotp(key, 59 / 30), Some(287082));
    }

    #[test]
    fn base32_handling() {
        // "12345678901234567890" in Base32.
        let cleaned = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_uppercase();
        let key = data_encoding::BASE32_NOPAD.decode(cleaned.as_bytes()).unwrap();
        assert_eq!(key, b"12345678901234567890");
    }
}

struct App {
    secret: String,
    time_offset: Arc<AtomicI64>,
    sync_status: Arc<AtomicU8>,
    copied_at: Option<Instant>,
    first_frame: bool,
}

impl App {
    fn new(ctx: egui::Context) -> Self {
        let time_offset = Arc::new(AtomicI64::new(0));
        let sync_status = Arc::new(AtomicU8::new(SYNC_PENDING));

        let offset = Arc::clone(&time_offset);
        let status = Arc::clone(&sync_status);
        std::thread::spawn(move || {
            match fetch_time_offset() {
                Some(off) => {
                    offset.store(off, Ordering::Relaxed);
                    status.store(SYNC_OK, Ordering::Relaxed);
                }
                None => status.store(SYNC_FAILED, Ordering::Relaxed),
            }
            ctx.request_repaint();
        });

        Self {
            secret: String::new(),
            time_offset,
            sync_status,
            copied_at: None,
            first_frame: true,
        }
    }

    fn copy_code(&mut self, ctx: &egui::Context, code: &str) {
        let digits: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() == 6 {
            ctx.copy_text(digits);
            self.copied_at = Some(Instant::now());
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        ctx.request_repaint_after(Duration::from_millis(200));

        let time_offset = self.time_offset.load(Ordering::Relaxed);
        let code = generate_totp(&self.secret, time_offset);
        let seconds_remaining = 30 - ((unix_now() + time_offset) % 30);
        let dark = ui.visuals().dark_mode;

        egui::Panel::bottom("status").show_separator_line(false).show(ui, |ui| {
            let status_text = match self.sync_status.load(Ordering::Relaxed) {
                SYNC_OK => "Synced with Google Time",
                SYNC_FAILED => "Using Local Computer Time",
                _ => "Syncing time…",
            };
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(status_text).size(10.5).color(Color32::from_gray(120)));
                ui.add_space(4.0);
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(18.0);
                ui.label(RichText::new("Input your Secret Key:").size(17.0).strong());
                ui.add_space(8.0);

                let entry = ui.add(
                    TextEdit::singleline(&mut self.secret)
                        .desired_width(270.0)
                        .horizontal_align(Align::Center)
                        .hint_text("Base32 secret (spaces ok)"),
                );
                if self.first_frame {
                    entry.request_focus();
                    self.first_frame = false;
                }

                ui.add_space(14.0);

                let code_color = if dark {
                    Color32::from_rgb(0x64, 0xB5, 0xF6)
                } else {
                    Color32::from_rgb(0x00, 0x5A, 0x9E)
                };
                let code_label = ui
                    .add(
                        Label::new(
                            RichText::new(&code)
                                .monospace()
                                .size(40.0)
                                .strong()
                                .color(code_color),
                        )
                        .sense(Sense::click()),
                    )
                    .on_hover_cursor(CursorIcon::PointingHand)
                    .on_hover_text("Click to copy");
                if code_label.clicked() {
                    self.copy_code(&ctx, &code);
                }

                let timer_color = if seconds_remaining <= 5 {
                    Color32::from_rgb(0xD1, 0x34, 0x38)
                } else {
                    Color32::from_gray(140)
                };
                ui.label(
                    RichText::new(format!("Valid for: {}s", seconds_remaining))
                        .size(12.0)
                        .color(timer_color),
                );

                ui.add_space(12.0);

                let just_copied = self
                    .copied_at
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(2));
                let btn_text = if just_copied { "Copied!" } else { "Copy to Clipboard" };
                if ui.button(btn_text).clicked() {
                    self.copy_code(&ctx, &code);
                }
            });
        });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([340.0, 300.0])
            .with_resizable(false)
            .with_app_id("simple-totp"),
        ..Default::default()
    };
    eframe::run_native(
        "Simple TOTP",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc.egui_ctx.clone())))),
    )
}
