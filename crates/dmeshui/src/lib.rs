use dmeshtui::{MemoryMeshClient, Role, UiModel};
use eframe::egui;

#[cfg(target_os = "android")]
mod android_bridge {
    use jni::JavaVM;
    use jni::objects::{GlobalRef, JObject, JString};
    use std::sync::OnceLock;

    static JVM: OnceLock<JavaVM> = OnceLock::new();
    static ACTIVITY: OnceLock<GlobalRef> = OnceLock::new();
    static ACTIVITY_CLASS: OnceLock<String> = OnceLock::new();

    pub fn init(app: &winit::platform::android::activity::AndroidApp) {
        let vm = match unsafe { JavaVM::from_raw(app.vm_as_ptr().cast()) } {
            Ok(vm) => vm,
            Err(e) => {
                log::warn!("failed to get JavaVM: {}", e);
                return;
            }
        };
        let activity_ref = {
            let mut env = match vm.attach_current_thread() {
                Ok(env) => env,
                Err(e) => {
                    log::warn!("failed to attach JNI thread: {}", e);
                    return;
                }
            };
            let activity = unsafe { JObject::from_raw(app.activity_as_ptr().cast()) };
            let class_name = activity_class_name(&mut env, &activity);
            let _ = ACTIVITY_CLASS.set(class_name);
            match env.new_global_ref(activity) {
                Ok(activity) => activity,
                Err(e) => {
                    log::warn!("failed to store activity ref: {}", e);
                    return;
                }
            }
        };
        let _ = JVM.set(vm);
        let _ = ACTIVITY.set(activity_ref);
    }

    fn activity_class_name(env: &mut jni::JNIEnv<'_>, activity: &JObject<'_>) -> String {
        let Ok(class_value) = env.call_method(activity, "getClass", "()Ljava/lang/Class;", &[])
        else {
            return String::new();
        };
        let Ok(class_obj) = class_value.l() else {
            return String::new();
        };
        let Ok(name_value) = env.call_method(class_obj, "getName", "()Ljava/lang/String;", &[])
        else {
            return String::new();
        };
        let Ok(name_obj) = name_value.l() else {
            return String::new();
        };
        env.get_string(&JString::from(name_obj))
            .map(|s| s.into())
            .unwrap_or_default()
    }

    pub fn is_ratatui_activity() -> bool {
        ACTIVITY_CLASS
            .get()
            .map(|name| name.ends_with(".RatatuiActivity"))
            .unwrap_or(false)
    }

    pub fn submit_text(text: &str) {
        let Some(vm) = JVM.get() else {
            return;
        };
        let Some(activity) = ACTIVITY.get() else {
            return;
        };
        let mut env = match vm.attach_current_thread() {
            Ok(env) => env,
            Err(e) => {
                log::warn!("failed to attach JNI thread: {}", e);
                return;
            }
        };
        if env
            .find_class("com/github/costinm/dmesh/chat/ChatBridge")
            .is_err()
        {
            return;
        }
        let text = match env.new_string(text) {
            Ok(text) => text,
            Err(e) => {
                log::warn!("failed to allocate Java string: {}", e);
                return;
            }
        };
        let text = JString::from(text);
        let args = &[activity.as_obj().into(), (&text).into()];
        if let Err(e) = env.call_static_method(
            "com/github/costinm/dmesh/chat/ChatBridge",
            "submitText",
            "(Landroid/content/Context;Ljava/lang/String;)V",
            args,
        ) {
            log::warn!("ChatBridge.submitText failed: {}", e);
        }
    }

    pub fn drain_events() -> Vec<String> {
        let Some(vm) = JVM.get() else {
            return Vec::new();
        };
        let mut env = match vm.attach_current_thread() {
            Ok(env) => env,
            Err(e) => {
                log::warn!("failed to attach JNI thread: {}", e);
                return Vec::new();
            }
        };
        let value = match env.call_static_method(
            "com/github/costinm/dmesh/chat/ChatBridge",
            "drainEvents",
            "()Ljava/lang/String;",
            &[],
        ) {
            Ok(value) => value,
            Err(e) => {
                log::warn!("ChatBridge.drainEvents failed: {}", e);
                return Vec::new();
            }
        };
        let obj = match value.l() {
            Ok(obj) => obj,
            Err(e) => {
                log::warn!("ChatBridge.drainEvents returned non-object: {}", e);
                return Vec::new();
            }
        };
        let text: String = match env.get_string(&JString::from(obj)) {
            Ok(text) => text.into(),
            Err(e) => {
                log::warn!("failed to read drained events: {}", e);
                return Vec::new();
            }
        };
        text.lines().map(str::to_owned).collect()
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: winit::platform::android::activity::AndroidApp) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info),
    );
    android_bridge::init(&app);
    log::info!("Starting dmeshui egui activity on Android");

    let options = eframe::NativeOptions {
        android_app: Some(app),
        viewport: egui::ViewportBuilder::default().with_inner_size([420.0, 720.0]),
        ..Default::default()
    };

    let result = if android_bridge::is_ratatui_activity() {
        run_ratatui_with_options(options)
    } else {
        run_with_options(options)
    };
    if let Err(e) = result {
        log::error!("egui application failed: {e}");
    }
}

pub fn main() -> eframe::Result {
    run_with_options(eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([420.0, 720.0]),
        ..Default::default()
    })
}

fn run_with_options(options: eframe::NativeOptions) -> eframe::Result {
    eframe::run_native(
        "DMesh Chat",
        options,
        Box::new(|cc| Ok(Box::new(ChatApp::new(cc)))),
    )
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn run_ratatui_with_options(options: eframe::NativeOptions) -> eframe::Result {
    eframe::run_native(
        "DMesh Ratatui",
        options,
        Box::new(|cc| Ok(Box::new(RatatuiPreviewApp::new(cc)))),
    )
}

struct ChatApp {
    messages: Vec<ChatMessage>,
    input_value: String,
}

struct ChatMessage {
    author: &'static str,
    text: String,
}

impl ChatApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_theme(egui::Theme::Dark);
        Self {
            messages: vec![ChatMessage {
                author: "dmesh",
                text: "Chat UI ready. Messages typed here are forwarded through ChatBridge."
                    .to_owned(),
            }],
            input_value: String::new(),
        }
    }

    fn submit(&mut self) {
        let text = self.input_value.trim().to_owned();
        if text.is_empty() {
            return;
        }

        #[cfg(target_os = "android")]
        android_bridge::submit_text(&text);

        self.messages.push(ChatMessage { author: "me", text });
        self.input_value.clear();
    }

    fn drain_events(&mut self) {
        #[cfg(target_os = "android")]
        for line in android_bridge::drain_events() {
            self.messages.push(ChatMessage {
                author: "json",
                text: line,
            });
        }
    }
}

impl eframe::App for ChatApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        ui.add_space(28.0);

        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("DMesh Chat");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                let input_width = (ui.available_width() - 72.0).max(80.0);
                let input = ui.add_sized(
                    [input_width, 38.0],
                    egui::TextEdit::singleline(&mut self.input_value)
                        .hint_text("Type a message or /logs"),
                );

                let send_clicked = ui
                    .add_sized([64.0, 38.0], egui::Button::new("Send"))
                    .clicked();
                let enter_pressed =
                    input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                if send_clicked || enter_pressed {
                    self.submit();
                }
            });
            ui.add_space(8.0);

            let message_height = ui.available_height().max(120.0);
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), message_height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for message in &self.messages {
                                egui::Frame::group(ui.style()).show(ui, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.strong(message.author);
                                        ui.label(&message.text);
                                    });
                                });
                                ui.add_space(6.0);
                            }
                        });
                },
            );
        });
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
struct RatatuiPreviewApp {
    model: UiModel,
    client: MemoryMeshClient,
}

impl RatatuiPreviewApp {
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_theme(egui::Theme::Dark);
        let mut model = UiModel::new("DMesh Ratatui");
        model.push_system("Android eframe preview using the dmeshtui shared model.");
        Self {
            model,
            client: MemoryMeshClient::default(),
        }
    }

    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    fn submit(&mut self) {
        self.model.submit_current(&mut self.client);
    }
}

impl eframe::App for RatatuiPreviewApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.add_space(24.0);
        ui.heading(&self.model.title);
        ui.monospace("Shared model: crates/dmeshtui. Terminal backend: ratatui on Linux.");
        ui.separator();
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for message in &self.model.conversation.messages {
                    let color = match message.role {
                        Role::System => egui::Color32::LIGHT_BLUE,
                        Role::Assistant => egui::Color32::LIGHT_GREEN,
                        Role::User => egui::Color32::YELLOW,
                    };
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(color, format!("{:?}", message.role));
                        ui.monospace(&message.content);
                    });
                }
            });
        ui.separator();
        ui.horizontal(|ui| {
            let input = ui.add_sized(
                [ui.available_width() - 76.0, 40.0],
                egui::TextEdit::singleline(&mut self.model.input)
                    .hint_text("mesh method, e.g. messages.snapshot"),
            );
            let send = ui
                .add_sized([68.0, 40.0], egui::Button::new("Send"))
                .clicked();
            let enter = input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if send || enter {
                self.submit();
            }
        });
    }
}
