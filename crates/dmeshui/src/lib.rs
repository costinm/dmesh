use eframe::egui;

#[cfg(target_os = "android")]
mod android_bridge {
    use jni::JavaVM;
    use jni::objects::{GlobalRef, JObject, JString};
    use std::sync::OnceLock;

    static JVM: OnceLock<JavaVM> = OnceLock::new();
    static ACTIVITY: OnceLock<GlobalRef> = OnceLock::new();

    pub fn init(app: &winit::platform::android::activity::AndroidApp) {
        let vm = match unsafe { JavaVM::from_raw(app.vm_as_ptr().cast()) } {
            Ok(vm) => vm,
            Err(e) => {
                log::warn!("failed to get JavaVM: {}", e);
                return;
            }
        };
        let activity_ref = {
            let env = match vm.attach_current_thread() {
                Ok(env) => env,
                Err(e) => {
                    log::warn!("failed to attach JNI thread: {}", e);
                    return;
                }
            };
            let activity = unsafe { JObject::from_raw(app.activity_as_ptr().cast()) };
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

    if let Err(e) = run_with_options(options) {
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

        self.messages.push(ChatMessage {
            author: "me",
            text,
        });
        self.input_value.clear();
    }
}

impl eframe::App for ChatApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.add_space(28.0);

        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("DMesh Chat");
            ui.add_space(8.0);

            let message_height = (ui.available_height() - 56.0).max(120.0);
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

            ui.horizontal(|ui| {
                let input_width = (ui.available_width() - 72.0).max(80.0);
                let input = ui.add_sized(
                    [input_width, 38.0],
                    egui::TextEdit::singleline(&mut self.input_value).hint_text("Type a message"),
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
        });
    }
}
