mod catalog;

use dmeshtui::{MemoryMeshClient, Role, UiModel};
use egui;

pub struct ChatApp {
    pub messages: Vec<ChatMessage>,
    pub input_value: String,
    pub history: Vec<String>,
    pub history_idx: Option<usize>,
    pub draft_input: String,
    pub selected_suggestion: usize,
}

pub struct ChatMessage {
    pub author: &'static str,
    pub text: String,
}

impl ChatApp {
    pub fn new() -> Self {
        Self {
            messages: vec![ChatMessage {
                author: "dmesh",
                text: "Chat UI ready. Messages typed here are forwarded through ChatBridge."
                    .to_owned(),
            }],
            input_value: String::new(),
            history: Vec::new(),
            history_idx: None,
            draft_input: String::new(),
            selected_suggestion: 0,
        }
    }

    pub fn submit(&mut self) {
        let text = self.input_value.trim().to_owned();
        if text.is_empty() {
            return;
        }

        #[cfg(target_os = "android")]
        android_bridge::submit_text(&text);

        // Add to history
        if self.history.last().map(|s| s.as_str()) != Some(&text) {
            self.history.push(text.clone());
        }
        self.history_idx = None;
        self.draft_input.clear();

        self.messages.push(ChatMessage { author: "me", text });
        self.input_value.clear();
    }

    pub fn drain_events(&mut self) {
        #[cfg(target_os = "android")]
        for line in android_bridge::drain_events() {
            self.messages.push(ChatMessage {
                author: "json",
                text: line,
            });
        }
    }

    pub fn matching_commands(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        let trimmed = self.input_value.trim_start();
        if !trimmed.starts_with('/') {
            return Vec::new();
        }
        // Extract command prefix up to first whitespace
        let cmd_part = trimmed.split_whitespace().next().unwrap_or(trimmed);
        let search = &cmd_part[1..].to_lowercase();

        let mut matches = Vec::new();
        for item in catalog::CATALOG {
            let name_slash = item.name.replace('.', "/");
            let name_dot = item.name.to_lowercase();
            if search.is_empty()
                || name_dot.contains(search)
                || name_slash.contains(search)
                || item.title.to_lowercase().contains(search)
            {
                matches.push((item.name, item.title, item.desc));
                if matches.len() >= 6 {
                    break;
                }
            }
        }
        matches
    }

    pub fn apply_completion(&mut self, name: &str) {
        let cmd_slash = format!("/{} ", name.replace('.', "/"));
        self.input_value = cmd_slash;
    }

    pub fn complete_selected(&mut self) {
        let suggestions = self.matching_commands();
        if !suggestions.is_empty() {
            let idx = self.selected_suggestion.min(suggestions.len() - 1);
            self.apply_completion(suggestions[idx].0);
        }
    }

    pub fn navigate_history(&mut self, up: bool) {
        let suggestions = self.matching_commands();
        if up {
            if !suggestions.is_empty() && self.selected_suggestion > 0 {
                self.selected_suggestion -= 1;
            } else if !self.history.is_empty() {
                match self.history_idx {
                    None => {
                        self.draft_input = self.input_value.clone();
                        let new_idx = self.history.len() - 1;
                        self.history_idx = Some(new_idx);
                        self.input_value = self.history[new_idx].clone();
                    }
                    Some(idx) if idx > 0 => {
                        let new_idx = idx - 1;
                        self.history_idx = Some(new_idx);
                        self.input_value = self.history[new_idx].clone();
                    }
                    _ => {}
                }
            }
        } else {
            if !suggestions.is_empty() && self.selected_suggestion + 1 < suggestions.len() {
                self.selected_suggestion += 1;
            } else if let Some(idx) = self.history_idx {
                if idx + 1 < self.history.len() {
                    let new_idx = idx + 1;
                    self.history_idx = Some(new_idx);
                    self.input_value = self.history[new_idx].clone();
                } else {
                    self.history_idx = None;
                    self.input_value = self.draft_input.clone();
                }
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        self.drain_events();
        ui.add_space(16.0);

        let suggestions = self.matching_commands();

        // Keyboard navigation for history and auto-complete
        let up_pressed = ui.input(|i| i.key_pressed(egui::Key::ArrowUp));
        let down_pressed = ui.input(|i| i.key_pressed(egui::Key::ArrowDown));
        let tab_pressed = ui.input(|i| i.key_pressed(egui::Key::Tab));

        if tab_pressed {
            self.complete_selected();
        } else if up_pressed {
            self.navigate_history(true);
        } else if down_pressed {
            self.navigate_history(false);
        }

        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.heading("DMesh Chat");
                if !self.history.is_empty() {
                    ui.label(
                        egui::RichText::new(format!("({} in history, ↑/↓ to browse)", self.history.len()))
                            .weak()
                            .small(),
                    );
                }
            });
            ui.add_space(8.0);

            // Input row
            ui.horizontal(|ui| {
                let input_width = (ui.available_width() - 72.0).max(80.0);
                let input = ui.add_sized(
                    [input_width, 38.0],
                    egui::TextEdit::singleline(&mut self.input_value)
                        .hint_text("Type a message or /command (e.g. /messages, /lmesh/status)"),
                );
                if input.clicked() {
                    input.request_focus();
                }

                let send_clicked = ui
                    .add_sized([64.0, 38.0], egui::Button::new("Send"))
                    .clicked();
                let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter))
                    || (input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));

                if send_clicked || enter_pressed {
                    self.submit();
                }
            });

            // Autocomplete suggestions panel
            if !suggestions.is_empty() {
                ui.add_space(4.0);
                egui::Frame::popup(ui.style()).show(ui, |ui| {
                    ui.set_max_width(ui.available_width());
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new("Suggestions:").small().strong());
                        for (idx, (name, title, desc)) in suggestions.iter().enumerate() {
                            let is_selected = idx == self.selected_suggestion.min(suggestions.len() - 1);
                            let slash_cmd = format!("/{}", name.replace('.', "/"));
                            let label_text = if !title.is_empty() {
                                format!("{} ({})", slash_cmd, title)
                            } else {
                                slash_cmd
                            };

                            let mut btn = egui::Button::new(
                                egui::RichText::new(&label_text).monospace().size(12.0),
                            );
                            if is_selected {
                                btn = btn.fill(ui.visuals().selection.bg_fill);
                            }

                            let resp = ui.add(btn);
                            if !desc.is_empty() {
                                resp.clone().on_hover_text(*desc);
                            }
                            if resp.clicked() {
                                self.apply_completion(name);
                            }
                        }
                    });
                });
            }

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

impl Default for ChatApp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub struct RatatuiPreviewApp {
    pub model: UiModel,
    pub client: MemoryMeshClient,
}

impl RatatuiPreviewApp {
    pub fn new() -> Self {
        let mut model = UiModel::new("DMesh Ratatui");
        model.push_system("Android preview using the dmeshtui shared model.");
        Self {
            model,
            client: MemoryMeshClient::default(),
        }
    }

    pub fn submit(&mut self) {
        self.model.submit_current(&mut self.client);
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(16.0);
        ui.heading(&self.model.title);
        ui.monospace("Shared model: crates/dmeshtui.");
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

impl Default for RatatuiPreviewApp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "android"))]
impl eframe::App for ChatApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.ui(ui);
    }
}

#[cfg(not(target_os = "android"))]
impl eframe::App for RatatuiPreviewApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.ui(ui);
    }
}

#[cfg(not(target_os = "android"))]
pub fn main() -> eframe::Result {
    eframe::run_native(
        "DMesh Chat",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([420.0, 720.0]),
            ..Default::default()
        },
        Box::new(|cc| {
            cc.egui_ctx.set_theme(egui::Theme::Dark);
            Ok(Box::new(ChatApp::new()))
        }),
    )
}

#[cfg(target_os = "android")]
mod android_bridge {
    use jni::JavaVM;
    use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
    use std::sync::OnceLock;

    static JVM: OnceLock<JavaVM> = OnceLock::new();
    static CONTEXT: OnceLock<GlobalRef> = OnceLock::new();
    static CLASS_LOADER: OnceLock<GlobalRef> = OnceLock::new();

    pub fn init(vm: JavaVM, context: GlobalRef, class_loader: GlobalRef) {
        let _ = JVM.set(vm);
        let _ = CONTEXT.set(context);
        let _ = CLASS_LOADER.set(class_loader);
    }

    fn find_bridge_class<'a>(env: &mut jni::JNIEnv<'a>) -> Result<JClass<'a>, jni::errors::Error> {
        if let Some(cl_ref) = CLASS_LOADER.get() {
            let class_name = env.new_string("com.github.costinm.dmesh.chat.ChatBridge")?;
            let res = env.call_method(
                cl_ref.as_obj(),
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::from(&class_name)],
            )?;
            let obj = res.l()?;
            Ok(JClass::from(obj))
        } else {
            env.find_class("com/github/costinm/dmesh/chat/ChatBridge")
        }
    }

    pub fn submit_text(text: &str) {
        let Some(vm) = JVM.get() else {
            return;
        };
        let Some(ctx) = CONTEXT.get() else {
            return;
        };
        let mut env = match vm.attach_current_thread() {
            Ok(env) => env,
            Err(e) => {
                log::warn!("failed to attach JNI thread: {}", e);
                return;
            }
        };
        let bridge_class = match find_bridge_class(&mut env) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("failed to find ChatBridge class: {}", e);
                let _ = env.exception_clear();
                return;
            }
        };
        let text = match env.new_string(text) {
            Ok(text) => text,
            Err(e) => {
                log::warn!("failed to allocate Java string: {}", e);
                let _ = env.exception_clear();
                return;
            }
        };
        let text = JString::from(text);
        let args = &[ctx.as_obj().into(), (&text).into()];
        if let Err(e) = env.call_static_method(
            &bridge_class,
            "submitText",
            "(Landroid/content/Context;Ljava/lang/String;)V",
            args,
        ) {
            log::warn!("ChatBridge.submitText failed: {}", e);
            let _ = env.exception_clear();
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
        let bridge_class = match find_bridge_class(&mut env) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("failed to find ChatBridge class: {}", e);
                let _ = env.exception_clear();
                return Vec::new();
            }
        };
        let value = match env.call_static_method(
            &bridge_class,
            "drainEvents",
            "()Ljava/lang/String;",
            &[],
        ) {
            Ok(value) => value,
            Err(e) => {
                log::warn!("ChatBridge.drainEvents failed: {}", e);
                let _ = env.exception_clear();
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
mod android_surface {
    use super::*;
    use glutin_egl_sys::egl;
    use glutin_egl_sys::egl::types;
    use jni::objects::{JClass, JObject, JString};
    use jni::sys::{jboolean, jfloat, jint, jlong};
    use jni::JNIEnv;
    use ndk::native_window::NativeWindow;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    struct RendererState {
        window: Option<NativeWindow>,
        width: u32,
        height: u32,
        density: f32,
        insets_bottom: f32,
        egui_ctx: egui::Context,
        chat_app: ChatApp,
        raw_input: egui::RawInput,
        start_time: Instant,
        last_touch_pos: Option<egui::Pos2>,
    }

    struct EglContext {
        egl: egl::Egl,
        display: types::EGLDisplay,
        context: types::EGLContext,
        surface: types::EGLSurface,
        config: types::EGLConfig,
        gl: Arc<glow::Context>,
        painter: egui_glow::Painter,
    }

    impl EglContext {
        unsafe fn new(native_window: &NativeWindow) -> Result<Self, String> {
            let lib = unsafe { libloading::Library::new("libEGL.so") }
                .map_err(|e| format!("failed to load libEGL.so: {e}"))?;
            let egl = egl::Egl::load_with(|sym| {
                let sym_cstr = std::ffi::CString::new(sym).unwrap();
                let sym_bytes = sym_cstr.as_bytes_with_nul();
                match unsafe { lib.get::<*const c_void>(sym_bytes) } {
                    Ok(f) => *f,
                    Err(_) => std::ptr::null(),
                }
            });

            let display = unsafe { egl.GetDisplay(egl::DEFAULT_DISPLAY) };
            if display == egl::NO_DISPLAY {
                return Err("eglGetDisplay failed".to_string());
            }

            let mut major = 0;
            let mut minor = 0;
            if unsafe { egl.Initialize(display, &mut major, &mut minor) } == 0 {
                return Err("eglInitialize failed".to_string());
            }

            #[rustfmt::skip]
            let attribs = [
                egl::RENDERABLE_TYPE as i32, egl::OPENGL_ES2_BIT as i32,
                egl::SURFACE_TYPE as i32, egl::WINDOW_BIT as i32,
                egl::RED_SIZE as i32, 8,
                egl::GREEN_SIZE as i32, 8,
                egl::BLUE_SIZE as i32, 8,
                egl::ALPHA_SIZE as i32, 8,
                egl::DEPTH_SIZE as i32, 16,
                egl::NONE as i32,
            ];

            let mut config: types::EGLConfig = std::ptr::null();
            let mut num_configs = 0;
            if unsafe { egl.ChooseConfig(display, attribs.as_ptr(), &mut config as *mut _ as *mut *const c_void, 1, &mut num_configs) } == 0 || num_configs == 0 {
                return Err("eglChooseConfig failed".to_string());
            }

            #[rustfmt::skip]
            let context_attribs = [
                egl::CONTEXT_CLIENT_VERSION as i32, 2,
                egl::NONE as i32,
            ];

            let context = unsafe { egl.CreateContext(display, config, egl::NO_CONTEXT, context_attribs.as_ptr()) };
            if context == egl::NO_CONTEXT {
                return Err("eglCreateContext failed".to_string());
            }

            let surface = unsafe { egl.CreateWindowSurface(
                display,
                config,
                native_window.ptr().as_ptr() as *mut _,
                std::ptr::null(),
            ) };
            if surface == egl::NO_SURFACE {
                return Err("eglCreateWindowSurface failed".to_string());
            }

            if unsafe { egl.MakeCurrent(display, surface, surface, context) } == 0 {
                return Err("eglMakeCurrent failed".to_string());
            }

            let egl_clone = egl.clone();
            let gl = unsafe {
                glow::Context::from_loader_function(|name: &str| {
                    let c_name = std::ffi::CString::new(name).unwrap();
                    egl_clone.GetProcAddress(c_name.as_ptr()) as *const c_void
                })
            };
            let gl = Arc::new(gl);

            let painter = egui_glow::Painter::new(gl.clone(), "", None, false)
                .map_err(|e| format!("Painter::new error: {e}"))?;

            // Intentionally keep `lib` loaded for process lifetime
            std::mem::forget(lib);

            Ok(Self {
                egl,
                display,
                context,
                surface,
                config,
                gl,
                painter,
            })
        }

        unsafe fn swap_buffers(&self) {
            unsafe { self.egl.SwapBuffers(self.display, self.surface); }
        }

        unsafe fn destroy(&mut self) {
            self.painter.destroy();
            unsafe {
                self.egl.MakeCurrent(self.display, egl::NO_SURFACE, egl::NO_SURFACE, egl::NO_CONTEXT);
                if self.surface != egl::NO_SURFACE {
                    self.egl.DestroySurface(self.display, self.surface);
                    self.surface = egl::NO_SURFACE;
                }
                if self.context != egl::NO_CONTEXT {
                    self.egl.DestroyContext(self.display, self.context);
                    self.context = egl::NO_CONTEXT;
                }
                self.egl.Terminate(self.display);
            }
        }
    }

    pub struct AndroidBridgeRenderer {
        state: Arc<Mutex<RendererState>>,
        render_requested: Arc<AtomicBool>,
        running: Arc<AtomicBool>,
    }

    impl AndroidBridgeRenderer {
        pub fn new(density: f32) -> Self {
            let egui_ctx = egui::Context::default();
            egui_ctx.set_theme(egui::Theme::Dark);

            let state = Arc::new(Mutex::new(RendererState {
                window: None,
                width: 0,
                height: 0,
                density: density.max(1.0),
                insets_bottom: 0.0,
                egui_ctx,
                chat_app: ChatApp::new(),
                raw_input: egui::RawInput::default(),
                start_time: Instant::now(),
                last_touch_pos: None,
            }));

            let render_requested = Arc::new(AtomicBool::new(true));
            let running = Arc::new(AtomicBool::new(true));

            let thread_state = state.clone();
            let thread_req = render_requested.clone();
            let thread_running = running.clone();

            std::thread::Builder::new()
                .name("egui_render".to_string())
                .spawn(move || {
                    Self::render_thread_loop(thread_state, thread_req, thread_running);
                })
                .expect("failed to spawn render thread");

            Self {
                state,
                render_requested,
                running,
            }
        }

        fn render_thread_loop(
            state_arc: Arc<Mutex<RendererState>>,
            render_req: Arc<AtomicBool>,
            running: Arc<AtomicBool>,
        ) {
            let mut egl_ctx: Option<EglContext> = None;
            let mut current_window_ptr: *mut c_void = std::ptr::null_mut();

            while running.load(Ordering::Relaxed) {
                let mut should_render = render_req.swap(false, Ordering::Relaxed);

                let (window_opt, w, h, density, insets_bottom) = {
                    let s = state_arc.lock().unwrap();
                    let win = s.window.as_ref().map(|w| w.ptr().as_ptr() as *mut c_void);
                    (win, s.width, s.height, s.density, s.insets_bottom)
                };

                if let Some(win_ptr) = window_opt {
                    if egl_ctx.is_none() || current_window_ptr != win_ptr {
                        if let Some(mut old) = egl_ctx.take() {
                            unsafe { old.destroy() };
                        }
                        let s = state_arc.lock().unwrap();
                        if let Some(ref win) = s.window {
                            match unsafe { EglContext::new(win) } {
                                Ok(ctx) => {
                                    egl_ctx = Some(ctx);
                                    current_window_ptr = win_ptr;
                                    should_render = true;
                                }
                                Err(e) => {
                                    log::error!("Failed to create EGL context: {e}");
                                }
                            }
                        }
                    }
                } else {
                    if let Some(mut old) = egl_ctx.take() {
                        unsafe { old.destroy() };
                    }
                    current_window_ptr = std::ptr::null_mut();
                }

                if let (Some(ctx), true) = (&mut egl_ctx, should_render && w > 0 && h > 0) {
                    let mut s = state_arc.lock().unwrap();
                    let elapsed = s.start_time.elapsed().as_secs_f64();
                    let screen_w = w as f32 / density;
                    let screen_h = (h as f32 - insets_bottom) / density;

                    let mut raw_input = s.raw_input.take();
                    raw_input.time = Some(elapsed);
                    raw_input.screen_rect = Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(screen_w, screen_h),
                    ));
                    raw_input.max_texture_side = Some(2048);

                    let egui_ctx = s.egui_ctx.clone();
                    drop(s);

                    let full_output = egui_ctx.run_ui(raw_input, |ui| {
                        let mut s = state_arc.lock().unwrap();
                        s.chat_app.ui(ui);
                    });

                    unsafe {
                        use glow::HasContext as _;
                        ctx.gl.viewport(0, insets_bottom as i32, w as i32, (h as f32 - insets_bottom) as i32);
                        ctx.gl.clear_color(0.12, 0.12, 0.14, 1.0);
                        ctx.gl.clear(glow::COLOR_BUFFER_BIT);

                        let clipped_primitives = egui_ctx.tessellate(full_output.shapes, density);
                        ctx.painter.paint_and_update_textures(
                            [w, h],
                            density,
                            &clipped_primitives,
                            &full_output.textures_delta,
                        );
                        ctx.swap_buffers();
                    }

                    if full_output.viewport_output.values().any(|v| v.repaint_delay.is_zero()) {
                        render_req.store(true, Ordering::Relaxed);
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(16));
            }

            if let Some(mut old) = egl_ctx.take() {
                unsafe { old.destroy() };
            }
        }

        pub fn set_surface(&self, window: Option<NativeWindow>, w: u32, h: u32) {
            let mut s = self.state.lock().unwrap();
            s.window = window;
            s.width = w;
            s.height = h;
            self.render_requested.store(true, Ordering::Relaxed);
        }

        pub fn set_size(&self, w: u32, h: u32) {
            let mut s = self.state.lock().unwrap();
            s.width = w;
            s.height = h;
            self.render_requested.store(true, Ordering::Relaxed);
        }

        pub fn set_insets_bottom(&self, bottom: f32) {
            let mut s = self.state.lock().unwrap();
            s.insets_bottom = bottom;
            self.render_requested.store(true, Ordering::Relaxed);
        }

        pub fn push_touch(&self, action: i32, x: f32, y: f32) {
            let mut s = self.state.lock().unwrap();
            let pos = egui::pos2(x / s.density, y / s.density);
            match action {
                0 => { // ACTION_DOWN
                    s.last_touch_pos = Some(pos);
                    s.raw_input.events.push(egui::Event::PointerMoved(pos));
                    s.raw_input.events.push(egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::default(),
                    });
                }
                1 => { // ACTION_UP
                    s.last_touch_pos = None;
                    s.raw_input.events.push(egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: false,
                        modifiers: egui::Modifiers::default(),
                    });
                }
                2 => { // ACTION_MOVE
                    if let Some(prev_pos) = s.last_touch_pos {
                        let dy = pos.y - prev_pos.y;
                        let dx = pos.x - prev_pos.x;
                        if dy.abs() > 0.5 || dx.abs() > 0.5 {
                            s.raw_input.events.push(egui::Event::MouseWheel {
                                unit: egui::MouseWheelUnit::Point,
                                delta: egui::vec2(dx, dy),
                                modifiers: egui::Modifiers::default(),
                                phase: egui::TouchPhase::Move,
                            });
                        }
                    }
                    s.last_touch_pos = Some(pos);
                    s.raw_input.events.push(egui::Event::PointerMoved(pos));
                }
                3 => { // ACTION_CANCEL
                    s.last_touch_pos = None;
                    s.raw_input.events.push(egui::Event::PointerGone);
                }
                _ => {}
            }
            self.render_requested.store(true, Ordering::Relaxed);
        }

        pub fn push_scroll(&self, dx: f32, dy: f32) {
            let mut s = self.state.lock().unwrap();
            s.raw_input.events.push(egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(dx, dy),
                modifiers: egui::Modifiers::default(),
                phase: egui::TouchPhase::Move,
            });
            self.render_requested.store(true, Ordering::Relaxed);
        }

        pub fn append_input(&self, text: &str) {
            let mut s = self.state.lock().unwrap();
            s.chat_app.input_value.push_str(text);
            self.render_requested.store(true, Ordering::Relaxed);
        }

        pub fn backspace_input(&self) {
            let mut s = self.state.lock().unwrap();
            s.chat_app.input_value.pop();
            self.render_requested.store(true, Ordering::Relaxed);
        }

        pub fn push_text(&self, text: String) {
            let mut s = self.state.lock().unwrap();
            s.raw_input.events.push(egui::Event::Text(text));
            self.render_requested.store(true, Ordering::Relaxed);
        }

        pub fn push_key(&self, key: egui::Key, pressed: bool) {
            let mut s = self.state.lock().unwrap();
            s.raw_input.events.push(egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: egui::Modifiers::default(),
            });
            self.render_requested.store(true, Ordering::Relaxed);
        }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeInit(
        mut env: JNIEnv,
        _class: JClass,
        context: JObject,
        density: jfloat,
    ) -> jlong {
        android_logger::init_once(
            android_logger::Config::default().with_max_level(log::LevelFilter::Info),
        );

        let vm = env.get_java_vm().expect("Failed to get JavaVM");
        let context_ref = env.new_global_ref(context).expect("Failed to get global context ref");
        let cl_ref = match env.call_method(context_ref.as_obj(), "getClassLoader", "()Ljava/lang/ClassLoader;", &[]) {
            Ok(cl_val) => match cl_val.l() {
                Ok(cl_obj) => env.new_global_ref(cl_obj).expect("Failed to get ClassLoader ref"),
                Err(e) => panic!("getClassLoader returned non-object: {e}"),
            },
            Err(e) => panic!("failed to call getClassLoader: {e}"),
        };

        android_bridge::init(vm, context_ref, cl_ref);

        let renderer = Box::new(AndroidBridgeRenderer::new(density as f32));
        Box::into_raw(renderer) as jlong
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeSurfaceCreated(
        env: JNIEnv,
        _class: JClass,
        ptr: jlong,
        surface: JObject,
        width: jint,
        height: jint,
    ) {
        if ptr == 0 { return; }
        unsafe {
            let renderer = &*(ptr as *const AndroidBridgeRenderer);
            let win_ptr = ndk_sys::ANativeWindow_fromSurface(env.get_native_interface(), surface.as_raw());
            if !win_ptr.is_null() {
                let window = NativeWindow::from_ptr(std::ptr::NonNull::new_unchecked(win_ptr));
                renderer.set_surface(Some(window), width as u32, height as u32);
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeSurfaceChanged(
        _env: JNIEnv,
        _class: JClass,
        ptr: jlong,
        width: jint,
        height: jint,
    ) {
        if ptr == 0 { return; }
        unsafe {
            let renderer = &*(ptr as *const AndroidBridgeRenderer);
            renderer.set_size(width as u32, height as u32);
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeSurfaceDestroyed(
        _env: JNIEnv,
        _class: JClass,
        ptr: jlong,
    ) {
        if ptr == 0 { return; }
        unsafe {
            let renderer = &*(ptr as *const AndroidBridgeRenderer);
            renderer.set_surface(None, 0, 0);
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeTouchEvent(
        _env: JNIEnv,
        _class: JClass,
        ptr: jlong,
        action: jint,
        x: jfloat,
        y: jfloat,
    ) {
        if ptr == 0 { return; }
        unsafe {
            let renderer = &*(ptr as *const AndroidBridgeRenderer);
            renderer.push_touch(action, x as f32, y as f32);
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeCommitText(
        mut env: JNIEnv,
        _class: JClass,
        ptr: jlong,
        text: JString,
    ) {
        if ptr == 0 { return; }
        unsafe {
            let renderer = &*(ptr as *const AndroidBridgeRenderer);
            if let Ok(text_str) = env.get_string(&text) {
                let s: String = text_str.into();
                renderer.append_input(&s);
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeKey(
        _env: JNIEnv,
        _class: JClass,
        ptr: jlong,
        key_code: jint,
        pressed: jboolean,
    ) {
        if ptr == 0 { return; }
        unsafe {
            let renderer = &*(ptr as *const AndroidBridgeRenderer);
            if key_code == 67 && pressed != 0 {
                renderer.backspace_input();
            } else if key_code == 66 && pressed != 0 {
                let mut s = renderer.state.lock().unwrap();
                s.chat_app.submit();
                renderer.render_requested.store(true, Ordering::Relaxed);
                return;
            } else if key_code == 19 && pressed != 0 {
                let mut s = renderer.state.lock().unwrap();
                s.chat_app.navigate_history(true);
                renderer.render_requested.store(true, Ordering::Relaxed);
                return;
            } else if key_code == 20 && pressed != 0 {
                let mut s = renderer.state.lock().unwrap();
                s.chat_app.navigate_history(false);
                renderer.render_requested.store(true, Ordering::Relaxed);
                return;
            } else if key_code == 61 && pressed != 0 {
                let mut s = renderer.state.lock().unwrap();
                s.chat_app.complete_selected();
                renderer.render_requested.store(true, Ordering::Relaxed);
                return;
            }

            let key = match key_code {
                19 => egui::Key::ArrowUp,
                20 => egui::Key::ArrowDown,
                61 => egui::Key::Tab,
                66 => egui::Key::Enter,
                67 => egui::Key::Backspace,
                111 => egui::Key::Escape,
                _ => return,
            };
            renderer.push_key(key, pressed != 0);
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeScroll(
        _env: JNIEnv,
        _class: JClass,
        ptr: jlong,
        dx: jfloat,
        dy: jfloat,
    ) {
        if ptr == 0 { return; }
        unsafe {
            let renderer = &*(ptr as *const AndroidBridgeRenderer);
            renderer.push_scroll(dx as f32, dy as f32);
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeSetInsets(
        _env: JNIEnv,
        _class: JClass,
        ptr: jlong,
        bottom: jfloat,
    ) {
        if ptr == 0 { return; }
        unsafe {
            let renderer = &*(ptr as *const AndroidBridgeRenderer);
            renderer.set_insets_bottom(bottom as f32);
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_com_github_costinm_dmesh_chat_EguiSurfaceView_nativeDestroy(
        _env: JNIEnv,
        _class: JClass,
        ptr: jlong,
    ) {
        if ptr != 0 {
            unsafe {
                let renderer = Box::from_raw(ptr as *mut AndroidBridgeRenderer);
                renderer.running.store(false, Ordering::Relaxed);
            }
        }
    }
}
