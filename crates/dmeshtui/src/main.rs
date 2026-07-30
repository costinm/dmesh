use std::io;
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use dmeshtui::browser::CommandBrowser;
use dmeshtui::commands::{discover_commands, discover_services};
use dmeshtui::local::{LocalMeshSocket, MeshSocketOptions};
use dmeshtui::{MeshClient, Role, UiModel};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut terminal = setup_terminal()?;
    let result = run(&mut terminal, args);
    restore_terminal(&mut terminal)?;
    result
}

#[derive(Debug, Parser)]
#[command(name = "dmeshtui", about = "Terminal UI for local mesh JSONL sockets")]
struct Args {
    #[arg(long)]
    app: Option<String>,
    #[arg(long)]
    remote: Option<String>,
    #[arg(long)]
    target_app: Option<String>,
    #[arg(long, default_value = "mesh.remote.jsonl")]
    remote_method: String,
    #[arg(long)]
    max_messages: Option<usize>,
}

fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, args: Args) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let services = discover_services(&cwd);
    let commands = discover_commands(&cwd);

    let mut model = UiModel::new("DMesh TUI");
    if let Some(max) = args.max_messages {
        model.max_messages = max;
    }

    let first_connected = services.iter().find(|s| s.connected);
    if let Some(svc) = first_connected {
        model.active_service = svc.name.clone();
    } else if let Some(svc) = services.first() {
        model.active_service = svc.name.clone();
    }

    let mut browser = CommandBrowser::new(commands, services.clone());
    let mut client = LocalMeshSocket::from_options(MeshSocketOptions {
        app: Some(model.active_service.clone()),
        socket: None,
        remote: args.remote,
        target_app: args.target_app,
        remote_method: Some(args.remote_method),
    })?;

    loop {
        for event_line in client.poll()? {
            model.push_response(event_line.clone(), event_line);
        }
        terminal.draw(|frame| draw(frame, &model, &browser))?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        handle_key(&mut model, &mut browser, &mut client, &key)?;

        if key.code == KeyCode::Char('q') && key.modifiers.contains(KeyModifiers::CONTROL)
        {
            return Ok(());
        }
    }
}

// ============ KEY HANDLING ============

fn handle_key(
    model: &mut UiModel,
    browser: &mut CommandBrowser,
    client: &mut LocalMeshSocket,
    key: &crossterm::event::KeyEvent,
) -> anyhow::Result<bool> {
    // Ctrl-P: toggle command palette
    if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
        model.show_palette = !model.show_palette;
        if model.show_palette {
            browser.clear();
        }
        return Ok(false);
    }

    // Ctrl-N: cycle active service
    if key.code == KeyCode::Char('n') && key.modifiers.contains(KeyModifiers::CONTROL) {
        model.cycle_service(browser.services());
        client.set_active_service(&model.active_service);
        model.push_system(format!("active service: {}", model.active_service));
        return Ok(false);
    }

    // Palette is open — handle palette keys
    if model.show_palette {
        return handle_palette_key(model, browser, client, key);
    }

    // Global shortcuts
    if key.code == KeyCode::Char('?') {
        model.push_system(dmeshtui::HELP_TEXT);
        return Ok(false);
    }

    // Normal mode keys
    handle_normal_key(model, browser, client, key)
}

fn handle_palette_key(
    model: &mut UiModel,
    browser: &mut CommandBrowser,
    client: &mut LocalMeshSocket,
    key: &crossterm::event::KeyEvent,
) -> anyhow::Result<bool> {
    let exiting = match key.code {
        KeyCode::Esc => {
            model.show_palette = false;
            browser.clear();
            false
        }
        KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.show_palette = false;
            true
        }
        KeyCode::Char(c) => {
            browser.input(c);
            false
        }
        KeyCode::Backspace => {
            browser.backspace();
            false
        }
        KeyCode::Up => {
            browser.select_up();
            false
        }
        KeyCode::Down => {
            browser.select_down();
            false
        }
        KeyCode::Enter => {
            if let Some(cmd) = browser.selected_command() {
                model.active_service = cmd.service.clone();
                client.set_active_service(&cmd.service);
                model.input.clear();
                model.input.push_str(&cmd.name);
                for param in &cmd.params {
                    if param.required {
                        model.input.push(' ');
                        model.input.push_str(&param.name);
                        model.input.push_str(": ");
                    }
                }
            }
            model.show_palette = false;
            browser.clear();
            false
        }
        _ => false,
    };
    Ok(exiting)
}

fn handle_normal_key(
    model: &mut UiModel,
    browser: &CommandBrowser,
    client: &mut LocalMeshSocket,
    key: &crossterm::event::KeyEvent,
) -> anyhow::Result<bool> {
    match key.code {
        KeyCode::Tab => {
            model.cycle_service(browser.services());
            client.set_active_service(&model.active_service);
        }
        KeyCode::Char(c) => model.input.push(c),
        KeyCode::Backspace => {
            let _ = model.input.pop();
        }
        KeyCode::Enter => {
            model.submit_current(client);
        }
        KeyCode::Up => {
            model.scroll_offset = model.scroll_offset.saturating_add(1);
        }
        KeyCode::Down => {
            model.scroll_offset = model.scroll_offset.saturating_sub(1);
        }
        _ => {}
    }
    Ok(false)
}


// ============ DRAW ============

fn draw(frame: &mut Frame<'_>, model: &UiModel, browser: &CommandBrowser) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    draw_content(frame, model, chunks[0]);
    draw_status_bar(frame, model, chunks[1]);
    draw_input_bar(frame, model, chunks[2]);

    if model.show_palette {
        draw_palette(frame, browser, area);
    }
}

// ============ INPUT BAR (top, always visible) ============

fn draw_input_bar(frame: &mut Frame<'_>, model: &UiModel, area: Rect) {
    let style = Style::default()
        .fg(Color::Black)
        .bg(Color::Green)
        .add_modifier(Modifier::BOLD);
    let text = format!("> {}", model.input);
    frame.render_widget(Paragraph::new(text).style(style), area);
}

// ============ CONTENT AREA ============

fn draw_content(frame: &mut Frame<'_>, model: &UiModel, area: Rect) {
    let messages = &model.conversation.messages;
    if messages.is_empty() {
        frame.render_widget(
            Paragraph::new("No messages. Ctrl-P for commands, /help for keys.")
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    }

    let mut lines: Vec<Line<'_>> = Vec::new();
    let max_width = area.width.saturating_sub(4) as usize;

    for msg in messages {
        let (prefix, color) = match msg.role {
            Role::User => ("> ", Color::Yellow),
            Role::Assistant => ("< ", Color::Green),
            Role::System => ("  ", Color::Cyan),
        };

        let content_lines: Vec<&str> = msg.content.lines().collect();
        if content_lines.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("{}(empty)", prefix),
                Style::default().fg(color),
            )));
        } else {
            let first_line: String = content_lines[0].chars().take(max_width).collect();
            lines.push(Line::from(Span::styled(
                format!("{}{}", prefix, first_line),
                Style::default().fg(color),
            )));
            for line in content_lines.iter().skip(1) {
                let truncated: String = line.chars().take(max_width).collect();
                lines.push(Line::from(Span::styled(
                    format!("  {}", truncated),
                    Style::default().fg(color),
                )));
            }
        }
    }

    let total_lines = lines.len();
    let visible_height = area.height as usize;
    let max_scroll = total_lines.saturating_sub(visible_height);
    let scroll_offset = model.scroll_offset.min(max_scroll);
    let row = (total_lines.saturating_sub(visible_height)).saturating_sub(scroll_offset) as u16;

    frame.render_widget(
        Paragraph::new(Text::from(lines)).scroll((row, 0)),
        area,
    );
}

// ============ STATUS BAR ============

fn draw_status_bar(frame: &mut Frame<'_>, model: &UiModel, area: Rect) {
    let service = &model.active_service;
    let msg_count = model.conversation.messages.len();
    let palette_indicator = if model.show_palette { " [PALETTE]" } else { "" };

    frame.render_widget(
        Paragraph::new(format!(
            "{} | {} msgs | Ctrl-P:commands Ctrl-N:switch /help{}",
            service, msg_count, palette_indicator
        ))
        .style(Style::default().fg(Color::Black).bg(Color::Gray)),
        area,
    );
}

// ============ COMMAND PALETTE (centered overlay) ============

fn draw_palette(frame: &mut Frame<'_>, browser: &CommandBrowser, screen: Rect) {
    let palette_w = (screen.width.max(40)).min(100);
    let matches = browser.matches();
    let command_count = matches.len();
    let max_visible = (screen.height.saturating_sub(6)) as usize;
    let visible_count = command_count.min(max_visible);
    let palette_h = (2 + visible_count as u16).min(screen.height.saturating_sub(1));

    let palette_area = Rect {
        x: (screen.width - palette_w) / 2,
        y: 2,
        width: palette_w,
        height: palette_h.min(screen.height - 1),
    };

    frame.render_widget(Clear, palette_area);
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Rgb(30, 30, 46))),
        palette_area,
    );

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .margin(0)
        .split(palette_area);

    let filter_text = format!(" > {} (Esc:close)", browser.filter_text());
    let filter_style = Style::default()
        .fg(Color::Yellow)
        .bg(Color::Rgb(30, 30, 46))
        .add_modifier(Modifier::BOLD);
    frame.render_widget(Paragraph::new(filter_text).style(filter_style), inner[0]);

    if !matches.is_empty() && inner[1].height > 0 {
        let sel = browser.selected_index();
        let entries = browser.entries();
        let visible_height = inner[1].height as usize;

        let skip = if sel >= visible_height {
            sel - visible_height + 1
        } else {
            0
        };

        let mut items: Vec<ListItem> = Vec::new();
        let mut shown = 0;

        for (match_idx, &idx) in matches.iter().enumerate().skip(skip) {
            if shown >= visible_height {
                break;
            }
            let entry = &entries[idx];
            if entry.kind == dmeshtui::browser::EntryKind::Header {
                continue;
            }
            let is_selected = match_idx == sel;
            let style = if is_selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if !entry.connected {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::White)
            };
            let params: Vec<String> = browser
                .all_commands()
                .get(entry.index)
                .map(|cmd| {
                    cmd.params
                        .iter()
                        .filter(|p| p.required)
                        .map(|p| format!("{}:{}", p.name, p.param_type))
                        .collect()
                })
                .unwrap_or_default();
            let param_str = if params.is_empty() {
                String::new()
            } else {
                format!(" [{}]", params.join(", "))
            };
            let desc = if entry.description.is_empty() {
                "(no description)"
            } else {
                &entry.description
            };
            let text = format!("{}: {}{}", entry.name, desc, param_str);
            items.push(ListItem::new(text).style(style));
            shown += 1;
        }

        frame.render_widget(
            List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow)),
                )
                .style(Style::default().bg(Color::Rgb(30, 30, 46))),
            inner[1],
        );
    }
}

// ============ TERMINAL SETUP ============

fn setup_terminal() -> anyhow::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
