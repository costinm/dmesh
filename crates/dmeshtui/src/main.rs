use std::io;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use dmeshtui::local::{LocalMeshSocket, MeshSocketOptions};
use dmeshtui::{MeshClient, MeshEventKind, UiModel};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

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
    /// Local app UDS to connect to. Defaults to ssh-mesh when --remote is set, otherwise mesh-init.
    #[arg(long)]
    app: Option<String>,

    /// Explicit local UDS socket path.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Remote node routed by the local mesh service.
    #[arg(long)]
    remote: Option<String>,

    /// App on the remote node that should receive JSONL requests.
    #[arg(long)]
    target_app: Option<String>,

    /// Local service method used to route remote JSONL requests.
    #[arg(long, default_value = "mesh.remote.jsonl")]
    remote_method: String,
}

fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, args: Args) -> anyhow::Result<()> {
    let mut model = UiModel::new("DMesh TUI");
    let mut client = LocalMeshSocket::from_options(MeshSocketOptions {
        app: args.app,
        socket: args.socket,
        remote: args.remote,
        target_app: args.target_app,
        remote_method: Some(args.remote_method),
    })?;

    loop {
        for event in client.poll()? {
            model.push(MeshEventKind::Inbound, event);
        }
        terminal.draw(|frame| draw(frame, &model))?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Char(c) => model.input.push(c),
            KeyCode::Backspace => {
                model.input.pop();
            }
            KeyCode::Enter => {
                if model.input.trim() == "/quit" {
                    return Ok(());
                }
                model.submit_current(&mut client);
            }
            KeyCode::Esc => return Ok(()),
            _ => {}
        }
    }
}

fn draw(frame: &mut ratatui::Frame<'_>, model: &UiModel) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    let lines = model.events.iter().map(|event| {
        let style = match event.kind {
            MeshEventKind::Info => Style::default().fg(Color::Cyan),
            MeshEventKind::Inbound => Style::default().fg(Color::Green),
            MeshEventKind::Outbound => Style::default().fg(Color::Yellow),
            MeshEventKind::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        };
        Line::from(vec![
            Span::styled(format!("{:?}", event.kind), style),
            Span::raw(" "),
            Span::raw(event.text.clone()),
        ])
    });

    frame.render_widget(
        Paragraph::new(lines.collect::<Vec<_>>())
            .block(Block::default().title(model.title.as_str()).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(model.input.as_str())
            .block(Block::default().title("Command").borders(Borders::ALL)),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new("Enter sends JSONL to local UDS. Esc exits. --remote wraps requests for local mesh routing."),
        chunks[2],
    );
}

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
