use std::io;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::catalog::{AmplificationMethod, METHODS, TransportType};

pub enum GuiAction {
    Quit,
    RunAttack(&'static AmplificationMethod),
}

pub struct GuiApp {
    selected_layer: usize,
    selected_method: usize,
    should_quit: bool,
    pending_attack: Option<&'static AmplificationMethod>,
}

fn unique_layers() -> Vec<&'static str> {
    let mut seen = Vec::new();
    for m in METHODS.iter() {
        let name = m.layer.name();
        if !seen.contains(&name) {
            seen.push(name);
        }
    }
    seen
}

fn methods_in_layer(layer_name: &str) -> Vec<&'static AmplificationMethod> {
    METHODS
        .iter()
        .filter(|m| m.layer.name() == layer_name)
        .collect()
}

impl GuiApp {
    pub fn new() -> Self {
        GuiApp {
            selected_layer: 0,
            selected_method: 0,
            should_quit: false,
            pending_attack: None,
        }
    }

    fn current_layer_name(&self) -> &'static str {
        let layers = unique_layers();
        if layers.is_empty() {
            return "L7 Application";
        }
        layers[self.selected_layer.min(layers.len() - 1)]
    }

    fn current_methods(&self) -> Vec<&'static AmplificationMethod> {
        methods_in_layer(self.current_layer_name())
    }

    fn current_method(&self) -> Option<&'static AmplificationMethod> {
        let methods = self.current_methods();
        methods.get(self.selected_method).copied()
    }

    /// Run the GUI: loop entering/exiting TUI for each action
    pub fn run(&mut self) -> io::Result<()> {
        loop {
            enable_raw_mode()?;
            let mut stdout = io::stdout();
            stdout.execute(EnterAlternateScreen)?;
            let backend = CrosstermBackend::new(stdout);
            let mut terminal = ratatui::Terminal::new(backend)?;
            terminal.clear()?;

            let action = self.run_until_action(&mut terminal)?;

            drop(terminal);
            disable_raw_mode()?;
            let _ = io::stdout().execute(LeaveAlternateScreen);

            match action {
                GuiAction::Quit => break,
                GuiAction::RunAttack(method) => {
                    self.execute_attack(method);
                }
            }
        }
        Ok(())
    }

    /// Returns when the user either quits or wants to run an attack
    fn run_until_action(
        &mut self,
        terminal: &mut ratatui::Terminal<CrosstermBackend<std::io::Stdout>>,
    ) -> io::Result<GuiAction> {
        self.pending_attack = None;
        while !self.should_quit {
            terminal.draw(|f| self.render(f))?;
            self.handle_events()?;
            if let Some(method) = self.pending_attack.take() {
                self.should_quit = false;
                return Ok(GuiAction::RunAttack(method));
            }
        }
        Ok(GuiAction::Quit)
    }

    fn handle_events(&mut self) -> io::Result<()> {
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                        KeyCode::Up | KeyCode::Char('k') => {
                            if self.selected_method > 0 {
                                self.selected_method -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            let methods = self.current_methods();
                            if !methods.is_empty() {
                                self.selected_method =
                                    (self.selected_method + 1).min(methods.len() - 1);
                            }
                        }
                        KeyCode::Left | KeyCode::Char('h') => {
                            if self.selected_layer > 0 {
                                self.selected_layer -= 1;
                                self.selected_method = 0;
                            }
                        }
                        KeyCode::Right | KeyCode::Char('l') => {
                            let layers = unique_layers();
                            if self.selected_layer < layers.len() - 1 {
                                self.selected_layer += 1;
                                self.selected_method = 0;
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(method) = self.current_method() {
                                if method.is_implemented {
                                    self.pending_attack = Some(method);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Run a catalog method by spawning the current binary as a subprocess
    fn execute_attack(&self, method: &'static AmplificationMethod) {
        println!();
        println!("  ⚡ Running: {} (id: {})", method.name, method.id);
        println!("  Layer: {} | Transport: {} | Port: {} | Amplification: {}",
            method.layer.name(), method.transport.name(), method.port, method.ampl_factor);
        println!("  ─────────────────────────────────────────────────────");

        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  Error: cannot find binary path: {}", e);
                println!("\n  Press Enter to return to browser...");
                let _ = io::stdin().read_line(&mut String::new());
                return;
            }
        };

        let concurrency = 10;
        let duration = 15;

        let mut cmd = std::process::Command::new(&exe);

        // HTTP methods (have http_mode)
        if let Some(mode) = method.http_mode {
            cmd.args([
                "--proxy",
                "",
                mode,
                &concurrency.to_string(),
                &duration.to_string(),
            ]);
        } else {
            match method.transport {
                TransportType::Tcp => {
                    let target = format!("127.0.0.1:{}", method.port);
                    cmd.args([
                        "--protocol",
                        "tcp",
                        &target,
                        method.id,
                        &concurrency.to_string(),
                        &duration.to_string(),
                    ]);
                }
                TransportType::Udp => {
                    let target = format!("127.0.0.1:{}", method.port);
                    cmd.args([
                        "--protocol",
                        "udp",
                        &target,
                        method.id,
                        &concurrency.to_string(),
                        &duration.to_string(),
                    ]);
                }
                _ => {
                    println!("  This method ({} transport) is not yet supported from the GUI.",
                        method.transport.name());
                    println!("\n  Press Enter to return to browser...");
                    let _ = io::stdin().read_line(&mut String::new());
                    return;
                }
            }
        }

        let status = cmd.status();
        match status {
            Ok(s) => {
                if !s.success() {
                    if let Some(code) = s.code() {
                        eprintln!("  Attack exited with code {}", code);
                    }
                }
            }
            Err(e) => {
                eprintln!("  Failed to run attack: {}", e);
            }
        }

        println!("\n  ─────────────────────────────────────────────────────");
        println!("  Attack finished. Press Enter to return to browser...");
        let _ = io::stdin().read_line(&mut String::new());
    }

    fn render(&self, f: &mut Frame) {
        let _layers = unique_layers();
        let methods = self.current_methods();
        let selected = self.current_method();

        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(9),
            ])
            .split(f.area());

        // Title
        let title = Paragraph::new(Line::from(Span::styled(
            " simulate-load - Amplification Methods Browser [Enter=run, q=quit] ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        f.render_widget(title, main_chunks[0]);

        // Layer tabs
        let tab_items: Vec<ListItem> = unique_layers()
            .iter()
            .enumerate()
            .map(|(i, layer)| {
                let prefix = if i == self.selected_layer {
                    "▶ "
                } else {
                    "  "
                };
                let style = if i == self.selected_layer {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                let count = methods_in_layer(layer).len();
                ListItem::new(Line::from(Span::styled(
                    format!("{}{}  ({} methods)", prefix, layer, count),
                    style,
                )))
            })
            .collect();
        let layer_tabs = List::new(tab_items)
            .block(Block::default().borders(Borders::ALL).title("Layers"))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        f.render_widget(layer_tabs, main_chunks[1]);

        // Methods list
        let method_items: Vec<ListItem> = methods
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let indicator = if m.is_implemented { "✓ " } else { "○ " };
                let style = if i == self.selected_method {
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else if m.is_implemented {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::White)
                };
                let arrow = if i == self.selected_method {
                    "▸ "
                } else {
                    "  "
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{}{}", arrow, indicator), style),
                    Span::styled(m.name, style),
                    Span::styled(
                        format!("  [{}:{}]", m.transport.name(), m.port),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            })
            .collect();
        let method_list = List::new(method_items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Methods - {} ", self.current_layer_name())),
            )
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        f.render_widget(method_list, main_chunks[2]);

        // Description + hint
        if let Some(m) = selected {
            let mut info = vec![
                Line::from(vec![Span::styled(
                    m.name,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(vec![Span::raw(format!(
                    "Layer: {} | Transport: {} | Port: {} | Amplification: {}",
                    m.layer.name(),
                    m.transport.name(),
                    m.port,
                    m.ampl_factor
                ))]),
                Line::from(vec![Span::raw(format!(
                    "Needs root: {} | Tor-compatible: {} | Status: {}",
                    if m.needs_root { "Yes" } else { "No" },
                    if m.works_with_tor { "Yes" } else { "No" },
                    if m.is_implemented {
                        "IMPLEMENTED"
                    } else {
                        "Not yet"
                    },
                ))]),
            ];
            if m.is_implemented {
                info.push(Line::from(Span::styled(
                    "  Press Enter to run this attack (10 conn, 15s)",
                    Style::default().fg(Color::Yellow),
                )));
            } else {
                info.push(Line::from(Span::styled(
                    "  This method is not yet implemented",
                    Style::default().fg(Color::Red),
                )));
            }
            info.push(Line::from(Span::raw("")));
            for line in m.description.lines() {
                info.push(Line::from(Span::raw(line)));
            }
            let desc = Paragraph::new(Text::from(info))
                .block(Block::default().borders(Borders::ALL).title("Description"))
                .wrap(Wrap { trim: false });
            f.render_widget(desc, main_chunks[3]);
        } else {
            let desc = Paragraph::new("No method selected")
                .block(Block::default().borders(Borders::ALL).title("Description"));
            f.render_widget(desc, main_chunks[3]);
        }
    }
}
