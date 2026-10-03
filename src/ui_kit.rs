//! Workbench components from spec §1–§2. Screens compose these instead of
//! styling egui widgets directly, so every tab shares one visual vocabulary:
//! panels with badges, control strips, grid tables with per-cell selection,
//! verdict pills, key hints, position-coloured meters and bar sparklines.
use crate::shell::{Hint, Key, Strip};
use crate::theme;
use egui::{
    pos2, text::LayoutJob, vec2, Align, Align2, Color32, FontFamily, FontId, Rect, Response,
    RichText, Rounding, Sense, Stroke, TextFormat, Ui,
};

// ---------------------------------------------------------------- text

pub fn mono(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text).size(size).color(color)
}
/// Semibold Plex Mono (titles, severity words, hero values).
pub fn strong(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text)
        .family(FontFamily::Name(theme::SEMIBOLD.into()))
        .size(size)
        .color(color)
}
pub fn data(text: impl Into<String>) -> RichText {
    mono(text, theme::DATA, theme::text())
}
pub fn label(text: impl Into<String>) -> RichText {
    mono(text, theme::LABEL, theme::text2())
}
pub fn meta(text: impl Into<String>) -> RichText {
    mono(text, theme::META, theme::muted())
}

pub fn text_width(ui: &Ui, text: &str, font: FontId) -> f32 {
    ui.fonts(|f| f.layout_no_wrap(text.into(), font, Color32::WHITE).size().x)
}

/// Draws `text` into `rect`, truncating with `…` when it does not fit.
/// Returns the laid-out width.
pub fn paint_text(
    ui: &Ui,
    rect: Rect,
    text: &str,
    font: FontId,
    color: Color32,
    align: Align,
) -> f32 {
    let mut job = LayoutJob::single_section(text.into(), TextFormat::simple(font, color));
    job.wrap.max_width = rect.width().max(1.0);
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    job.wrap.overflow_character = Some('…');
    let galley = ui.fonts(|f| f.layout_job(job));
    let x = match align {
        Align::Min => rect.left(),
        Align::Center => rect.center().x - galley.size().x / 2.0,
        Align::Max => rect.right() - galley.size().x,
    };
    let y = rect.center().y - galley.size().y / 2.0;
    let width = galley.size().x;
    ui.painter()
        .with_clip_rect(rect)
        .galley(pos2(x, y), galley, color);
    width
}

/// 10px letter-spaced section heading (inspector sections).
pub fn section(ui: &mut Ui, text: &str) {
    ui.add_space(6.0);
    let mut job = LayoutJob::default();
    job.append(
        text,
        0.0,
        TextFormat {
            font_id: FontId::monospace(theme::META),
            color: theme::muted(),
            extra_letter_spacing: 0.4,
            ..Default::default()
        },
    );
    ui.label(job);
    ui.add_space(2.0);
}

// ---------------------------------------------------------------- chips

#[allow(clippy::too_many_arguments)]
fn chip_shape(
    ui: &mut Ui,
    text: &str,
    font: FontId,
    fg: Color32,
    bg: Color32,
    padding: egui::Vec2,
    radius: f32,
    sense: Sense,
) -> Response {
    let galley = ui.fonts(|f| f.layout_no_wrap(text.into(), font, fg));
    let size = galley.size() + padding * 2.0;
    let (rect, response) = ui.allocate_exact_size(size, sense);
    if ui.is_rect_visible(rect) {
        ui.painter().rect_filled(rect, radius, bg);
        ui.painter().galley(rect.min + padding, galley, fg);
    }
    response
}

/// Inverse chip carrying the key of the tab a panel summarises.
pub fn badge(ui: &mut Ui, key: &str) -> Response {
    chip_shape(
        ui,
        key,
        theme::semibold(theme::LABEL),
        theme::inverse(),
        theme::text2(),
        vec2(5.0, 0.0),
        3.0,
        Sense::hover(),
    )
}

/// Title-bar chip: 11px 600 on a status ground with dark text.
pub fn chip(ui: &mut Ui, text: &str, ground: Color32) -> Response {
    chip_shape(
        ui,
        text,
        theme::semibold(theme::LABEL),
        theme::inverse(),
        ground,
        vec2(7.0, 2.0),
        3.0,
        Sense::click(),
    )
}

/// Verdict pill: lowercase, 11px 600, 9px radius, inverse text on the
/// severity ground. `None` renders the muted variant (raised ground).
pub fn pill(ui: &mut Ui, text: &str, severity: Option<Color32>) -> Response {
    let (fg, bg) = match severity {
        Some(color) => (theme::inverse(), color),
        None => (theme::muted(), theme::raised()),
    };
    chip_shape(
        ui,
        &text.to_lowercase(),
        theme::semibold(theme::LABEL),
        fg,
        bg,
        vec2(7.0, 1.0),
        9.0,
        Sense::hover(),
    )
}

/// Paints a pill at a position without allocating (table cells).
pub fn paint_pill(ui: &Ui, rect: Rect, text: &str, severity: Option<Color32>, align: Align) {
    let (fg, bg) = match severity {
        Some(color) => (theme::inverse(), color),
        None => (theme::muted(), theme::raised()),
    };
    let galley =
        ui.fonts(|f| f.layout_no_wrap(text.to_lowercase(), theme::semibold(theme::LABEL), fg));
    let size = galley.size() + vec2(14.0, 2.0);
    let size = vec2(size.x.min(rect.width()), size.y);
    let x = match align {
        Align::Min => rect.left(),
        Align::Center => rect.center().x - size.x / 2.0,
        Align::Max => rect.right() - size.x,
    };
    let pill = Rect::from_min_size(pos2(x, rect.center().y - size.y / 2.0), size);
    let painter = ui.painter().with_clip_rect(rect);
    painter.rect_filled(pill, 9.0, bg);
    painter.galley(pill.min + vec2(7.0, 1.0), galley, fg);
}

// ---------------------------------------------------------------- keys

/// `key` in key colour, one space, `label` in muted. Clickable — hints are
/// the only buttons the app has.
pub fn key_hint(ui: &mut Ui, hint: &Hint) -> bool {
    let mut job = LayoutJob::default();
    job.append(
        &hint.key_text(),
        0.0,
        TextFormat::simple(FontId::monospace(theme::LABEL), theme::key_hint()),
    );
    job.append(
        &hint.label,
        6.0,
        TextFormat::simple(FontId::monospace(theme::LABEL), theme::muted()),
    );
    let galley = ui.fonts(|f| f.layout_job(job));
    let (rect, response) = ui.allocate_exact_size(galley.size(), Sense::click());
    if ui.is_rect_visible(rect) {
        if response.hovered() {
            ui.painter()
                .rect_filled(rect.expand2(vec2(3.0, 1.0)), 3.0, theme::raised());
        }
        ui.painter().galley(rect.min, galley, theme::text());
    }
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// A row of hints with the spec's 16px gap; returns the clicked key.
pub fn hint_row(ui: &mut Ui, hints: &[Hint]) -> Option<Key> {
    let mut clicked = None;
    for (i, hint) in hints.iter().enumerate() {
        if i > 0 {
            ui.add_space(10.0);
        }
        if key_hint(ui, hint) {
            clicked = Some(hint.key);
        }
    }
    clicked
}

// ---------------------------------------------------------------- panels

pub struct PanelHead<'a> {
    /// The tab key this panel summarises (inverse chip); None for unbadged.
    pub badge: Option<&'a str>,
    pub title: &'a str,
    /// Right-aligned muted metadata: counts, windows, provenance.
    pub meta: &'a str,
    pub focused: bool,
}

impl<'a> PanelHead<'a> {
    pub fn new(title: &'a str) -> Self {
        Self {
            badge: None,
            title,
            meta: "",
            focused: false,
        }
    }
    pub fn badge(mut self, key: &'a str) -> Self {
        self.badge = Some(key);
        self
    }
    pub fn meta(mut self, meta: &'a str) -> Self {
        self.meta = meta;
        self
    }
    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }
}

/// A panel: 1px border (accent when focused), 6px radius, panel ground,
/// title row with badge · accent title · muted metadata, then the body.
/// `extra` draws right-aligned header content before the metadata (keys).
pub fn panel<R>(ui: &mut Ui, head: PanelHead, body: impl FnOnce(&mut Ui) -> R) -> R {
    panel_with(ui, head, |_| {}, body)
}

pub fn panel_with<R>(
    ui: &mut Ui,
    head: PanelHead,
    extra: impl FnOnce(&mut Ui),
    body: impl FnOnce(&mut Ui) -> R,
) -> R {
    let stroke = Stroke::new(
        1.0_f32,
        if head.focused {
            theme::accent()
        } else {
            theme::border()
        },
    );
    egui::Frame::none()
        .fill(theme::panel())
        .stroke(stroke)
        .rounding(6.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing = vec2(6.0, 4.0);
            egui::Frame::none()
                .inner_margin(egui::Margin::symmetric(10.0, 5.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.set_min_height(18.0);
                        if let Some(key) = head.badge {
                            badge(ui, key);
                        }
                        ui.label(strong(head.title, theme::DATA, theme::accent()));
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            // Extras wider than the room beside the title are
                            // cut at its edge, never drawn over it.
                            ui.set_clip_rect(ui.max_rect().intersect(ui.clip_rect()));
                            extra(ui);
                            if !head.meta.is_empty() {
                                ui.add(
                                    egui::Label::new(mono(head.meta, theme::LABEL, theme::muted()))
                                        .truncate(),
                                );
                            }
                        });
                    });
                });
            let line = ui.available_rect_before_wrap();
            ui.painter().hline(
                line.x_range(),
                line.top(),
                Stroke::new(1.0_f32, theme::border()),
            );
            egui::Frame::none()
                .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    body(ui)
                })
                .inner
        })
        .inner
}

/// A panel that fills exactly `rect` (fixed layouts: dashboards, splits).
pub fn panel_in<R>(ui: &mut Ui, rect: Rect, head: PanelHead, body: impl FnOnce(&mut Ui) -> R) -> R {
    ui.allocate_ui_at_rect(rect, |ui| {
        ui.set_clip_rect(rect.intersect(ui.clip_rect()));
        panel(ui, head, |ui| {
            let remaining = rect.bottom() - ui.min_rect().top() - 8.0;
            ui.set_min_height(remaining.max(0.0));
            ui.set_max_height(remaining.max(0.0));
            body(ui)
        })
    })
    .inner
}

// ---------------------------------------------------------------- strips

pub struct StripGroup<'a> {
    pub label: &'a str,
    /// (option text, optional count shown inside the option).
    pub options: Vec<(String, Option<usize>)>,
    pub active: usize,
}

/// Height of each line a control strip wraps onto after its first.
const STRIP_WRAP_HEIGHT: f32 = 24.0;

fn strip_option(group: &StripGroup, option: usize) -> String {
    match &group.options[option] {
        (text, Some(n)) => format!("{text} {n}"),
        (text, None) => text.clone(),
    }
}

/// Lays a control strip's options out in lines of at most `first_room`
/// points (the first line, beside the keys) and then `room`. Each entry is
/// (group, option), with `None` for the group's label, which always shares
/// a line with its first option. A group that does not fit on the current
/// line starts the next one when that holds all of it, and is split only
/// when no line could. The first line may be left to the keys.
fn strip_lines(
    ui: &Ui,
    groups: &[StripGroup],
    first_room: f32,
    room: f32,
) -> Vec<Vec<(usize, Option<usize>)>> {
    let font = FontId::monospace(theme::LABEL);
    let gap = ui.spacing().item_spacing.x;
    // A hair over the text, so rounding never pushes a chip past the edge.
    let width_of = |text: &str| text_width(ui, text, font.clone()) + 1.0;
    let mut lines: Vec<Vec<(usize, Option<usize>)>> = vec![Vec::new()];
    let mut used = 0.0;
    for (g, group) in groups.iter().enumerate() {
        let mut units = vec![(vec![(g, None)], width_of(group.label))];
        for o in 0..group.options.len() {
            // Chips have 7 pt of padding each side.
            let chip = width_of(&strip_option(group, o)) + 14.0;
            if o == 0 {
                units[0].0.push((g, Some(0)));
                units[0].1 += gap + chip;
            } else {
                units.push((vec![(g, Some(o))], chip));
            }
        }
        let whole = units.iter().map(|(_, width)| width).sum::<f32>()
            + gap * units.len().saturating_sub(1) as f32;
        let empty = lines.last().is_some_and(|line| line.is_empty());
        let lead = if empty { 0.0 } else { 14.0 + gap };
        let limit = if lines.len() == 1 { first_room } else { room };
        if used + lead + whole > limit && whole <= room && !(empty && limit >= room) {
            lines.push(Vec::new());
            used = 0.0;
        }
        for (i, (entries, width)) in units.into_iter().enumerate() {
            let empty = lines.last().is_some_and(|line| line.is_empty());
            let lead = match (empty, i) {
                (true, _) => 0.0,
                (false, 0) => 14.0 + gap,
                (false, _) => gap,
            };
            let limit = if lines.len() == 1 { first_room } else { room };
            // An empty line with the whole width keeps whatever comes, even
            // something wider than it; only the keys' line passes it on.
            if used + lead + width > limit && !(empty && limit >= room) {
                lines.push(Vec::new());
                used = width;
            } else {
                used += lead + width;
            }
            lines.last_mut().unwrap().extend(entries);
        }
    }
    lines
}

/// The 30px control strip: dim group label, options (active = filled
/// chip), counts inside options, right-aligned keys. Options that do not
/// fit beside the keys wrap onto further lines instead of running under
/// them. Returns the clicked (group, option) and any clicked key.
pub fn control_strip(
    ui: &mut Ui,
    groups: &[StripGroup],
    keys: &[Hint],
) -> (Option<(usize, usize)>, Option<Key>) {
    let mut picked = None;
    let mut key = None;
    let width = ui.available_width();
    let font = FontId::monospace(theme::LABEL);
    // Each key: its text, 6 pt, its label, then 8 pt and the item gap.
    let keys_w: f32 = keys
        .iter()
        .map(|h| {
            text_width(ui, &h.key_text(), font.clone())
                + 6.0
                + text_width(ui, &h.label, font.clone())
                + 8.0
                + ui.spacing().item_spacing.x
        })
        .sum();
    let first_room = if keys.is_empty() {
        width
    } else {
        width - keys_w - 14.0
    };
    let lines = strip_lines(ui, groups, first_room, width);
    for (n, line) in lines.iter().enumerate() {
        let height = if n == 0 {
            theme::STRIP_HEIGHT
        } else {
            STRIP_WRAP_HEIGHT
        };
        ui.allocate_ui_with_layout(
            vec2(width, height),
            egui::Layout::left_to_right(Align::Center),
            |ui| {
                ui.set_min_height(height);
                for (i, &(g, option)) in line.iter().enumerate() {
                    let group = &groups[g];
                    let Some(o) = option else {
                        if i > 0 {
                            ui.add_space(14.0);
                        }
                        ui.label(mono(group.label, theme::LABEL, theme::muted()));
                        continue;
                    };
                    let active = o == group.active;
                    let response = chip_shape(
                        ui,
                        &strip_option(group, o),
                        FontId::monospace(theme::LABEL),
                        if active {
                            theme::text()
                        } else {
                            theme::text2()
                        },
                        if active {
                            theme::raised()
                        } else {
                            Color32::TRANSPARENT
                        },
                        vec2(7.0, 2.0),
                        3.0,
                        Sense::click(),
                    );
                    if response
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        picked = Some((g, o));
                    }
                }
                if n == 0 {
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        for hint in keys.iter().rev() {
                            if key_hint(ui, hint) {
                                key = Some(hint.key);
                            }
                            ui.add_space(8.0);
                        }
                    });
                }
            },
        );
    }
    (picked, key)
}

/// The status strip: 3px severity rail, severity word bold in its colour,
/// sentence, right-aligned contextual keys.
pub fn status_strip(ui: &mut Ui, strip: &Strip) -> Option<Key> {
    let mut clicked = None;
    let (rect, _) = ui.allocate_exact_size(
        vec2(ui.available_width(), theme::STRIP_HEIGHT),
        Sense::hover(),
    );
    let rail = Rect::from_min_size(rect.min + vec2(0.0, 5.0), vec2(3.0, rect.height() - 10.0));
    ui.painter().rect_filled(rail, 1.0, strip.color);
    ui.allocate_ui_at_rect(rect.shrink2(vec2(12.0, 0.0)), |ui| {
        ui.horizontal_centered(|ui| {
            ui.label(strong(&strip.word, theme::DATA, strip.color));
            ui.add(egui::Label::new(mono(&strip.sentence, theme::DATA, theme::text())).truncate());
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                for hint in strip.keys.iter().rev() {
                    if key_hint(ui, hint) {
                        clicked = Some(hint.key);
                    }
                    ui.add_space(8.0);
                }
            });
        });
    });
    clicked
}

// ---------------------------------------------------------------- tables

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Width {
    /// Exact pixels.
    Px(f32),
    /// Share of the remaining width, never below `min` pixels.
    Flex(f32, f32),
}

#[derive(Clone, Debug)]
pub struct Column {
    pub title: String,
    pub width: Width,
    pub align: Align,
}

impl Column {
    pub fn px(title: impl Into<String>, px: f32) -> Self {
        Self {
            title: title.into(),
            width: Width::Px(px),
            align: Align::Min,
        }
    }
    pub fn flex(title: impl Into<String>, weight: f32, min: f32) -> Self {
        Self {
            title: title.into(),
            width: Width::Flex(weight, min),
            align: Align::Min,
        }
    }
    /// Right-aligned (rates, counts, durations).
    pub fn right(mut self) -> Self {
        self.align = Align::Max;
        self
    }
    #[allow(dead_code)]
    pub fn center(mut self) -> Self {
        self.align = Align::Center;
        self
    }
}

pub const COLUMN_GAP: f32 = 4.0;

/// The narrowest a row of `columns` can be: every column at its minimum.
pub fn min_width(columns: &[Column]) -> f32 {
    resolve_widths(columns, 0.0).iter().sum::<f32>()
        + COLUMN_GAP * columns.len().saturating_sub(1) as f32
}

/// Resolves column widths for `available` pixels (4px gaps between cells).
pub fn resolve_widths(columns: &[Column], available: f32) -> Vec<f32> {
    let gaps = COLUMN_GAP * columns.len().saturating_sub(1) as f32;
    let fixed: f32 = columns
        .iter()
        .map(|c| match c.width {
            Width::Px(px) => px,
            Width::Flex(_, min) => min,
        })
        .sum();
    let weights: f32 = columns
        .iter()
        .map(|c| match c.width {
            Width::Flex(w, _) => w,
            _ => 0.0,
        })
        .sum();
    let spare = (available - gaps - fixed).max(0.0);
    columns
        .iter()
        .map(|c| match c.width {
            Width::Px(px) => px,
            Width::Flex(w, min) => {
                min + if weights > 0.0 {
                    spare * w / weights
                } else {
                    0.0
                }
            }
        })
        .collect()
}

pub type CellPainter = Box<dyn FnOnce(&Ui, Rect)>;

/// What one cell renders.
pub enum Cell {
    Text(String, Color32),
    /// Name in text colour followed by a muted suffix (`ncat 473`).
    Pair(String, Color32, String),
    Pill(String, Option<Color32>),
    Empty,
    /// Custom painting inside the cell rect.
    Paint(CellPainter),
}

impl Cell {
    pub fn text(text: impl Into<String>) -> Self {
        Cell::Text(text.into(), theme::text())
    }
    pub fn muted(text: impl Into<String>) -> Self {
        Cell::Text(text.into(), theme::muted())
    }
    pub fn colored(text: impl Into<String>, color: Color32) -> Self {
        Cell::Text(text.into(), color)
    }
    pub fn paint(f: impl FnOnce(&Ui, Rect) + 'static) -> Self {
        Cell::Paint(Box::new(f))
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct TableResponse {
    pub clicked: Option<usize>,
    pub double_clicked: Option<usize>,
    pub secondary: Option<usize>,
    pub header_clicked: Option<usize>,
    /// A right-click menu entry chosen this frame: (row, its key).
    pub menu: Option<(usize, crate::shell::Key)>,
}

/// Data rows are 12px text with 4px/6px cell padding (22px) in the compact
/// density, 8px padding (30px) in comfortable.
pub const ROW_HEIGHT: f32 = 22.0;

/// A spec table: lowercase 10px muted header, grid cells with a 4px gutter,
/// the selected row's cells on the raised ground (gutters stay panel
/// ground). Rows are virtualized; `scroll_to` centres a row once.
pub struct Table<'a> {
    pub id: &'a str,
    pub columns: &'a [Column],
    pub rows: usize,
    pub selected: Option<usize>,
    pub scroll_to: Option<usize>,
    pub row_height: f32,
    /// Column index sorted by, with an arrow in its header.
    pub sort: Option<(usize, bool)>,
    /// Rows drawn as full-width group headers (text only, first cell spans).
    pub max_height: Option<f32>,
    /// Right-click menu entries for a row; a chosen entry comes back in
    /// [`TableResponse::menu`] and should be dispatched like its key.
    pub menu: Option<&'a dyn Fn(usize) -> Vec<crate::shell::Hint>>,
}

impl<'a> Table<'a> {
    pub fn new(id: &'a str, columns: &'a [Column], rows: usize) -> Self {
        Self {
            id,
            columns,
            rows,
            selected: None,
            scroll_to: None,
            row_height: ROW_HEIGHT,
            sort: None,
            max_height: None,
            menu: None,
        }
    }
    /// Right-click menu for each row: the same actions its inspector offers.
    pub fn menu(mut self, entries: &'a dyn Fn(usize) -> Vec<crate::shell::Hint>) -> Self {
        self.menu = Some(entries);
        self
    }
    pub fn selected(mut self, row: Option<usize>) -> Self {
        self.selected = row;
        self
    }
    pub fn scroll_to(mut self, row: Option<usize>) -> Self {
        self.scroll_to = row;
        self
    }
    pub fn sort(mut self, column: usize, descending: bool) -> Self {
        self.sort = Some((column, descending));
        self
    }
    pub fn max_height(mut self, height: f32) -> Self {
        self.max_height = Some(height);
        self
    }

    /// `cell(row, column)` builds each visible cell. `row_style(row)` may
    /// return a full-width group header text instead of cells. Narrower
    /// than every column's minimum, the table scrolls sideways rather than
    /// cut its last columns off, under a scroll bar that stays drawn so the
    /// cut is visible (shift + wheel, or drag or click the bar).
    pub fn show(
        self,
        ui: &mut Ui,
        cell: impl FnMut(usize, usize) -> Cell,
        group: impl FnMut(usize) -> Option<(String, Color32)>,
    ) -> TableResponse {
        let needed = min_width(self.columns);
        if needed <= ui.available_width() + 0.5 {
            return self.show_columns(ui, cell, group);
        }
        let scroll_style = ui.spacing().scroll;
        ui.spacing_mut().scroll = theme::shown_scroll_bars();
        let out = egui::ScrollArea::horizontal()
            .id_source((self.id, "columns"))
            .show(ui, |ui| {
                // The rows' own scroll bar keeps the usual style.
                ui.spacing_mut().scroll = scroll_style;
                ui.set_width(needed);
                self.show_columns(ui, cell, group)
            })
            .inner;
        ui.spacing_mut().scroll = scroll_style;
        out
    }

    fn show_columns(
        self,
        ui: &mut Ui,
        mut cell: impl FnMut(usize, usize) -> Cell,
        mut group: impl FnMut(usize) -> Option<(String, Color32)>,
    ) -> TableResponse {
        let mut out = TableResponse::default();
        let widths = resolve_widths(self.columns, ui.available_width());
        // Header.
        let (header, _) = ui.allocate_exact_size(vec2(ui.available_width(), 18.0), Sense::hover());
        let mut x = header.left();
        for (i, (column, width)) in self.columns.iter().zip(&widths).enumerate() {
            let rect = Rect::from_min_size(pos2(x, header.top()), vec2(*width, header.height()));
            let mut title = column.title.clone();
            if let Some((sorted, descending)) = self.sort {
                if sorted == i {
                    title.push_str(if descending { " ↓" } else { " ↑" });
                }
            }
            let response = ui.interact(rect, ui.id().with((self.id, "h", i)), Sense::click());
            if response.clicked() {
                out.header_clicked = Some(i);
            }
            paint_text(
                ui,
                rect.shrink2(vec2(6.0, 0.0)),
                &title,
                FontId::monospace(theme::META),
                if response.hovered() {
                    theme::text2()
                } else {
                    theme::muted()
                },
                column.align,
            );
            x += width + COLUMN_GAP;
        }
        let stride = self.row_height + 2.0;
        let mut scroll = egui::ScrollArea::vertical()
            .id_source(self.id)
            .auto_shrink([false, self.max_height.is_some()]);
        if let Some(h) = self.max_height {
            scroll = scroll.max_height(h);
        }
        if let Some(row) = self.scroll_to {
            let viewport = self.max_height.unwrap_or(ui.available_height());
            scroll = scroll.vertical_scroll_offset((row as f32 * stride - viewport / 2.0).max(0.0));
        }
        let selected = self.selected;
        let columns = self.columns;
        let id = self.id;
        let row_height = self.row_height;
        scroll.show_rows(ui, row_height, self.rows, |ui, range| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for row in range {
                let (rect, response) =
                    ui.allocate_exact_size(vec2(ui.available_width(), row_height), Sense::click());
                if response.clicked() {
                    out.clicked = Some(row);
                }
                if response.double_clicked() {
                    out.double_clicked = Some(row);
                }
                if response.secondary_clicked() {
                    out.secondary = Some(row);
                }
                if let Some(entries) = self.menu {
                    response.context_menu(|ui| {
                        let entries = entries(row);
                        if entries.is_empty() {
                            ui.label(meta("no actions"));
                        }
                        for hint in entries {
                            let text = format!("{}  {}", hint.key_text(), hint.label);
                            if ui.button(mono(text, theme::LABEL, theme::text())).clicked() {
                                out.menu = Some((row, hint.key));
                                ui.close_menu();
                            }
                        }
                    });
                }
                if !ui.is_rect_visible(rect) {
                    continue;
                }
                if let Some((text, color)) = group(row) {
                    let chosen = selected == Some(row);
                    ui.painter().rect_filled(rect, 3.0, theme::raised());
                    if chosen {
                        ui.painter().rect_stroke(
                            rect.shrink(0.5),
                            3.0,
                            Stroke::new(1.0_f32, theme::accent()),
                        );
                    }
                    paint_text(
                        ui,
                        rect.shrink2(vec2(8.0, 0.0)),
                        &text,
                        FontId::monospace(theme::LABEL),
                        if chosen { theme::accent() } else { color },
                        Align::Min,
                    );
                    continue;
                }
                let hovered = response.hovered();
                let mut x = rect.left();
                for (col, (column, width)) in columns.iter().zip(&widths).enumerate() {
                    let cell_rect =
                        Rect::from_min_size(pos2(x, rect.top()), vec2(*width, rect.height()));
                    if selected == Some(row) {
                        ui.painter().rect_filled(cell_rect, 3.0, theme::raised());
                    } else if hovered {
                        ui.painter().rect_filled(
                            cell_rect,
                            3.0,
                            theme::raised().gamma_multiply(0.45),
                        );
                    }
                    let inner = cell_rect.shrink2(vec2(6.0, 0.0));
                    match cell(row, col) {
                        Cell::Text(text, color) => {
                            paint_text(
                                ui,
                                inner,
                                &text,
                                FontId::monospace(theme::DATA),
                                color,
                                column.align,
                            );
                        }
                        Cell::Pair(name, color, suffix) => {
                            let w = paint_text(
                                ui,
                                inner,
                                &name,
                                FontId::monospace(theme::DATA),
                                color,
                                Align::Min,
                            );
                            let rest = Rect::from_min_max(
                                pos2(inner.left() + w + 6.0, inner.top()),
                                inner.max,
                            );
                            if rest.width() > 8.0 {
                                paint_text(
                                    ui,
                                    rest,
                                    &suffix,
                                    FontId::monospace(theme::DATA),
                                    theme::muted(),
                                    Align::Min,
                                );
                            }
                        }
                        Cell::Pill(text, severity) => {
                            paint_pill(ui, inner, &text, severity, column.align)
                        }
                        Cell::Empty => {}
                        Cell::Paint(f) => f(ui, inner),
                    }
                    x += width + COLUMN_GAP;
                }
                let _ = id;
            }
        });
        out
    }
}

/// Key/value grid (`auto 1fr`, gap 5px 12px). `pairs` columns per row:
/// 1 for a plain list, 2 for tcp_info-style double columns.
pub fn kv_grid(ui: &mut Ui, id: &str, rows: &[(&str, String, Color32)], pairs: usize) {
    egui::Grid::new(id)
        .num_columns(pairs * 2)
        .spacing(vec2(12.0, 5.0))
        .show(ui, |ui| {
            for (i, (k, v, color)) in rows.iter().enumerate() {
                ui.label(mono(*k, theme::LABEL, theme::muted()));
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    ui.add(egui::Label::new(mono(v, theme::DATA, *color)).truncate());
                });
                if (i + 1) % pairs == 0 {
                    ui.end_row();
                }
            }
        });
}

/// Inspector header: badge · subject · verdict pill, then a muted line.
pub fn inspector_head(
    ui: &mut Ui,
    badge_key: Option<&str>,
    subject: &str,
    pill_text: Option<(&str, Option<Color32>)>,
    detail: &[String],
) {
    ui.horizontal(|ui| {
        if let Some(key) = badge_key {
            badge(ui, key);
        }
        ui.add(egui::Label::new(strong(subject, theme::DATA, theme::accent())).truncate());
        if let Some((text, severity)) = pill_text {
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                pill(ui, text, severity);
            });
        }
    });
    for line in detail {
        ui.label(mono(line, theme::LABEL, theme::text2()));
    }
}

/// Actions list: key 14px wide in key colour + label in text2.
pub fn actions(ui: &mut Ui, hints: &[Hint]) -> Option<Key> {
    let mut clicked = None;
    for (i, hint) in hints.iter().enumerate() {
        let response = ui
            .push_id(("action", i), |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(vec2(14.0, 16.0), Sense::hover());
                    paint_text(
                        ui,
                        rect,
                        &hint.key_text(),
                        FontId::monospace(theme::LABEL),
                        theme::key_hint(),
                        Align::Min,
                    );
                    ui.label(mono(&hint.label, theme::LABEL, theme::text2()));
                })
            })
            .inner
            .response
            .interact(Sense::click());
        if response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            clicked = Some(hint.key);
        }
    }
    clicked
}

/// Horizontal rule inside panels and inspectors.
pub fn rule(ui: &mut Ui) {
    let rect = ui.available_rect_before_wrap();
    ui.painter().hline(
        rect.x_range(),
        rect.top() + 3.0,
        Stroke::new(1.0_f32, theme::border()),
    );
    ui.add_space(7.0);
}

// ---------------------------------------------------------------- charts

/// Status colour along a track: good → warn → error by position.
pub fn status_ramp(fraction: f32) -> Color32 {
    let f = fraction.clamp(0.0, 1.0);
    if f < 0.5 {
        lerp(theme::good(), theme::warn(), f * 2.0)
    } else {
        lerp(theme::warn(), theme::error(), (f - 0.5) * 2.0)
    }
}

pub fn lerp(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

pub fn paint_meter(ui: &Ui, rect: Rect, fraction: Option<f32>, magnitude: bool) {
    let segments = ((rect.width() / 5.0).floor() as usize).clamp(4, 60);
    let gap = 1.0;
    let w = (rect.width() - gap * (segments - 1) as f32) / segments as f32;
    let lit = fraction.map(|f| (f.clamp(0.0, 1.0) * segments as f32).ceil() as usize);
    let painter = ui.painter();
    for i in 0..segments {
        let position = (i as f32 + 0.5) / segments as f32;
        let color = if magnitude {
            lerp(theme::rx_dim(), theme::rx(), position)
        } else {
            status_ramp(position)
        };
        let on = lit.is_some_and(|l| i < l.max(if fraction.unwrap_or(0.0) > 0.0 { 1 } else { 0 }));
        let x = rect.left() + i as f32 * (w + gap);
        let seg = Rect::from_min_size(pos2(x, rect.top()), vec2(w, rect.height()));
        painter.rect_filled(seg, 1.0, if on { color } else { theme::raised() });
    }
}

/// Batches chart bars into one mesh and draws them in the app-wide graph
/// look: btop dot cells lit from the baseline, or solid bars. With fade on,
/// colour runs dim at the baseline to the series colour at full scale (the
/// btop magnitude gradient); off, bars are the flat series colour.
pub struct Bars {
    mesh: egui::Mesh,
    clip: Rect,
    look: theme::GraphLook,
    pitch: f32,
    dot: f32,
    quads: usize,
}

/// Cap on unlit capacity dots per batch; lit cells always draw.
const CAPACITY_QUADS: usize = 24_000;

impl Bars {
    pub fn new(ui: &Ui, clip: Rect) -> Self {
        // Cells land on whole physical pixels: 3px pitch, 2px dots at 1x.
        let ppp = ui.ctx().pixels_per_point();
        let pitch = (3.0 * ppp).round().max(2.0) / ppp;
        Self {
            mesh: egui::Mesh::default(),
            clip,
            look: theme::graphs(),
            pitch,
            dot: (pitch * 2.0 / 3.0).max(1.0 / ppp),
            quads: 0,
        }
    }

    fn quad(&mut self, rect: Rect, top: Color32, bottom: Color32) {
        let rect = rect.intersect(self.clip);
        if rect.width() <= 0.0 || rect.height() <= 0.0 {
            return;
        }
        self.mesh.add_colored_rect(rect, top);
        if top != bottom {
            let n = self.mesh.vertices.len();
            self.mesh.vertices[n - 2].color = bottom;
            self.mesh.vertices[n - 1].color = bottom;
        }
        self.quads += 1;
    }

    fn shade(&self, color: Color32, t: f32) -> Color32 {
        if self.look.fade {
            lerp(
                lerp(theme::graph_bg(), color, 0.28),
                color,
                t.clamp(0.0, 1.0),
            )
        } else {
            color
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// A vertical bar in the column `x..x+w`, growing `h` points from
    /// `base` (up or down) within an `extent`-point track.
    pub fn vbar(
        &mut self,
        x: f32,
        w: f32,
        base: f32,
        extent: f32,
        h: f32,
        color: Color32,
        up: bool,
    ) {
        let h = h.clamp(0.0, extent);
        if !self.look.btop {
            if h <= 0.0 {
                return;
            }
            let (y0, y1) = if up {
                (base - h, base)
            } else {
                (base, base + h)
            };
            let far = self.shade(color, h / extent.max(1.0));
            let near = self.shade(color, 0.0);
            let (top, bottom) = if up { (far, near) } else { (near, far) };
            self.quad(
                Rect::from_min_max(pos2(x, y0), pos2(x + w, y1)),
                top,
                bottom,
            );
            return;
        }
        let rows = (extent / self.pitch).floor().max(1.0) as usize;
        let cols = ((w + self.pitch - self.dot) / self.pitch).floor().max(1.0) as usize;
        let lit = if h > 0.0 {
            ((h / self.pitch).ceil() as usize).clamp(1, rows)
        } else {
            0
        };
        let ghost = lerp(theme::graph_bg(), color, 0.10);
        for r in 0..rows {
            let on = r < lit;
            if !on && self.quads >= CAPACITY_QUADS {
                break;
            }
            let offset = r as f32 * self.pitch;
            let y = if up {
                base - offset - self.dot
            } else {
                base + offset
            };
            let c = if on {
                self.shade(color, (r + 1) as f32 / rows as f32)
            } else {
                ghost
            };
            for k in 0..cols {
                let cx = x + k as f32 * self.pitch;
                self.quad(
                    Rect::from_min_size(pos2(cx, y), vec2(self.dot, self.dot)),
                    c,
                    c,
                );
            }
        }
    }

    /// A horizontal share bar filling `fraction` of `track` from the left.
    pub fn hbar(&mut self, track: Rect, fraction: f32, color: Color32) {
        let fraction = fraction.clamp(0.0, 1.0);
        if !self.look.btop {
            if fraction > 0.0 {
                let right = track.left() + (track.width() * fraction).max(2.0);
                let near = self.shade(color, 0.0);
                let far = self.shade(color, fraction);
                let rect = Rect::from_min_max(track.min, pos2(right, track.bottom()));
                // Horizontal fade: left vertices dim, right vertices full.
                let rect = rect.intersect(self.clip);
                if rect.width() > 0.0 {
                    self.mesh.add_colored_rect(rect, near);
                    let n = self.mesh.vertices.len();
                    // add_colored_rect order: min, (max.x,min.y), (min.x,max.y), max
                    self.mesh.vertices[n - 3].color = far;
                    self.mesh.vertices[n - 1].color = far;
                    self.quads += 1;
                }
            }
            return;
        }
        let cols = (track.width() / self.pitch).floor().max(1.0) as usize;
        let rows = ((track.height() + self.pitch - self.dot) / self.pitch)
            .floor()
            .max(1.0) as usize;
        let lit = ((fraction * cols as f32).ceil() as usize).min(cols);
        let ghost = lerp(theme::graph_bg(), color, 0.10);
        for k in 0..cols {
            let on = k < lit;
            let c = if on {
                self.shade(color, (k + 1) as f32 / cols as f32)
            } else {
                ghost
            };
            for r in 0..rows {
                let y = track.top() + r as f32 * self.pitch;
                self.quad(
                    Rect::from_min_size(
                        pos2(track.left() + k as f32 * self.pitch, y),
                        vec2(self.dot, self.dot),
                    ),
                    c,
                    c,
                );
            }
        }
    }

    /// A missing sample: a baseline tick, never a bar.
    pub fn gap(&mut self, x: f32, w: f32, base: f32) {
        let c = theme::border();
        self.quad(
            Rect::from_min_max(pos2(x, base - 1.0), pos2(x + w, base)),
            c,
            c,
        );
    }

    pub fn finish(self, ui: &Ui) {
        if !self.mesh.is_empty() {
            ui.painter()
                .with_clip_rect(self.clip)
                .add(egui::Shape::mesh(self.mesh));
        }
    }
}

/// Bar sparkline (16–20 bars): each value against `max`, full-strength
/// colour from `color(value)`. Missing samples leave a gap.
pub fn paint_sparkbars(
    ui: &Ui,
    rect: Rect,
    values: &[Option<f64>],
    max: f64,
    color: impl Fn(f64) -> Color32,
) {
    if values.is_empty() {
        return;
    }
    let n = values.len();
    let gap = 1.0;
    let w = ((rect.width() - gap * (n - 1) as f32) / n as f32).max(1.0);
    let max = if max > 0.0 {
        max
    } else {
        values
            .iter()
            .flatten()
            .fold(0.0_f64, |a, b| a.max(*b))
            .max(1e-9)
    };
    let mut bars = Bars::new(ui, rect);
    for (i, v) in values.iter().enumerate() {
        let x = rect.left() + i as f32 * (w + gap);
        match v {
            Some(v) => {
                let h = ((v / max).clamp(0.0, 1.0) as f32 * rect.height()).max(1.5);
                bars.vbar(x, w, rect.bottom(), rect.height(), h, color(*v), true);
            }
            None => bars.gap(x, w, rect.bottom()),
        }
    }
    bars.finish(ui);
}

/// The last `n` samples of `values`, left-padded with gaps.
pub fn last_n<T: Copy>(values: impl DoubleEndedIterator<Item = T>, n: usize) -> Vec<Option<T>> {
    let mut tail: Vec<Option<T>> = values.rev().take(n).map(Some).collect();
    tail.resize(n, None);
    tail.reverse();
    tail
}

/// Mirrored bars: rx up, tx down, in the app-wide graph look.
pub fn paint_mirrored_bars(
    ui: &Ui,
    rect: Rect,
    rx: &[Option<f64>],
    tx: &[Option<f64>],
    ceiling: f64,
) {
    let n = rx.len().max(tx.len());
    if n == 0 {
        return;
    }
    let mid = rect.center().y;
    let gap = 1.0;
    let w = ((rect.width() - gap * (n - 1) as f32) / n as f32).max(1.0);
    ui.painter().with_clip_rect(rect).hline(
        rect.x_range(),
        mid,
        Stroke::new(1.0_f32, theme::border()),
    );
    let half = rect.height() / 2.0 - 1.0;
    let mut bars = Bars::new(ui, rect);
    for i in 0..n {
        let x = rect.left() + i as f32 * (w + gap);
        for (values, up) in [(rx, true), (tx, false)] {
            let Some(Some(v)) = values.get(i) else {
                continue;
            };
            let h = ((v / ceiling.max(1e-9)).clamp(0.0, 1.0) as f32 * half).max(1.0);
            let (color, base) = if up {
                (theme::rx(), mid - 1.0)
            } else {
                (theme::tx(), mid + 1.0)
            };
            bars.vbar(x, w, base, half, h, color, up);
        }
    }
    bars.finish(ui);
}

/// Which axis labels to draw. `spans` are their extents along the axis,
/// most important first; each is kept unless it would come within `gap` of
/// one already kept.
pub fn thin_labels(spans: &[(f32, f32)], gap: f32) -> Vec<bool> {
    let mut kept: Vec<(f32, f32)> = Vec::new();
    spans
        .iter()
        .map(|&(start, end)| {
            let clear = kept
                .iter()
                .all(|&(a, b)| start >= b + gap || end + gap <= a);
            if clear {
                kept.push((start, end));
            }
            clear
        })
        .collect()
}

/// A labelled time axis beneath a plot: ≥3 stops plus `now`.
pub fn time_axis(ui: &mut Ui, rect_x: egui::Rangef, labels: &[String]) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 14.0), Sense::hover());
    let n = labels.len().max(2);
    for (i, label) in labels.iter().enumerate() {
        let f = i as f32 / (n - 1) as f32;
        let x = rect_x.min + (rect_x.max - rect_x.min) * f;
        let align = if i == 0 {
            Align2::LEFT_CENTER
        } else if i == n - 1 {
            Align2::RIGHT_CENTER
        } else {
            Align2::CENTER_CENTER
        };
        ui.painter().text(
            pos2(x, rect.center().y),
            align,
            label,
            FontId::monospace(theme::META),
            theme::muted(),
        );
    }
}

// ---------------------------------------------------------------- sheets

/// A sheet over the current screen: 62% scrim, panel ground, accent border,
/// 8px radius, drop shadow. Returns the body's result and whether the scrim
/// was clicked.
pub fn sheet<R>(
    ctx: &egui::Context,
    id: &str,
    width: f32,
    top: Option<f32>,
    body: impl FnOnce(&mut Ui) -> R,
) -> (R, bool) {
    let screen = ctx.screen_rect();
    let scrim_clicked = egui::Area::new(egui::Id::new((id, "scrim")))
        .order(egui::Order::Middle)
        .fixed_pos(screen.min)
        .interactable(true)
        .show(ctx, |ui| {
            let (rect, response) = ui.allocate_exact_size(screen.size(), Sense::click());
            ui.painter()
                .rect_filled(rect, 0.0, Color32::from_rgba_unmultiplied(3, 5, 8, 158));
            response.clicked()
        })
        .inner;
    let width = width.min(screen.width() - 40.0);
    let pos = pos2(
        screen.center().x - width / 2.0,
        top.unwrap_or(screen.top() + 60.0),
    );
    let inner = egui::Area::new(egui::Id::new(id))
        .order(egui::Order::Foreground)
        .fixed_pos(pos)
        .show(ctx, |ui| {
            egui::Frame::none()
                .fill(theme::panel())
                .stroke(Stroke::new(1.0_f32, theme::accent()))
                .rounding(Rounding::same(8.0))
                .shadow(egui::epaint::Shadow {
                    offset: vec2(0.0, 24.0),
                    blur: 60.0,
                    spread: 0.0,
                    color: Color32::from_black_alpha(128),
                })
                .show(ui, |ui| {
                    ui.set_width(width);
                    ui.set_max_height(screen.height() - pos.y - 30.0);
                    body(ui)
                })
                .inner
        })
        .inner;
    (inner, scrim_clicked)
}

// ---------------------------------------------------------------- format

/// `4m02s`, `3h12m`, `12s` — ages from timestamps.
pub fn age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else if secs < 86_400 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{:02}h", secs / 86_400, (secs % 86_400) / 3600)
    }
}

/// Compact rate for tight columns and axes: `7M`, `287K`, `–`.
pub fn short_rate(bytes_per_sec: f64) -> String {
    if !bytes_per_sec.is_finite() || bytes_per_sec <= 0.0 {
        "–".into()
    } else if bytes_per_sec >= 1e9 {
        format!("{:.1}G", bytes_per_sec / 1e9)
    } else if bytes_per_sec >= 1e6 {
        format!("{:.0}M", bytes_per_sec / 1e6)
    } else if bytes_per_sec >= 1e3 {
        format!("{:.0}K", bytes_per_sec / 1e3)
    } else {
        format!("{bytes_per_sec:.0}")
    }
}

/// Rate that renders a true zero as muted `–`, per spec ("0 B is muted").
pub fn rate_cell(rate: Option<f64>, series: Color32) -> Cell {
    match rate {
        Some(r) if r > 0.0 => Cell::Text(crate::format::rate(r), series),
        _ => Cell::Text("–".into(), theme::muted()),
    }
}

#[cfg(test)]
mod bar_tests {
    use super::*;
    fn quads(look: theme::GraphLook, h: f32) -> (usize, Vec<Color32>) {
        theme::set_graphs(look);
        let ctx = egui::Context::default();
        let mut out = (0, vec![]);
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let clip = Rect::from_min_size(pos2(0.0, 0.0), vec2(30.0, 30.0));
                let mut bars = Bars::new(ui, clip);
                bars.vbar(0.0, 5.0, 30.0, 30.0, h, theme::rx(), true);
                out = (
                    bars.quads,
                    bars.mesh.vertices.iter().map(|v| v.color).collect(),
                );
            });
        });
        theme::set_graphs(theme::GraphLook {
            btop: true,
            fade: true,
        });
        out
    }
    #[test]
    fn btop_draws_dot_cells_with_capacity_and_bars_draw_one_solid_quad() {
        let (btop, _) = quads(
            theme::GraphLook {
                btop: true,
                fade: true,
            },
            15.0,
        );
        // 10 rows × 2 dot columns of capacity, every cell a quad.
        assert_eq!(btop, 20);
        let (bars, colors) = quads(
            theme::GraphLook {
                btop: false,
                fade: true,
            },
            15.0,
        );
        assert_eq!(bars, 1);
        assert_ne!(colors[0], colors[3], "fade runs baseline → top");
        let (_, flat) = quads(
            theme::GraphLook {
                btop: false,
                fade: false,
            },
            15.0,
        );
        assert!(flat.iter().all(|c| *c == theme::rx()));
        let (empty, _) = quads(
            theme::GraphLook {
                btop: false,
                fade: true,
            },
            0.0,
        );
        assert_eq!(empty, 0, "no bar for a zero in bars mode");
    }
    #[test]
    fn config_names_map_to_the_graph_look() {
        assert!(theme::GraphLook::from_config("dots", true).btop);
        assert!(!theme::GraphLook::from_config("bars", false).btop);
        assert_eq!(
            theme::GraphLook::from_config("bars", false).style_name(),
            "bars"
        );
    }
}

#[cfg(test)]
mod fit_tests {
    use super::*;

    /// Runs `body` in a `width`×300 pt panel; returns every painted text
    /// with its glyph extent and clip rect.
    fn texts(
        ctx: &egui::Context,
        width: f32,
        events: Vec<egui::Event>,
        time: f64,
        body: impl FnOnce(&mut Ui),
    ) -> Vec<(String, Rect, Rect)> {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(width, 300.0))),
            time: Some(time),
            events,
            ..Default::default()
        };
        let out = ctx.run(input, |ctx| {
            egui::CentralPanel::default().show(ctx, body);
        });
        let mut found = Vec::new();
        for clipped in &out.shapes {
            if let egui::Shape::Text(t) = &clipped.shape {
                let rows = t
                    .galley
                    .rows
                    .iter()
                    .fold(Rect::NOTHING, |a, r| a.union(r.rect));
                found.push((
                    t.galley.text().to_string(),
                    rows.translate(t.pos.to_vec2()),
                    clipped.clip_rect,
                ));
            }
        }
        found
    }

    #[test]
    fn panel_header_extras_stop_at_the_title() {
        let ctx = egui::Context::default();
        crate::theme::install_fonts(&ctx);
        let found = texts(&ctx, 260.0, vec![], 0.0, |ui| {
            panel_with(
                ui,
                PanelHead::new("throughput").meta("rx peak 86M mean 50M"),
                |ui| {
                    ui.label("a key hint far too wide for this header");
                },
                |_| {},
            );
        });
        let title = found.iter().find(|(t, _, _)| t == "throughput").unwrap();
        assert!(title.2.contains_rect(title.1), "the title stays whole");
        for (text, rect, clip) in &found {
            if text != "throughput" {
                let shown = rect.intersect(*clip);
                assert!(
                    !shown.intersects(title.1.shrink(1.0)),
                    "{text:?} drawn over the title"
                );
            }
        }
    }

    #[test]
    fn axis_labels_give_way_in_priority_order() {
        // Ceiling at 0, baseline at 100, a halfway mark crowding the
        // ceiling: the mark goes, the others stay.
        let spans = [(0.0, 12.0), (100.0, 112.0), (14.0, 26.0)];
        assert_eq!(thin_labels(&spans, 6.0), [true, true, false]);
        // With room for it, it stays.
        let spans = [(0.0, 12.0), (100.0, 112.0), (50.0, 62.0)];
        assert_eq!(thin_labels(&spans, 6.0), [true, true, true]);
        // Only what clears every kept label: the third overlaps nothing
        // kept once the second has given way.
        let spans = [(0.0, 10.0), (8.0, 20.0), (18.0, 30.0)];
        assert_eq!(thin_labels(&spans, 2.0), [true, false, true]);
    }

    #[test]
    fn control_strip_options_wrap_instead_of_running_under_its_keys() {
        let ctx = egui::Context::default();
        crate::theme::install_fonts(&ctx);
        let groups = [
            StripGroup {
                label: "show",
                options: ["concern", "all", "established", "listen", "time-wait"]
                    .map(|o| (o.to_string(), Some(3)))
                    .to_vec(),
                active: 1,
            },
            StripGroup {
                label: "group",
                options: ["none", "host", "process"]
                    .map(|o| (o.to_string(), None))
                    .to_vec(),
                active: 2,
            },
        ];
        let keys = [Hint::ch('s', "sort"), Hint::ch('/', "filter")];
        let mut height = 0.0;
        let mut lines = Vec::new();
        let found = texts(&ctx, 420.0, vec![], 0.0, |ui| {
            lines = strip_lines(
                ui,
                &groups,
                ui.available_width() - 120.0,
                ui.available_width(),
            );
            let top = ui.cursor().top();
            control_strip(ui, &groups, &keys);
            height = ui.cursor().top() - top;
        });
        assert!(lines.len() > 1, "{lines:?}");
        assert!(height > theme::STRIP_HEIGHT, "the strip grows to {height}");
        // A label never ends a line without its first option.
        for line in &lines {
            if let Some((g, None)) = line.last() {
                panic!("group {g}'s label ends a line: {lines:?}");
            }
        }
        let visible: Vec<_> = found
            .iter()
            .filter(|(_, rect, clip)| clip.contains_rect(*rect))
            .collect();
        for option in ["concern 3", "time-wait 3", "process", "s", "/"] {
            assert!(
                visible.iter().any(|(t, _, _)| t.starts_with(option)),
                "{option} not whole on screen"
            );
        }
        for (i, (a, ra, _)) in visible.iter().enumerate() {
            for (b, rb, _) in &visible[i + 1..] {
                let hit = ra.intersect(*rb);
                assert!(
                    !(hit.width() > 1.0 && hit.height() > 1.0),
                    "{a:?} over {b:?}"
                );
            }
        }
    }

    #[test]
    fn a_strip_splits_a_group_only_when_no_line_could_hold_it() {
        let ctx = egui::Context::default();
        crate::theme::install_fonts(&ctx);
        let group = |label, options: &[&str]| StripGroup {
            label,
            options: options.iter().map(|o| (o.to_string(), None)).collect(),
            active: 0,
        };
        let groups = [
            group("show", &["concern 1", "all 3", "established 3", "listen 0"]),
            group("group", &["none", "host", "process"]),
            group("window", &["1m", "5m", "15m", "30m", "1h"]),
        ];
        let mut split = Vec::new();
        texts(&ctx, 800.0, vec![], 0.0, |ui| {
            for width in (200..=800).step_by(4).map(|w| w as f32) {
                let lines = strip_lines(ui, &groups, width - 160.0, width);
                for (g, group) in groups.iter().enumerate() {
                    let on = lines
                        .iter()
                        .filter(|line| line.iter().any(|(i, _)| *i == g))
                        .count();
                    let alone = strip_lines(ui, std::slice::from_ref(group), width, width);
                    if on > 1 && alone.len() == 1 {
                        split.push(format!("{} at {width}: {lines:?}", group.label));
                    }
                }
            }
        });
        assert!(split.is_empty(), "split though a line holds it: {split:#?}");
    }

    #[test]
    fn a_table_narrower_than_its_columns_scrolls_sideways() {
        let ctx = egui::Context::default();
        crate::theme::install_fonts(&ctx);
        let columns = [
            Column::flex("name", 1.0, 120.0),
            Column::px("middle", 160.0),
            Column::px("last", 140.0),
        ];
        assert_eq!(
            min_width(&columns),
            120.0 + 160.0 + 140.0 + 2.0 * COLUMN_GAP
        );
        let table = |ui: &mut Ui| {
            Table::new("wide", &columns, 3).show(ui, |_, c| Cell::text(format!("c{c}")), |_| None);
        };
        let last = |found: &[(String, Rect, Rect)]| {
            found
                .iter()
                .find(|(t, _, _)| t == "last")
                .map(|(_, rect, clip)| clip.contains_rect(*rect))
        };
        let mut time = 0.0;
        let mut found = Vec::new();
        for _ in 0..2 {
            time += 0.1;
            found = texts(&ctx, 300.0, vec![], time, table);
        }
        assert_eq!(
            last(&found),
            Some(false),
            "the last column starts out of view"
        );
        let over = egui::Event::PointerMoved(pos2(150.0, 60.0));
        let wheel = egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: vec2(-400.0, 0.0),
            modifiers: Default::default(),
        };
        texts(&ctx, 300.0, vec![over, wheel], time + 0.1, table);
        for step in 2..20 {
            found = texts(&ctx, 300.0, vec![], time + step as f64 * 0.1, table);
        }
        assert_eq!(last(&found), Some(true), "and scrolls into it");
        // Wide enough, nothing scrolls and every column fits.
        let found = texts(&egui::Context::default(), 600.0, vec![], 0.0, table);
        assert_eq!(last(&found), Some(true));
    }
}
