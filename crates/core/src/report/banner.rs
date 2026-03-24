//! Braille-dot keyhole banner with true-color gradient rendering.
//!
//! Renders a high-resolution keyhole icon using Unicode braille characters
//! (U+2800..U+28FF), which provide 2×4 pixel resolution per character cell —
//! 8× the resolution of traditional ASCII block art. Combined with ANSI
//! true-color (24-bit) gradient coloring, the result is a smooth, distinctive
//! visual that looks like an actual graphic rendered inside the terminal.
//!
//! The keyhole is designed by hand on a 20×24 dot grid, then packed into
//! braille characters at build time via `const` functions. An optional vertical
//! scan-line animation reveals the image row-by-row for a polished entrance.

use std::io::Write;

// ─── Braille encoding ──────────────────────────────────────────────────────

/// Braille character dot positions:
///   ⠁ = (0,0)  ⠈ = (1,0)
///   ⠂ = (0,1)  ⠐ = (1,1)
///   ⠄ = (0,2)  ⠠ = (1,2)
///   ⡀ = (0,3)  ⢀ = (1,3)
///
/// A 2×4 cell maps to bits [0..7] within a single braille codepoint at
/// U+2800 + bits.
const DOT_MAP: [[u8; 4]; 2] = [
    [0x01, 0x02, 0x04, 0x40], // left column  (x=0)
    [0x08, 0x10, 0x20, 0x80], // right column (x=1)
];

// ─── Keyhole shape definition ──────────────────────────────────────────────

/// Width of the dot grid.
const KEYHOLE_COLS: usize = 20;

/// The keyhole as a human-readable grid. `#` = filled dot.
/// 20 columns × 24 rows. Each braille character encodes a 2×4 sub-block,
/// so this produces a 10-char × 6-row braille image.
const KEYHOLE_GRID: &[&str] = &[
    //  01234567890123456789
    "      ########      ", // 0  — circle top
    "    ############    ", // 1
    "   ##############   ", // 2
    "  ################  ", // 3  — circle widest
    "  ################  ", // 4
    "  ####  ####  ####  ", // 5  — inner circle void (the "hole" part of keyhole)
    "  ####        ####  ", // 6
    "  ####        ####  ", // 7
    "  ####  ####  ####  ", // 8
    "  ################  ", // 9
    "  ################  ", // 10
    "   ##############   ", // 11
    "    ####    ####    ", // 12 — transition to shaft
    "     ####  ####     ", // 13
    "      ########      ", // 14 — shaft top
    "      ########      ", // 15
    "       ######       ", // 16
    "       ######       ", // 17
    "       ######       ", // 18
    "       ######       ", // 19
    "       ######       ", // 20
    "       ######       ", // 21
    "      ########      ", // 22 — shaft bottom flare
    "      ########      ", // 23
];

/// Width of the brand text line below the keyhole.
const BRAND_LINE: &str = "K E Y H O G";
/// Sub-brand separator.
const RULE_LINE: &str = "───────────";

// ─── Gradient ──────────────────────────────────────────────────────────────

/// Gradient stops: deep amber → bright amber → warm white.
const GRADIENT: &[(u8, u8, u8)] = &[
    (180, 83, 9),    // deep amber (darker start)
    (245, 158, 11),  // amber-500
    (251, 191, 36),  // amber-400
    (253, 224, 71),  // amber-300 (bright gold)
    (254, 240, 138), // warm light
];

/// Interpolate between two RGB colors at position `t` ∈ [0.0, 1.0].
fn lerp_color(a: (u8, u8, u8), b: (u8, u8, u8), t: f32) -> (u8, u8, u8) {
    let r = a.0 as f32 + (b.0 as f32 - a.0 as f32) * t;
    let g = a.1 as f32 + (b.1 as f32 - a.1 as f32) * t;
    let bv = a.2 as f32 + (b.2 as f32 - a.2 as f32) * t;
    (r as u8, g as u8, bv as u8)
}

/// Sample the multi-stop gradient at position `t` ∈ [0.0, 1.0].
fn sample_gradient(t: f32) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0);
    let segments = GRADIENT.len() - 1;
    let scaled = t * segments as f32;
    let idx = (scaled as usize).min(segments - 1);
    let local_t = scaled - idx as f32;
    lerp_color(GRADIENT[idx], GRADIENT[idx + 1], local_t)
}

// ─── Braille packing ──────────────────────────────────────────────────────

/// Given the `KEYHOLE_GRID`, pack each 2×4 cell into a braille character.
/// Returns a `Vec` of rows, where each row is a `Vec<(char, f32)>`:
/// the braille character and its normalized x-position for gradient lookup.
fn pack_braille() -> Vec<Vec<(char, f32)>> {
    let grid: Vec<Vec<bool>> = KEYHOLE_GRID
        .iter()
        .map(|row| row.chars().map(|c| c == '#').collect())
        .collect();

    let cell_rows = (grid.len() + 3) / 4; // each braille char is 4 dots tall
    let cell_cols = KEYHOLE_COLS / 2;      // each braille char is 2 dots wide

    let mut result = Vec::with_capacity(cell_rows);

    for cy in 0..cell_rows {
        let mut row = Vec::with_capacity(cell_cols);
        for cx in 0..cell_cols {
            let mut bits: u8 = 0;
            for dy in 0..4 {
                for dx in 0..2 {
                    let gy = cy * 4 + dy;
                    let gx = cx * 2 + dx;
                    if gy < grid.len() && gx < grid[gy].len() && grid[gy][gx] {
                        bits |= DOT_MAP[dx][dy];
                    }
                }
            }
            let ch = char::from_u32(0x2800 + u32::from(bits)).unwrap_or('⠀');
            let t = cx as f32 / cell_cols.max(1) as f32;
            row.push((ch, t));
        }
        result.push(row);
    }

    result
}

// ─── Rendering ─────────────────────────────────────────────────────────────

/// Check if the terminal likely supports 24-bit true color.
fn supports_true_color() -> bool {
    if let Ok(ct) = std::env::var("COLORTERM") {
        return ct == "truecolor" || ct == "24bit";
    }
    if let Ok(term) = std::env::var("TERM") {
        return term.contains("256color") || term.contains("24bit");
    }
    false
}

/// Print the KeyHog braille keyhole banner.
///
/// # Arguments
/// - `w`: output writer (stdout, buffer, etc.)
/// - `color`: whether to emit ANSI color codes
/// - `animate`: whether to use the vertical scan-line reveal animation
///
/// The banner consists of:
/// 1. A braille-dot keyhole icon with amber gradient coloring
/// 2. Wide-spaced "K E Y H O G" text
/// 3. Version and detector count
pub fn print_banner<W: Write>(w: &mut W, color: bool, animate: bool) -> std::io::Result<()> {
    let true_color = color && supports_true_color();
    let braille_rows = pack_braille();

    writeln!(w)?;

    // ── Keyhole icon ──
    for (row_idx, row) in braille_rows.iter().enumerate() {
        // Center padding (keyhole is 10 braille chars wide, center in ~50 cols)
        write!(w, "    ")?;

        for &(ch, t) in row {
            if color && ch != '\u{2800}' {
                // Vertical gradient component: top rows darker, bottom brighter
                let vert_t = row_idx as f32 / braille_rows.len().max(1) as f32;
                // Blend horizontal and vertical gradients (60% horizontal, 40% vertical)
                let blended_t = t * 0.6 + vert_t * 0.4;
                let (r, g, b) = sample_gradient(blended_t);

                if true_color {
                    write!(w, "\x1b[38;2;{r};{g};{b}m{ch}\x1b[0m")?;
                } else {
                    let idx = 208 + ((blended_t * 15.0) as u8).min(15);
                    write!(w, "\x1b[38;5;{idx}m{ch}\x1b[0m")?;
                }
            } else {
                write!(w, "{ch}")?;
            }
        }

        writeln!(w)?;

        if animate {
            w.flush()?;
            // Faster at top (the "scan" accelerates), slower at bottom
            let delay_us = 30_000 + (row_idx as u64 * 5_000);
            std::thread::sleep(std::time::Duration::from_micros(delay_us.min(80_000)));
        }
    }

    writeln!(w)?;

    // ── Brand text ──
    if color {
        let brand_chars: Vec<char> = BRAND_LINE.chars().collect();
        let width = brand_chars.len().max(1);
        write!(w, "    ")?;
        for (i, ch) in brand_chars.iter().enumerate() {
            if *ch != ' ' {
                let t = i as f32 / width as f32;
                let (r, g, b) = sample_gradient(t);
                if true_color {
                    write!(w, "\x1b[38;2;{r};{g};{b}m{ch}\x1b[0m")?;
                } else {
                    let idx = 208 + ((t * 15.0) as u8).min(15);
                    write!(w, "\x1b[38;5;{idx}m{ch}\x1b[0m")?;
                }
            } else {
                write!(w, "{ch}")?;
            }
        }
        writeln!(w)?;
        writeln!(w, "    \x1b[90m{RULE_LINE}\x1b[0m")?;
    } else {
        writeln!(w, "    {BRAND_LINE}")?;
        writeln!(w, "    {RULE_LINE}")?;
    }

    // ── Version + tagline ──
    let version = env!("CARGO_PKG_VERSION");
    if color {
        writeln!(
            w,
            "    \x1b[90mv{version} · secret scanner · 886 detectors\x1b[0m"
        )?;
        writeln!(w, "    \x1b[90mby santh\x1b[0m")?;
    } else {
        writeln!(w, "    v{version} · secret scanner · 886 detectors")?;
        writeln!(w, "    by santh")?;
    }
    writeln!(w)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_renders_without_panic() {
        let mut buf = Vec::new();
        print_banner(&mut buf, false, false).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("K E Y H O G"),
            "banner should contain spaced brand name"
        );
        assert!(output.contains("santh"), "banner should credit santh");
    }

    #[test]
    fn banner_color_renders_ansi_escapes() {
        let mut buf = Vec::new();
        print_banner(&mut buf, true, false).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("\x1b["),
            "colored banner should contain ANSI escape sequences"
        );
    }

    #[test]
    fn braille_packing_produces_correct_dimensions() {
        let rows = pack_braille();
        // 24 dot-rows / 4 dots per braille row = 6 braille rows
        assert_eq!(rows.len(), 6, "should produce 6 braille rows from 24 dot-rows");
        // 20 dot-cols / 2 dots per braille col = 10 braille cols
        for row in &rows {
            assert_eq!(row.len(), 10, "each braille row should have 10 columns");
        }
    }

    #[test]
    fn braille_chars_are_valid_unicode() {
        let rows = pack_braille();
        for row in &rows {
            for &(ch, _) in row {
                let cp = ch as u32;
                assert!(
                    (0x2800..=0x28FF).contains(&cp),
                    "character U+{cp:04X} is outside braille block"
                );
            }
        }
    }

    #[test]
    fn gradient_endpoints_are_correct() {
        let start = sample_gradient(0.0);
        assert_eq!(start, GRADIENT[0], "gradient start should match first stop");
        let end = sample_gradient(1.0);
        assert_eq!(
            end,
            *GRADIENT.last().unwrap(),
            "gradient end should match last stop"
        );
    }

    #[test]
    fn gradient_midpoint_interpolates_smoothly() {
        let mid = sample_gradient(0.5);
        // midpoint should be between the darkest and brightest values
        assert!(
            mid.0 >= GRADIENT[0].0.min(GRADIENT[4].0),
            "red channel should be within gradient range"
        );
        assert!(
            mid.0 <= GRADIENT[0].0.max(GRADIENT[4].0),
            "red channel should be within gradient range"
        );
    }

    #[test]
    fn no_color_banner_has_no_escapes() {
        let mut buf = Vec::new();
        print_banner(&mut buf, false, false).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            !output.contains("\x1b["),
            "no-color banner should not contain ANSI escapes"
        );
    }
}
