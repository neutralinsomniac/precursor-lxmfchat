// Host-side replay of the IME input-box grow + tail-window algorithm
// (ime-frontend/src/main.rs) against the real typesetter, to diagnose the
// "grows by an extra line / blank line under the caret" symptom.
use blitstr2::GlyphStyle;
use ux_api::minigfx::Point;
use ux_api::wordwrap::{OverflowStrategy, Typesetter};

const STYLE: GlyphStyle = GlyphStyle::Tall; // gam::SYSTEM_STYLE
const LINE_H: isize = 19; // glyph_height_hint(Tall)
const MARGIN: isize = 4;
const SCREEN_W: isize = 336;

fn typeset(text: &str, h: isize, insertion: usize) -> (isize, usize, bool, isize) {
    // returns (cursor_y, line_height, overflow, extent_h)
    // ic_bounds.y (normalized br of an inclusive rect) = h - 1; IME bb = (0,1)..ic_bounds;
    // renderer extent = bb height - 2*margin = ((h-1) - 1) - 8
    let extent = Point::new(SCREEN_W - 2 * MARGIN, (h - 2) - 2 * MARGIN);
    let mut ts = Typesetter::setup(text, &extent, &STYLE, Some(insertion));
    let comp = ts.typeset(OverflowStrategy::Abort);
    let c = comp.final_cursor();
    (c.pt.y, c.line_height, comp.final_overflow(), extent.y)
}

#[test]
fn simulate_input_box_growth() {
    let min_input_height = LINE_H + MARGIN * 2; // chat layout floor (27)
    let mut h: isize = min_input_height;
    let mut last_height: u32 = 0;
    let text = "hello world this is a longer message that wraps across several lines on the precursor screen for testing growth and it keeps going on and on with more words so that the box has to grow several more times before we are done typing it all out completely";
    let mut line = String::new();

    for ch in text.chars() {
        line.push(ch);
        let nchars = line.chars().count();
        let (mut cy, mut clh, mut overflow, _) = typeset(&line, h, nchars);
        let mut shown = String::from("(full)");
        if (clh == 0 || overflow) && nchars > 0 {
            // new algorithm: precise needed-height computation
            let lh = if clh > 0 {
                clh as isize
            } else if last_height > 0 {
                last_height as isize
            } else {
                29
            };
            let needed = cy + 2 * lh + 1 + 2 * MARGIN + 2;
            if needed > h {
                let old = h;
                h = needed;
                let (cy2, clh2, ov2, _) = typeset(&line, h, nchars);
                cy = cy2;
                clh = clh2;
                overflow = ov2;
                shown = format!("(grew {} -> {})", old, h);
            }
        } else {
            last_height = clh as u32;
        }
        // tail-window path
        if overflow && nchars > 0 {
            let chars: Vec<char> = line.chars().collect();
            let mut start = 0usize;
            for _ in 0..16 {
                start += ((chars.len() - start) / 4).max(8).min(chars.len() - start);
                if start >= chars.len() {
                    break;
                }
                let tail: String = chars[start..].iter().collect();
                let probe = format!("…{}", tail);
                let (_, _, ov, _) = typeset(&probe, h, probe.chars().count());
                if !ov {
                    break;
                }
            }
            if start < chars.len() {
                let tail: String = chars[start..].iter().collect();
                let disp = format!("…{}", tail);
                let ins = chars.len() - start + 1;
                let (cy3, clh3, ov3, _) = typeset(&disp, h, ins);
                cy = cy3;
                clh = clh3;
                overflow = ov3;
                shown = format!("(tail -{})", start);
            }
        }
        // box geometry: text area spans y=margin..h-1-margin inside the canvas
        let extent_h = (h - 1) - 2 * MARGIN;
        let caret_line = cy / LINE_H + 1;
        let box_lines = (extent_h + LINE_H - 1) / LINE_H; // how many line-slots are visible
        let gap_below = extent_h - (cy + clh as isize);
        if shown.starts_with("(grew") {
            // a grow must land the caret on the last line of the box: no
            // residual overflow (the old undershoot) and no blank line below
            // the caret (the old overshoot on the retry)
            assert!(!overflow, "box still overflows right after growing");
            assert!(
                (0..LINE_H).contains(&gap_below),
                "grow left {}px below the caret line (a whole blank line is {}px)",
                gap_below,
                LINE_H
            );
        }
        println!(
            "chars={:3} h={} box_lines~{} caret_line={} gap_below_caret={} {} {}",
            nchars,
            h,
            box_lines,
            caret_line,
            gap_below,
            if overflow { "OVF" } else { "   " },
            shown,
        );
    }
}
