use std::cmp::min;
use std::fmt::Write as TextWrite;
use std::io::{Error, ErrorKind, Read, Write};

use blitstr2::GlyphStyle;
use dialogue::{Dialogue, post::Post};
use gam::{MenuMatic, UxRegistration, menu_matic};
use locales::t;
use modals::Modals;
use ticktimer_server::Ticktimer;
use ux_api::minigfx::*;
use ux_api::service::api::*;
use xous::{CID, MessageEnvelope};
use xous_names::XousNames;

use super::*;
//use crate::{ChatOp, Dialogue, Event, Post, CHAT_SERVER_NAME};
use crate::icontray::Icontray;

pub const BUSY_ANIMATION_RATE_MS: usize = 200;

/// Variables that define the visual properties of the layout
pub struct VisualProperties {
    pub canvas: Gid,
    pub total_screensize: Point,
    pub layout_screensize: Point,
    /// height of the status bar. This is subtracted from screensize.
    pub status_height: u16,
    pub bubble_width: u16,
    pub margin: Point,        // margin to edge of canvas
    pub bubble_margin: Point, // margin of text in bubbles
    pub bubble_radius: u16,
    pub bubble_space: isize, // spacing between text bubbles
}
#[allow(dead_code)]
pub(crate) struct Ui {
    // optional structures that indicate new input to the Chat loop per iteration
    // an input string
    pub input: Option<String>,
    // messages from other servers
    msg: Option<MessageEnvelope>,

    // Pddb connection
    pddb: pddb::Pddb,
    pddb_dict: Option<String>,
    pddb_key: Option<String>,
    dialogue: Option<Dialogue>,

    // Callbacks:
    // callback to our own server
    self_cid: CID,
    // optional SID of the "Owner" Chat App to receive UI-events
    app_cid: Option<CID>,
    // optional opcode ID to process UI-event msgs
    opcode_event: Option<usize>,

    gam: gam::Gam,
    modals: Modals,
    tt: Ticktimer,

    /// These variables are managed exclusively by the layout routine.
    /// the selected post is highlighted onscreen and the focus of the msg menu
    layout_selected: Option<usize>,
    /// the range of posts that are currently drawable. This was originally implemented as
    /// an Option<Range>, but we need to be able to do RangeInclusive and Reversed ranges.
    /// The RangeBounds trait isn't object-safe, so we can't Box/dyn it either...
    /// So, instead, we turn the ranges into a Vec and operate from there...
    layout_range: Vec<usize>,
    /// layout post bubbles on the screen from top-down or bottom-up
    layout_topdown: bool,

    /// TextView for the status bar. This encapsulates the state of the busy animation, and the text within.
    status_tv: TextView,
    /// Track the last time we update the status bar; use this avoid double-updating busy animations
    status_last_update_ms: u64,
    /// The default message to show when we exit a busy state
    status_idle_text: String,

    vp: VisualProperties,

    // variables that define a menu
    menu_mode: bool,
    app_menu: String,
    menu_mgr: MenuMatic,
    /// the F1-F4 helper-label tray (rendered by the IMEF's prediction area)
    icontray: Icontray,

    /// Document mode (e.g. the NomadNet page browser): when `document` is
    /// Some, redraws render it instead of the chat dialogue. `doc_staging`
    /// accumulates an incoming page so the current view stays up until
    /// DocumentShow swaps it in. `doc_suspended` parks the shown document when
    /// the app returns to the chat, so it can come back exactly as it was
    /// (scroll and cursor included). Chat-only apps never set any of them.
    document: Option<DocState>,
    doc_staging: Option<DocState>,
    doc_suspended: Option<DocState>,

    // our security token for making changes to our record on the GAM
    token: [u32; 4],
}

/// Hard bound on stored document lines (a parser-side cap should hit first).
const DOC_MAX_LINES: usize = 2048;
/// Vertical space taken by a divider line, total.
const DOC_DIVIDER_HEIGHT: u32 = 12;
/// Clip height used only when *measuring* a line's natural wrapped height: a
/// line must never be reported shorter than it really is just because it would
/// be clipped on screen, or the pixel scroll math drifts. Big enough that no
/// real line reaches it.
const DOC_MEASURE_CLIP: isize = 1 << 20;

pub(crate) struct DocState {
    #[allow(dead_code)]
    title: String,
    lines: Vec<DocLine>,
    /// lazily-computed line heights (same trick as Post::bounding_box). This is
    /// the line's *natural* wrapped height — independent of where it lands on
    /// screen — which is what makes pixel scrolling exact.
    heights: Vec<Option<u32>>,
    /// Pixel offset from the top of the document content to the top of the
    /// viewport. Scrolling is by pixels, not lines: a wrapped line can sit
    /// half on-screen, and stepping/paging never snap to a line boundary (the
    /// snapping is what skipped the tail of a wrapped line). Clamped to
    /// `[0, doc_max_scroll]` on every layout.
    scroll: u32,
    /// Selected link line, if any. The cursor *only* ever lands on a link line:
    /// it highlights that link and is what `Enter` activates, and link nav
    /// scrolls it into view. It does NOT drive the viewport — `scroll` alone
    /// does — so it can't make stepping jump by a whole line.
    cursor: Option<usize>,
}

#[allow(dead_code)]
impl Ui {
    pub(crate) fn new(
        sid: xous::SID,
        app_name: &'static str,
        app_menu: &'static str,
        app_cid: Option<xous::CID>,
        opcode_event: Option<usize>,
    ) -> Self {
        let xns = XousNames::new().unwrap();
        let gam = gam::Gam::new(&xns).expect("can't connect to GAM");

        let token = gam
            .register_ux(UxRegistration {
                app_name: String::from(app_name),
                ux_type: gam::UxType::Chat,
                predictor: Some(String::from(crate::icontray::SERVER_NAME_ICONTRAY)),
                listener: sid.to_array(), /* note disclosure of our SID to the GAM -- the secret is now
                                           * shared with the GAM! */
                redraw_id: ChatOp::GamRedraw as u32,
                gotinput_id: Some(ChatOp::GamLine as u32),
                audioframe_id: None,
                rawkeys_id: Some(ChatOp::GamRawkeys as u32),
                focuschange_id: Some(ChatOp::GamChangeFocus as u32),
            })
            .expect("couldn't register Ux context for chat")
            .unwrap();
        let xns = XousNames::new().unwrap();
        let modals = Modals::new(&xns).unwrap();
        let canvas = gam.request_content_canvas(token).expect("couldn't get content canvas");
        let screensize = gam.get_canvas_bounds(canvas).expect("couldn't get dimensions of content canvas");
        // The F1-F4 helper tray: blank until the app labels the keys it
        // handles (ChatOp::IcontraySet / cf_icontray_set).
        let icontray = Icontray::new(["", "", "", ""]);
        let menu_mgr = menu_matic(Vec::<MenuItem>::new(), app_menu, Some(xous::create_server().unwrap()))
            .expect("couldn't create MenuMatic manager");
        let pddb = pddb::Pddb::new();
        pddb.try_mount();

        // setup the initial status bar contents
        let margin = Point::new(4, 4);
        let status_height = gam.glyph_height_hint(GlyphStyle::Regular).unwrap() as u16;
        let mut status_tv = TextView::new(
            canvas,
            TextBounds::BoundingBox(Rectangle::new(
                Point::new(0, 0),
                Point::new(screensize.x, status_height as _),
            )),
        );
        status_tv.style = GlyphStyle::Regular;
        status_tv.margin = margin;
        status_tv.draw_border = false;
        status_tv.clear_area = true;
        status_tv.margin = Point::new(0, 0);
        write!(status_tv, "{}", t!("chat.status.initial", locales::LANG).to_string()).ok();
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        let status_last_update_ms = tt.elapsed_ms();
        let bubble_properties = VisualProperties {
            canvas,
            total_screensize: screensize,
            layout_screensize: Point::new(screensize.x, screensize.y - status_height as isize),
            status_height,
            bubble_width: ((screensize.x / 5) * 4) as u16, // 80% width for the text bubbles
            margin: Point::new(4, 4),
            bubble_margin: Point::new(4, 4),
            bubble_radius: 4,
            bubble_space: 4,
        };
        Ui {
            input: None,
            msg: None,
            pddb,
            pddb_dict: None,
            pddb_key: None,
            dialogue: None,
            self_cid: xous::connect(sid).unwrap(),
            app_cid,
            opcode_event,
            gam,
            modals,
            tt,
            status_tv,
            status_last_update_ms,
            layout_selected: None,
            layout_range: Vec::new(),
            layout_topdown: false,
            vp: bubble_properties,
            menu_mode: true,
            app_menu: app_menu.to_owned(),
            menu_mgr,
            icontray,
            document: None,
            doc_staging: None,
            doc_suspended: None,
            token,
            status_idle_text: t!("chat.status.initial", locales::LANG).to_string(),
        }
    }

    /// Read the current Dialogue from pddb
    pub fn dialogue_read(&mut self) -> Result<(), Error> {
        // Owned copies so we can delete the key on the recovery path without
        // tangling with the borrows held during the read below.
        let (dict, key) = match (self.pddb_dict.clone(), self.pddb_key.clone()) {
            (Some(d), Some(k)) => (d, k),
            _ => {
                log::warn!("missing pddb dict or key");
                return Err(Error::new(ErrorKind::InvalidData, "missing"));
            }
        };
        let mut pddb_key = match self.pddb.get(&dict, &key, None, true, false, None, None::<fn()>) {
            Ok(k) => k,
            Err(e) => {
                log::warn!("failed to get {}: {e}", key);
                return Err(Error::new(ErrorKind::InvalidData, "missing"));
            }
        };
        // Read the WHOLE value (a single `read` can return a short read, which the
        // envelope check below would then mis-flag as corrupt). Bound it so a
        // pathologically large key can't blow the heap.
        let mut buf = Vec::new();
        let cap = (dialogue::MAX_BYTES + dialogue::ENVELOPE_HEADER + 2) as u64;
        if let Err(e) = (&mut pddb_key).take(cap).read_to_end(&mut buf) {
            log::warn!("failed to read {}: {e}", key);
            return Err(Error::new(ErrorKind::InvalidData, "unreadable"));
        }
        let pos = buf.len();

        // Validate + decode (envelope, then the rkyv body — see
        // `dialogue::decode`). On an envelope failure we DON'T touch
        // `self.dialogue` or delete the key: the caller decides — `dialogue_set`
        // overwrites it with a fresh empty thread (delete-then-write), while a
        // post-save read-back simply keeps the (correct) in-memory copy it just
        // saved, so a transient read glitch can't lose data.
        self.dialogue = match dialogue::decode(&buf) {
            Err(dialogue::DecodeError::Envelope) => {
                log::warn!("Dialogue {dict}:{key} failed envelope validation ({pos} bytes)");
                return Err(Error::new(ErrorKind::InvalidData, "corrupt dialogue"));
            }
            Ok(mut dialogue) => {
                // Bubble heights are persisted with the posts, but they depend
                // on render details that can change between builds (e.g. the
                // author/time header line). Invalidate on load; the layout
                // recomputes them lazily for the posts it actually shows.
                for post in dialogue.posts_as_slice_mut() {
                    post.bounding_box = None;
                }
                // show most recent posts onscreen
                self.layout_selected = dialogue.post_last();
                self.layout_range.clear();
                self.layout_topdown = false;
                Some(dialogue)
            }
            Err(dialogue::DecodeError::Deserialize(e)) => {
                log::warn!("failed to deserialize Dialogue {}:{} {}", dict, key, e);
                None
            }
        };
        log::debug!("get '{}' = '{:?}'", key, self.dialogue);
        Ok(())
    }

    /// Save the current Dialogue to pddb
    pub fn dialogue_save(&self) -> Result<(), Error> {
        match (&self.dialogue, &self.pddb_dict, &self.pddb_key) {
            (Some(dialogue), Some(dict), Some(key)) => {
                let body = rkyv::to_bytes::<rkyv::rancor::Error>(dialogue).unwrap();
                // Frame the body so the reader can use its exact length and verify
                // it: MAGIC | len(4 BE) | crc(4 BE) | body.
                let mut val = Vec::with_capacity(dialogue::ENVELOPE_HEADER + body.len());
                val.extend_from_slice(&dialogue::ENVELOPE_MAGIC);
                val.extend_from_slice(&(body.len() as u32).to_be_bytes());
                val.extend_from_slice(&dialogue::checksum(&body).to_be_bytes());
                val.extend_from_slice(&body);
                // Delete first so the stored value length matches `val` exactly. A
                // PDDB key written with a *shorter* value keeps its old length and
                // a stale tail (write defaults to truncate=false), which would
                // corrupt the framed value on read — this is the bug that aborted
                // the app after a bubble's mark shrank (e.g. "○" 3B → "»" 2B).
                self.pddb.delete_key(&dict, &key, None).ok();
                match self.pddb.get(&dict, &key, None, true, true, Some(val.len()), None::<fn()>) {
                    // write_all (not write): a single `write` may be a short write,
                    // which would truncate the stored value and fail the reader's
                    // envelope check.
                    Ok(mut pddb_key) => match pddb_key.write_all(&val).and_then(|_| pddb_key.flush()) {
                        Ok(()) => {
                            self.pddb.sync().ok();
                            log::info!("Wrote {} bytes to {}:{}", val.len(), dict, key);
                        }
                        Err(e) => log::warn!("Error writing {}:{}: {:?}", dict, key, e),
                    },
                    Err(e) => log::warn!("failed to create {}:{}\n{}", dict, key, e),
                }
                Ok(())
            }
            _ => {
                log::warn!("missing dict, key or dialogue");
                Ok(())
            }
        }
    }

    /// Set the current Dialogue
    ///
    /// # Arguments
    ///
    /// * `pddb_dict` - the pddb dict holding all Dialogues for this Chat App
    /// * `pddb_key` - the pddb key holding a Dialogue
    pub fn dialogue_set(&mut self, pddb_dict: &str, pddb_key: Option<&str>) {
        self.pddb_dict = Some(pddb_dict.to_string());
        self.pddb_key = pddb_key.map(|key| key.to_string());
        if self.pddb_key.is_none() {
            self.dialogue_modal();
        }
        log::info!("Dialogue set to {:?}:{:?}", self.pddb_dict, self.pddb_key);
        match self.dialogue_read() {
            Ok(_) => {
                log::info!("read dialogue {:?}:{:?}", self.pddb_dict, self.pddb_key);
                self.redraw().expect("couldn't redraw screen");
            }
            Err(_) => {
                if let Some(key) = &self.pddb_key {
                    self.dialogue = Some(Dialogue::new(&key));
                    match self.dialogue_save() {
                        Ok(_) => log::info!("Dialogue created {}:{}", pddb_dict, key),
                        Err(e) => {
                            log::warn!("Failed to create Dialogue {}:{} : {e}", pddb_dict, key)
                        }
                    }
                }
            }
        }
    }

    /// Present a Modal to select Dialogue from pddb
    ///
    /// typically called in offline mode
    ///
    /// TODO move non-dialogue keys elsewhere
    pub fn dialogue_modal(&mut self) {
        if let Some(dict) = &self.pddb_dict {
            match self.pddb.list_keys(&dict, None) {
                Ok(keys) => {
                    if keys.len() > 0 {
                        self.modals
                            .add_list(keys.iter().map(|s| s.as_str()).collect())
                            .expect("failed modal add_list");
                        self.pddb_key =
                            self.modals.get_radiobutton(t!("chat.dialogue_title", locales::LANG)).ok();
                        log::info!("selected dialogue {}:{:?}", dict, self.pddb_key);
                    } else {
                        self.modals
                            .show_notification(t!("chat.dict_empty", locales::LANG), None)
                            .expect("notification failed");
                    }
                }
                Err(e) => log::warn!("failed to list pddb keys: {e}"),
            }
        }
    }

    /// Show some user help
    pub fn help(&self) {
        self.modals
            .show_notification(t!("chat.help.navigation", locales::LANG), None)
            .expect("notification failed");
    }

    /// Add a new MenuItem to the App menu
    ///
    /// # Arguments
    ///
    /// * `item` - an item action not handled by the Chat UI
    pub fn menu_add(&self, item: MenuItem) {
        self.menu_mgr.add_item(item);
    }

    /// Relabel one F1-F4 helper-tray slot and repaint the tray, so a
    /// background change (e.g. a new unread badge) shows without a keypress.
    pub fn icontray_set(&self, index: usize, label: &str) {
        self.icontray.set_slot(index, label);
        self.gam.request_ime_redraw().ok();
    }

    /// Add a new Post to the current Dialogue
    ///
    /// note: posts are sorted by timestamp, so:
    /// - `post_add` at beginning or end is fast (middle triggers a binary partition)
    /// - if adding multiple posts then add oldest/newest last!
    ///
    /// # Arguments
    ///
    /// * `author` - the name of the Author of the Post
    /// * `timestamp` - the timestamp of the Post
    /// * `text` - the text content of the Post
    /// * `attach_url` - a url of an attachment (image for example)
    pub fn post_add(
        &mut self,
        dialogue_id: &str,
        author: &str,
        timestamp: u64,
        text: &str,
        attach_url: Option<&str>,
    ) -> Result<(), Error> {
        match (&self.pddb_key, &mut self.dialogue) {
            (Some(pddb_key), Some(ref mut dialogue)) => {
                if dialogue_id.len() == 0 || pddb_key.eq(&dialogue_id) {
                    dialogue
                        .post_add(author, timestamp, text, attach_url, Some((&self.vp, &self.gam)))
                        .unwrap();
                } else {
                    log::warn!(
                        "dropping Post as dialogue_id does not match pddb_key: '{}' vs '{}'",
                        pddb_key,
                        dialogue_id
                    );
                }
            }
            (None, _) => log::warn!("no pddb_key set to match dialogue_id"),
            (_, None) => log::warn!("no Dialogue available to add Post"),
        }
        Ok(())
    }

    /// Delete a Post from the current Dialogue
    ///
    /// TODO: implement post_delete()

    pub fn post_del(&mut self, index: usize) -> Result<(), Error> {
        match &mut self.dialogue {
            Some(ref mut dialogue) => dialogue.post_del(index),
            None => Err(Error::new(ErrorKind::Other, "no dialogue to delete from")),
        }
    }

    /// Atomically replace the text of the post matching `(author, timestamp)` in
    /// the active dialogue. Returns true if found.
    pub fn post_update(&mut self, author: &str, timestamp: u64, text: &str) -> bool {
        match &mut self.dialogue {
            Some(ref mut dialogue) => {
                dialogue.post_update(author, timestamp, text, Some((&self.vp, &self.gam)))
            }
            None => false,
        }
    }

    /// Returns Some(index) of a matching Post by Author and Timestamp, or None
    ///
    /// # Arguments
    ///
    /// * `timestamp` - the Post timestamp criteria
    /// * `author` - the Post Author criteria
    pub fn post_find(&self, author: &str, timestamp: u64) -> Option<usize> {
        match &self.dialogue {
            Some(dialogue) => dialogue.post_find(author, timestamp),
            None => None,
        }
    }

    /// Return Some<Post> from the current Dialogue, or None
    ///
    /// # Arguments
    ///
    /// * `index` - index of the Post to retrieve
    pub fn post_get(&self, index: usize) -> Option<&Post> {
        match &self.dialogue {
            Some(dialogue) => dialogue.post_get(index),
            None => None,
        }
    }

    /// Set various status flags on a Post in the current Dialogue
    ///
    /// TODO: not implemented
    pub fn post_flag(&self, _key: u32) -> Result<(), Error> {
        log::warn!("not implemented");
        Err(Error::new(ErrorKind::Other, "not implemented"))
    }

    /// Set the Selected Post to an arbitrary index
    ///
    /// # Arguments
    ///
    /// * `index` - POST_SELECT_NEXT or POST_SELECT_PREV or an arbitraty index
    pub fn post_select(&mut self, index: usize) {
        self.layout_selected = match &self.dialogue {
            Some(dialogue) => {
                match dialogue.post_last() {
                    Some(last_post) => {
                        match (index, self.layout_selected) {
                            (POST_SELECTED_NEXT, Some(selected)) => {
                                if selected >= last_post {
                                    self.event(Event::Bottom);
                                    Some(last_post)
                                } else {
                                    Some(selected + 1)
                                }
                            }
                            (POST_SELECTED_PREV, Some(selected)) => {
                                if selected == 0 {
                                    self.event(Event::Top);
                                    Some(selected)
                                } else {
                                    Some(selected - 1)
                                }
                            }
                            (index, _) => Some(min(index, last_post)), // arbitrary post
                        }
                    }
                    None => None,
                }
            }
            None => None,
        }
    }

    pub fn get_menu_mode(&self) -> bool {
        self.menu_mode
    }

    pub fn set_menu_mode(&mut self, menu_mode: bool) {
        self.menu_mode = menu_mode;
    }

    /// Send a xous scalar message with an Event to the Chat App cid/opcode
    ///
    /// # Arguments
    ///
    /// * `event` - the type of event to send
    ///
    /// Error when `app_cid` == None or `opcode_event` == None
    pub fn event(&self, event: Event) {
        log::info!("Event {:?}", event);
        match (self.app_cid, self.opcode_event) {
            (Some(cid), Some(opcode)) => match xous::send_message(
                cid,
                xous::Message::new_scalar(opcode as usize, event as usize, 0, 0, 0),
            ) {
                Ok(_) => log::info!("sent event msg"),
                Err(e) => log::warn!("failed to send event msg: {:?}", e),
            },
            _ => log::warn!("missing cid or event opcode"),
        }
    }

    /// Clear the screen area, not including the status bar
    fn clear_area(&self) {
        self.gam
            .draw_rectangle(
                self.vp.canvas,
                Rectangle::new_with_style(
                    Point::new(0, self.vp.status_height as isize),
                    self.vp.total_screensize,
                    DrawStyle { fill_color: Some(PixelColor::Light), stroke_color: None, stroke_width: 0 },
                ),
            )
            .expect("can't clear canvas area");
    }

    /// Show the App Menu (← key)
    pub(crate) fn raise_app_menu(&mut self) {
        self.gam.raise_menu(&self.app_menu).expect("couldn't raise our submenu");
        log::info!("raised app menu");
    }

    /// Show the Msg Menu (→ key)
    pub(crate) fn raise_msg_menu(&mut self) {
        log::warn!("msg menu not implemented - pull-requests welcome");
    }

    /// Redraw posts on the screen.
    ///
    /// Up to three attempts are made to layout the Posts:
    /// * ensuring the selected post is fully visible, and
    /// * best use of the screen is achieved
    pub(crate) fn redraw(&mut self) -> Result<(), xous::Error> {
        // The content canvas changes size under us: the IME input box grows
        // while a long message is composed (canvas shrinks) and snaps back on
        // send, and document mode hides the input box (canvas grows). The
        // startup size cached in `vp` would anchor bottom-up bubbles below a
        // shrunken canvas — every bubble clipped away — so re-measure first.
        if let Ok(size) = self.gam.get_canvas_bounds(self.vp.canvas) {
            self.vp.total_screensize = size;
            self.vp.layout_screensize = Point::new(size.x, size.y - self.vp.status_height as isize);
        }
        if self.doc_active() {
            self.layout_document();
            self.status_last_update_ms = self.tt.elapsed_ms();
        } else if self.dialogue.is_some() {
            self.layout().expect("layout failed to execute");
            self.status_last_update_ms = self.tt.elapsed_ms();
        } else {
            self.clear_area(); // no dialogue so clear screen
        }
        log::trace!("chat app redraw##");
        self.gam.redraw().expect("couldn't redraw screen");
        Ok(())
    }

    // ------------------------- document mode -------------------------

    pub(crate) fn doc_active(&self) -> bool {
        self.document.is_some()
    }

    /// Start staging a new document. The current view (chat or a previous
    /// document) keeps rendering until `doc_show` swaps the staged one in.
    pub(crate) fn doc_begin(&mut self, title: &str) {
        self.doc_staging = Some(DocState {
            title: title.to_owned(),
            lines: Vec::new(),
            heights: Vec::new(),
            scroll: 0,
            cursor: None,
        });
    }

    pub(crate) fn doc_append(&mut self, lines: Vec<DocLine>) {
        if let Some(doc) = self.doc_staging.as_mut() {
            let room = DOC_MAX_LINES.saturating_sub(doc.lines.len());
            for line in lines.into_iter().take(room) {
                doc.lines.push(line);
                doc.heights.push(None);
            }
        }
    }

    /// Swap the staged document in and show it from the top. The IME input
    /// box is hidden while a document is up — there is nothing to type into,
    /// and it otherwise covers a line of the page. A newly shown page replaces
    /// any suspended one (the app's back stack owns history, not this slot).
    pub(crate) fn doc_show(&mut self) {
        if let Some(doc) = self.doc_staging.take() {
            let entering = self.document.is_none();
            self.document = Some(doc);
            self.doc_suspended = None;
            if entering {
                self.set_input_visible(false);
            }
        }
    }

    /// Leave document mode; the next redraw renders the chat dialogue again.
    pub(crate) fn doc_clear(&mut self) {
        if self.document.take().is_some() {
            self.set_input_visible(true);
        }
        self.doc_staging = None;
        self.doc_suspended = None;
    }

    /// Set the shown document aside and return to the chat dialogue;
    /// `doc_resume` brings it back exactly as it was (scroll + cursor).
    pub(crate) fn doc_suspend(&mut self) {
        if let Some(doc) = self.document.take() {
            self.doc_suspended = Some(doc);
            self.set_input_visible(true);
        }
        self.doc_staging = None;
    }

    /// Bring back a set-aside document. Returns false when there is none.
    pub(crate) fn doc_resume(&mut self) -> bool {
        match self.doc_suspended.take() {
            Some(doc) => {
                self.document = Some(doc);
                self.set_input_visible(false);
                true
            }
            None => false,
        }
    }

    /// Show or hide the layout's IME input box (negative height = hidden;
    /// 0 or any small positive request is clamped up to the one-line minimum
    /// — 0 can't mean "hide" because the IME requests 0 to reset its height
    /// after every send). Authorized by our app token — the GAM resizes this
    /// context's own chat layout.
    fn set_input_visible(&self, visible: bool) {
        let mut req = gam::api::SetCanvasBoundsRequest {
            token: self.token,
            token_type: gam::TokenType::App,
            requested: Point::new(0, if visible { 1 } else { -1 }),
            granted: None,
        };
        self.gam.set_canvas_bounds_request(&mut req).ok();
        // Stop keystrokes reaching the IME while the input box is hidden, so
        // document-mode keys (j/k/g/G scrolling) don't pile into the compose
        // line behind the page; resume when it comes back.
        self.gam.set_imef_suspend(self.token, !visible).ok();
        if visible {
            // Repaint the restored input line right away (it would otherwise
            // stay blank until the next keystroke).
            self.gam.request_ime_redraw().ok();
        }
    }

    /// True when document line `i` is a link line.
    fn doc_is_link(&self, i: usize) -> bool {
        self.document.as_ref().and_then(|d| d.lines.get(i)).map(|l| l.kind == DOC_KIND_LINK).unwrap_or(false)
    }

    /// Move the link selection to the previous/next LINK anywhere in the
    /// document and scroll it into view. The cursor cares only about links —
    /// never plain text — so this hops link to link regardless of how the
    /// surrounding text wraps. From no selection it starts at the top of what's
    /// on screen, so the first link picked is the one nearest the viewport.
    pub(crate) fn doc_cursor(&mut self, next: bool) {
        let total = match self.document.as_ref() {
            Some(d) if !d.lines.is_empty() => d.lines.len(),
            _ => return,
        };
        let anchor = self.doc_first_visible_line();
        let target = match self.document.as_ref().and_then(|d| d.cursor) {
            Some(c) if next => ((c + 1)..total).find(|&i| self.doc_is_link(i)),
            Some(c) => (0..c).rev().find(|&i| self.doc_is_link(i)),
            None if next => (anchor..total).find(|&i| self.doc_is_link(i)),
            None => (0..=anchor).rev().find(|&i| self.doc_is_link(i)),
        };
        if let Some(i) = target {
            if let Some(doc) = self.document.as_mut() {
                doc.cursor = Some(i);
            }
            self.doc_scroll_into_view(i);
        }
    }

    /// Page the document by one screenful. Pure pixel scroll (the same
    /// mechanism as `doc_line`, just a bigger step), so it can never skip the
    /// tail of a wrapped line: a line cut at the bottom edge reappears at the
    /// top of the next page. A one-row overlap carries the boundary line across
    /// for reading continuity.
    pub(crate) fn doc_page(&mut self, down: bool) {
        let (_, _, budget) = self.doc_metrics();
        let step = budget.saturating_sub(self.doc_row_step()).max(self.doc_row_step()) as i32;
        self.doc_scroll_by(if down { step } else { -step });
    }

    /// Step the document one display row (j/k). Pixel scroll by one glyph row,
    /// independent of logical lines — so it always moves by the same small
    /// amount, never by a whole wrapped line.
    pub(crate) fn doc_line(&mut self, down: bool) {
        let step = self.doc_row_step() as i32;
        self.doc_scroll_by(if down { step } else { -step });
    }

    /// Jump to the top (g) or bottom (G) of the document. Pure scroll; the link
    /// selection is dropped (there is no link "edge" to land on).
    pub(crate) fn doc_edge(&mut self, bottom: bool) {
        let target = if bottom { self.doc_max_scroll() } else { 0 };
        if let Some(doc) = self.document.as_mut() {
            doc.scroll = target;
            doc.cursor = None;
        }
    }

    /// One display row, in pixels: a glyph line plus the inter-line gap. The
    /// shared unit behind both line-stepping and paging.
    fn doc_row_step(&self) -> u32 {
        blitstr2::glyph_height_hint(GlyphStyle::Regular) as u32 + self.vp.bubble_space as u32
    }

    /// Apply a signed pixel delta to the scroll offset, clamped to range.
    fn doc_scroll_by(&mut self, delta: i32) {
        let max = self.doc_max_scroll() as i64;
        if let Some(doc) = self.document.as_mut() {
            doc.scroll = (doc.scroll as i64 + delta as i64).clamp(0, max) as u32;
        }
    }

    /// Document-space top (pixels) of line `idx`, summing natural heights and
    /// the inter-line gap. `idx == lines.len()` gives the total content height.
    fn doc_line_top(&mut self, idx: usize) -> u32 {
        let mut y = 0u32;
        for i in 0..idx {
            y += self.doc_line_height(i) + self.vp.bubble_space as u32;
        }
        y
    }

    /// Largest valid scroll offset: content taller than the viewport can be
    /// scrolled until its bottom meets the viewport bottom; shorter content
    /// can't scroll at all.
    fn doc_max_scroll(&mut self) -> u32 {
        let total = self.document.as_ref().map(|d| d.lines.len()).unwrap_or(0);
        let (_, _, budget) = self.doc_metrics();
        self.doc_line_top(total).saturating_sub(budget)
    }

    /// Index of the first line at least partly visible at the current scroll.
    fn doc_first_visible_line(&mut self) -> usize {
        let (scroll, total) = match self.document.as_ref() {
            Some(d) => (d.scroll, d.lines.len()),
            None => return 0,
        };
        let mut y = 0u32;
        for i in 0..total {
            y += self.doc_line_height(i) + self.vp.bubble_space as u32;
            if y > scroll {
                return i;
            }
        }
        total.saturating_sub(1)
    }

    /// Nudge the scroll so line `i` is fully on screen, moving the least amount
    /// needed (and never past the document's end).
    fn doc_scroll_into_view(&mut self, i: usize) {
        let (_, _, budget) = self.doc_metrics();
        let top = self.doc_line_top(i);
        let h = self.doc_line_height(i);
        let max = self.doc_max_scroll();
        if let Some(doc) = self.document.as_mut() {
            if top < doc.scroll {
                doc.scroll = top;
            } else if top + h > doc.scroll + budget {
                doc.scroll = (top + h).saturating_sub(budget);
            }
            doc.scroll = doc.scroll.min(max);
        }
    }

    /// The link under the cursor, if a link is selected.
    pub(crate) fn doc_selected_link(&self) -> Option<u16> {
        let doc = self.document.as_ref()?;
        let line = doc.lines.get(doc.cursor?)?;
        if line.kind == DOC_KIND_LINK { Some(line.link_id) } else { None }
    }

    /// Build the TextView for one document line at vertical position `y`.
    /// Must be constructed identically when measuring and when drawing, or
    /// the cached heights go stale (same rule as chat bubbles).
    fn doc_textview(&self, line: &DocLine, y: isize, highlight: bool, clip_bottom: isize) -> TextView {
        let width = (self.vp.layout_screensize.x - 2 * self.vp.margin.x) as u16;
        let bounds = match line.align {
            DOC_ALIGN_CENTER => TextBounds::CenteredTop(Rectangle::new(
                Point::new(self.vp.margin.x, y),
                Point::new(self.vp.layout_screensize.x - self.vp.margin.x, clip_bottom),
            )),
            DOC_ALIGN_RIGHT => TextBounds::GrowableFromTr(
                Point::new(self.vp.layout_screensize.x - self.vp.margin.x, y),
                width,
            ),
            _ => TextBounds::GrowableFromTl(Point::new(self.vp.margin.x, y), width),
        };
        let mut tv = TextView::new(self.vp.canvas, bounds);
        tv.style = match line.style {
            DOC_STYLE_BOLD => GlyphStyle::Bold,
            DOC_STYLE_MONO => GlyphStyle::Monospace,
            DOC_STYLE_LARGE => GlyphStyle::Large,
            _ => GlyphStyle::Regular,
        };
        tv.clip_rect = Some(Rectangle::new(
            Point::new(0, self.vp.status_height as isize),
            Point::new(self.vp.total_screensize.x, clip_bottom),
        ));
        // Links read as "buttons": always boxed, and fat-bordered under the
        // cursor. (True video-inverse selection isn't available here — the GAM
        // only honors TextView.invert for token-validated system canvases.)
        let is_link = line.kind == DOC_KIND_LINK;
        tv.draw_border = is_link;
        tv.border_width = if highlight { 3 } else { 1 };
        tv.rounded_border = if is_link { Some(self.vp.bubble_radius) } else { None };
        tv.clear_area = false;
        tv.ellipsis = false;
        tv.insertion = None;
        // Borders need breathing room or they overstrike the glyphs.
        tv.margin = if is_link { Point::new(3, 3) } else { Point::new(0, 0) };
        write!(tv.text, "{}", line.text).ok();
        tv
    }

    /// Natural (unclipped) wrapped height of document line `i`, measured lazily
    /// and cached. Measured with a deep clip so where the line happens to fall
    /// on screen never shortens the cached value — pixel scrolling relies on
    /// these being the true heights.
    fn doc_line_height(&mut self, i: usize) -> u32 {
        let Some(doc) = self.document.as_ref() else { return 0 };
        let Some(line) = doc.lines.get(i) else { return 0 };
        if let Some(h) = doc.heights[i] {
            return h;
        }
        let h = if line.kind == DOC_KIND_DIVIDER || line.text.is_empty() {
            DOC_DIVIDER_HEIGHT
        } else {
            let mut tv = self.doc_textview(line, self.vp.status_height as isize, false, DOC_MEASURE_CLIP);
            match self.gam.bounds_compute_textview(&mut tv) {
                Ok(_) => tv.bounds_computed.map(|r| r.height()).unwrap_or(DOC_DIVIDER_HEIGHT),
                Err(_) => DOC_DIVIDER_HEIGHT,
            }
        };
        if let Some(doc) = self.document.as_mut() {
            doc.heights[i] = Some(h);
        }
        h
    }

    /// The document's drawable area: (first y, bottom y, height budget).
    /// Measured against FRESH canvas bounds every time, because the content
    /// canvas changes size out from under the startup bounds in `vp`: the
    /// input box is hidden in document mode (the canvas GROWS past `vp`),
    /// and outside it the IME can have grown the input into the content
    /// area. Stale bounds made paging skip lines that were never shown.
    fn doc_metrics(&self) -> (isize, isize, u32) {
        let size = self.gam.get_canvas_bounds(self.vp.canvas).unwrap_or(self.vp.total_screensize);
        let y0 = self.vp.status_height as isize + self.vp.margin.y;
        // The IMEF helper-bar (F1-F4 tray) sits at the very bottom of the
        // screen and the content canvas runs underneath it, so the bottom row
        // of the canvas is physically covered. Hold the visible bottom above
        // the tray (its predictive canvas is `Tall glyph + 2*margin` tall, per
        // the GAM chat layout): otherwise a fully-covered last line counts as
        // visible and page-down skips it (a merely partly-cut line is caught
        // by the clip test in `layout_document`, but a hidden one isn't).
        let tray = blitstr2::glyph_height_hint(GlyphStyle::Tall) as isize + 2 * self.vp.margin.y;
        let bottom = (size.y - tray).max(y0 + 1);
        (y0, bottom, (bottom - y0).max(0) as u32)
    }

    /// Render the document at the current pixel `scroll`: draw every line that
    /// intersects the viewport (clip handles the partial line at each edge),
    /// links bordered and the selected link highlighted, then the status bar —
    /// mirroring `layout()` for chat.
    fn layout_document(&mut self) {
        let total = match self.document.as_ref() {
            Some(d) => d.lines.len(),
            None => return,
        };
        // Re-clamp scroll: heights (and thus the max) can shift as new content
        // streams in or the canvas resizes.
        let max = self.doc_max_scroll();
        let (scroll, cursor) = {
            let doc = self.document.as_mut().unwrap();
            doc.scroll = doc.scroll.min(max);
            (doc.scroll, doc.cursor)
        };

        // Clear everything (status bar included; it is redrawn below). Clear to
        // the FULL canvas height, not the (tray-reduced) layout bottom: with the
        // input box hidden the canvas is taller than the startup bounds, and
        // clearing only to the stale/reduced size would leave ghosts in the
        // reclaimed strip (incl. the part under the helper bar between redraws).
        let (y0, bottom, _) = self.doc_metrics();
        let clear_bottom = self.gam.get_canvas_bounds(self.vp.canvas).map(|s| s.y).unwrap_or(bottom);
        self.gam
            .draw_rectangle(
                self.vp.canvas,
                Rectangle::new_with_style(
                    Point::new(0, 0),
                    Point::new(self.vp.total_screensize.x, clear_bottom),
                    DrawStyle { fill_color: Some(PixelColor::Light), stroke_color: None, stroke_width: 0 },
                ),
            )
            .expect("can't clear canvas area");

        // Walk the whole document in document space; draw the lines that
        // intersect the viewport [scroll, scroll + budget). Each line's screen
        // y is pure arithmetic (`y0 + doc_y - scroll`), so a wrapped line can
        // sit partly above the top (negative offset, clipped at the status bar)
        // or partly below the bottom (clipped at `bottom`). Nothing is ever
        // skipped, and the on-screen height of a line never feeds back into its
        // cached natural height.
        let mut doc_y = 0u32; // top of line i, document space
        for i in 0..total {
            let h = self.doc_line_height(i);
            let line_bottom = doc_y + h;
            let next_y = line_bottom + self.vp.bubble_space as u32;
            if line_bottom <= scroll {
                doc_y = next_y; // entirely above the viewport
                continue;
            }
            let screen_y = y0 + doc_y as isize - scroll as isize;
            if screen_y >= bottom {
                break; // this and everything after is below the viewport
            }
            let line = match self.document.as_ref().and_then(|d| d.lines.get(i)) {
                Some(l) => l.clone(),
                None => break,
            };
            if line.kind == DOC_KIND_DIVIDER {
                let mid = screen_y + (DOC_DIVIDER_HEIGHT / 2) as isize;
                if mid >= y0 && mid < bottom {
                    let rule = Line::new(
                        Point::new(self.vp.margin.x, mid),
                        Point::new(self.vp.layout_screensize.x - self.vp.margin.x, mid),
                    );
                    self.gam.draw_line(self.vp.canvas, rule).ok();
                }
            } else if !line.text.is_empty() {
                let highlight = cursor == Some(i) && line.kind == DOC_KIND_LINK;
                let mut tv = self.doc_textview(&line, screen_y, highlight, bottom);
                self.gam.post_textview(&mut tv).ok();
            }
            doc_y = next_y;
        }

        // Status bar on top, exactly like the chat layout.
        self.gam.post_textview(&mut self.status_tv).expect("couldn't render status bar");
        let status_border = Line::new(
            Point::new(0, self.vp.status_height as isize),
            Point::new(self.vp.total_screensize.x, self.vp.status_height as isize),
        );
        self.gam.draw_line(self.vp.canvas, status_border).expect("couldn't draw status lower border");
    }

    /// Update the busy state. Does not touch any other aspect of the screen layout.
    pub(crate) fn redraw_busy(&mut self) -> Result<(), xous::Error> {
        let curtime = self.tt.elapsed_ms();
        if curtime - self.status_last_update_ms > BUSY_ANIMATION_RATE_MS as u64 {
            self.gam.post_textview(&mut self.status_tv)?;
            self.gam.redraw().expect("couldn't redraw screen");
            self.status_last_update_ms = curtime;
        }
        Ok(())
    }

    /// Update the status bar, without any throttling
    pub(crate) fn redraw_status_forced(&mut self) -> Result<(), xous::Error> {
        self.gam.post_textview(&mut self.status_tv)?;
        self.gam.redraw().expect("couldn't redraw screen");
        let curtime = self.tt.elapsed_ms();
        self.status_last_update_ms = curtime;
        Ok(())
    }

    /// Returns `true` if the status bar is currently set for the busy animation
    pub(crate) fn is_busy(&self) -> bool {
        self.status_tv.busy_animation_state.is_some()
    }

    /// Set the status bar text. Forces an immediate repaint: discrete status text
    /// must always show, unlike the busy *animation* (whose rapid updates go
    /// through the throttled `UpdateBusy` path). Otherwise a one-shot status update
    /// can be silently dropped by the throttle and leave stale text on screen.
    pub(crate) fn set_status_text(&mut self, msg: &str) {
        self.status_tv.clear_str();
        write!(self.status_tv, "{}", msg).ok();
        xous::send_message(
            self.self_cid,
            xous::Message::new_scalar(ChatOp::UpdateBusyForced as usize, 0, 0, 0, 0),
        )
        .ok();
    }

    /// Sets the status bar to animate the busy animation
    pub(crate) fn set_busy_state(&mut self, run: bool) {
        if run {
            self.status_tv.busy_animation_state = Some(0); // the "glitch" to 0 is intentional, gives an indicator that a new op has started
        } else {
            if self.status_tv.busy_animation_state.take().is_some() {
                self.status_tv.clear_str();
                write!(self.status_tv, "{}", self.status_idle_text).ok();
                // force the update, to ensure the idle state text is actually rendered
                xous::send_message(
                    self.self_cid,
                    xous::Message::new_scalar(ChatOp::UpdateBusyForced as usize, 0, 0, 0, 0),
                )
                .ok();
            }
        }
    }

    /// Set the default idle text. Does *not* cause a redraw. If you need
    /// an instant re-draw, call `set_status_text()`
    pub(crate) fn set_status_idle_text(&mut self, msg: &str) {
        self.status_idle_text = msg.to_owned();
    }

    /// Layout the post bubbles on the screen.
    ///
    /// The challenge is to layout a sub-set of the posts on screen, ensuring that
    /// the selected-post is fully displayed, and to do something non-jarring as the
    /// user moves the selection up or down.
    ///
    /// That is, when the user clicks up then the currently selected post should go
    /// un-bold, and the post above should go bold, without movement - unless the newly
    /// selected post is partially or fully off-screen, in which case, the posts need
    /// to move down. There are three edge cases, when the first or last post is reached,
    /// or when the post is too big for the screen. And an additional challenge,
    /// that the only way to calculate the vertical height of a post is to lay it out.
    fn layout(&mut self) -> Result<(), Error> {
        if let Some(dialogue) = self.dialogue.as_mut() {
            log::info!("redrawing dialogue: {}", dialogue.title);

            // 1. Consistency check the layout range versus selected post.
            let search_required = if let Some(selected) = self.layout_selected {
                !self.layout_range.contains(&selected)
            } else {
                true
            };

            // 2. Adjust the displayable range.
            if search_required {
                let starting_at = if let Some(selected) = self.layout_selected {
                    if self.layout_range.len() > 0 {
                        self.layout_topdown = selected <= *self.layout_range.iter().min().unwrap_or(&0);
                        selected
                    } else {
                        // if no range is available, go from the bottom up, starting with the selected post
                        self.layout_topdown = false;
                        selected
                    }
                } else {
                    // no post selected, always layout from bottom up, starting at the most recent post
                    self.layout_topdown = false;
                    dialogue.post_last().unwrap_or(0)
                };
                // Snapshot author names before the posts are mutably borrowed:
                // height measurement must use the same header the bubble will
                // render with (see `post_header`).
                let author_names = dialogue.author_names();
                let mut fwd_iter;
                let mut rev_iter;
                let search_window: &mut dyn Iterator<Item = _> = if self.layout_topdown {
                    // search from the selected post to all newer posts, top-to-down
                    fwd_iter = dialogue.posts_as_slice_mut()[starting_at..].iter_mut();
                    &mut fwd_iter
                } else {
                    // search from oldest post to selected post, bottom-to-top
                    if dialogue.posts_as_slice().len() > 0 {
                        rev_iter = dialogue.posts_as_slice_mut()[..=starting_at].iter_mut().rev();
                    } else {
                        // zero-length case we still have to return an empty iterator, but
                        // we can't have the range be inclusive and the code still work
                        rev_iter = dialogue.posts_as_slice_mut().iter_mut().rev();
                    }
                    &mut rev_iter
                };
                let mut total_height = 0;
                self.layout_range.clear();
                for (i, post) in search_window.enumerate() {
                    let next_height = if let Some(bb) = post.bounding_box {
                        bb.height() + self.vp.bubble_space as u32 + self.vp.bubble_margin.y as u32
                    } else {
                        // if the "natural height" has not been computed, do so now.
                        let header = crate::post_header(
                            author_names.get(&post.author_id()).map(|s| s.as_str()),
                            post.timestamp(),
                        );
                        let mut layout_bubble = default_textview(post, Some(&header), false, &self.vp);
                        log::debug!("compute bounds on {}", layout_bubble);
                        if self.gam.bounds_compute_textview(&mut layout_bubble).is_ok() {
                            post.bounding_box = layout_bubble.bounds_computed;
                            match layout_bubble.bounds_computed {
                                Some(r) => {
                                    r.height() + self.vp.bubble_space as u32 + self.vp.bubble_margin.y as u32
                                }
                                None => {
                                    log::warn!(
                                        "Unexpected null bounds in computing textview heights, layout will be incorrect."
                                    );
                                    0
                                }
                            }
                        } else {
                            log::warn!(
                                "Unexpected error in computing textview heights, layout will be incorrect."
                            );
                            0
                        }
                    };
                    if total_height + next_height > self.vp.layout_screensize.y as u32 {
                        if self.layout_topdown {
                            self.layout_range = (starting_at..starting_at + i).collect();
                        } else {
                            self.layout_range = (starting_at - i..=starting_at).rev().collect();
                        }
                        break;
                    }
                    total_height += next_height;
                }
                if self.layout_range.len() == 0 {
                    // not enough elements to fill the entire screen. Just select everything from selected
                    // to the last possible message.
                    log::debug!("Not enough elements to fill the screen");
                    if self.layout_topdown {
                        self.layout_range = (starting_at..).collect();
                    } else {
                        if dialogue.posts_as_slice().len() > 0 {
                            self.layout_range = (0..=starting_at).rev().collect();
                        } else {
                            // "empty range" in case of no posts
                            self.layout_range = (0..0).rev().collect();
                        }
                    }
                }
            }
            assert!(
                dialogue.posts_as_slice().len() == 0 || self.layout_range.len() > 0,
                "Layout range should be set at this point."
            );

            // 3. clear the entire area, and re-draw the status bar
            self.gam
                .draw_rectangle(
                    self.vp.canvas,
                    Rectangle::new_with_style(
                        Point::new(0, 0),
                        self.vp.total_screensize,
                        DrawStyle {
                            fill_color: Some(PixelColor::Light),
                            stroke_color: None,
                            stroke_width: 0,
                        },
                    ),
                )
                .expect("can't clear canvas area");

            // 4. draw the text bubbles, in the order computed in step 2.
            let mut y = if self.layout_topdown {
                self.vp.status_height as isize + self.vp.bubble_margin.y
            } else {
                self.vp.status_height as isize + self.vp.layout_screensize.y - self.vp.bubble_margin.y
            };
            log::debug!(
                "Laying out with selected {:?} in range {:?}; topdown: {:?}",
                self.layout_selected,
                self.layout_range,
                self.layout_topdown
            );
            for &post_index in &self.layout_range {
                let post = match dialogue.post_get(post_index) {
                    Some(p) => p,
                    None => {
                        log::warn!(
                            "Expected post at index {}, returned nothing. Range {:?}, posts {:?}",
                            post_index,
                            self.layout_range,
                            dialogue.posts_as_slice()
                        );
                        continue;
                    }
                };
                let highlight =
                    if let Some(selected) = self.layout_selected { selected == post_index } else { false };
                let mut bubble_tv = bubble(&self.vp, self.layout_topdown, post, dialogue, highlight, y);
                self.gam.post_textview(&mut bubble_tv).expect("couldn't render bubble textview");
                // double check the actual bounds against expected bounds
                match bubble_tv.bounds_computed {
                    Some(actual_r) => {
                        let expected_r = post.bounding_box.expect("bb should be computed by now");
                        if expected_r.height() != actual_r.height() {
                            log::warn!(
                                "Height mismatch of drawn versus pre-computed text (expected {}, got {}) for {}",
                                expected_r.height(),
                                actual_r.height(),
                                bubble_tv.to_str()
                            );
                        }
                        if self.layout_topdown {
                            y += actual_r.height() as isize;
                        } else {
                            y -= actual_r.height() as isize;
                        }
                        // sanity check the computations
                        if y > self.vp.layout_screensize.y + self.vp.status_height as isize
                            || y < self.vp.status_height as isize
                        {
                            log::error!(
                                "Computed range of elements sent to layout overflows at index {}",
                                post_index
                            );
                            // stop laying out to avoid text artifacts
                            break;
                        }
                        // add y-margin before the next iteration
                        if self.layout_topdown {
                            y += self.vp.bubble_space + self.vp.bubble_margin.y;
                        } else {
                            y -= self.vp.bubble_space + self.vp.bubble_margin.y;
                        }
                    }
                    _ => {
                        log::error!(
                            "No bounds computed for {}, this is a GAM or typesetter bug!",
                            bubble_tv.to_str()
                        );
                    }
                }
            }

            // 5. draw status bar on top of any post that happens to flow over the top...
            self.gam.post_textview(&mut self.status_tv).expect("couldn't render status bar");
            let status_border = Line::new(
                Point::new(0, self.vp.status_height as isize),
                Point::new(self.vp.total_screensize.x, self.vp.status_height as isize),
            );
            self.gam.draw_line(self.vp.canvas, status_border).expect("couldn't draw status lower border");

            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidData, "missing dialogue"))
        }
    }
}
