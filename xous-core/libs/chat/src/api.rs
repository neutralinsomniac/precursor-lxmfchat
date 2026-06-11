use enumset::EnumSetType;
use rkyv::{Archive, Deserialize, Serialize};

// shorthand for the function keys F1 - F4
pub const F1: char = '\u{0011}';
pub const F2: char = '\u{0012}';
pub const F3: char = '\u{0013}';
pub const F4: char = '\u{0014}';

// these are used to increment and decrement the selected post
pub const POST_SELECTED_NEXT: usize = usize::MAX - 0;
pub const POST_SELECTED_PREV: usize = usize::MAX - 1;

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum ChatOp {
    // Save the Dialogue to pddb (ie after PostAdd, PostDelete)
    DialogueSave = 0,
    /// Set the current Dialogue to be displayed
    DialogueSet,
    /// change the Chat UI in/out of focus
    GamChangeFocus,
    /// a line of text has arrived
    GamLine,
    /// receive rawkeys from gam
    GamRawkeys,
    /// redraw our Chat UI
    GamRedraw,
    /// Show some user help
    Help,
    /// Add a new MenuItem to the App menu
    MenuAdd,
    /// Add a new Post to the Dialogue
    PostAdd,
    /// Delete a Post from the Dialogue
    PostDel,
    /// Find a Post by timestamp and Author
    PostFind,
    /// Atomically replace the text of the Post matching (author, timestamp).
    /// Find+replace in a single op so a concurrent PostAdd/PostDel can't shift
    /// the target between a separate find and edit.
    PostUpdate,
    PostFlag,
    /// Set status bar text
    SetStatusText,
    /// Run or stop the busy animation.
    SetBusyAnimationState,
    /// Set the status idle text (to be shown when exiting all busy states)
    SetStatusIdleText,
    /// Set one F1-F4 helper-tray label (and repaint the tray)
    IcontraySet,
    /// Update just the state of the busy animation, if any. Internal opcode.
    /// Will skip the update if called too often.
    UpdateBusy,
    /// Force update the busy bar, without rate throttling. Internal opcode.
    UpdateBusyForced,
    /// exit the application
    Quit,
    /// Document mode: reset the staging document + set its title (Buffer<DocMeta>).
    /// The displayed view (chat or a previous document) is untouched until
    /// DocumentShow, so a page being fetched never blanks the screen.
    DocumentBegin,
    /// Document mode: append a batch of lines to the staging document
    /// (Buffer<DocLines>; send in modest batches, not one giant buffer)
    DocumentLines,
    /// Document mode: display the staged document (scalar)
    DocumentShow,
    /// Document mode: leave, returning to the chat dialogue (scalar)
    DocumentClear,
    /// Document mode: blocking scalar query of the cursor's link;
    /// returns link_id+1, or 0 when the cursor is not on a link
    DocumentGetSelected,
    /// Document mode: scroll a screenful (scalar arg: 0 = up, 1 = down)
    DocumentPage,
}

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub(crate) enum BusyAnimOp {
    Start,
    Pump,
}

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum IconOp {
    PostMenu = 0,
    F2Op,
    F3Op,
    AppMenu,
}

pub const POST_TEXT_MAX: usize = 3072;

#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct Find {
    pub author: String,
    pub timestamp: u64,
    pub key: Option<usize>, // the return post key if found.
}

/// Request/response for [`ChatOp::PostUpdate`]: replace the text of the post
/// matching `(author, timestamp)`. The server sets `found` to whether a matching
/// post existed in the active dialogue (so the caller can defer if it didn't).
#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct PostUpdate {
    pub author: String,
    pub timestamp: u64,
    pub text: String,
    pub found: bool,
}

/// Request for [`ChatOp::IcontraySet`]: relabel the F-key helper-tray slot
/// `index` (0..=3 → F1..F4). Keep labels short — each slot is a quarter of the
/// screen width.
#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct IcontraySet {
    pub index: u32,
    pub label: String,
}

#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct Dialogue {
    pub dict: String,
    pub key: Option<String>,
}

#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct Post {
    pub dialogue_id: String,
    pub author: String,
    pub timestamp: u64,
    pub text: String,
    pub attach_url: Option<String>,
}

/// Events are sent to the Chat App when key things occur in the Chat UI
#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum Event {
    Focus,
    F1,     // F1 button click
    F2,     // F2 button click
    F3,     // you get the idea
    F4,     // guess
    Up,     // Up click
    Down,   // Down click
    Left,   // Left click
    Right,  // Right click
    Top,    // Top of post list reached
    Bottom, // Bottom of post list reached
    Key,    // keystroke
    Post,   // new user Post committed
    Menu,   // menu item clicked
}

#[derive(
    Archive, Serialize, Deserialize, Debug, num_derive::FromPrimitive, num_derive::ToPrimitive, EnumSetType,
)]
pub enum PostFlag {
    Deleted,
    Draft,
    Hidden,
}

#[derive(
    Archive, Serialize, Deserialize, Debug, num_derive::FromPrimitive, num_derive::ToPrimitive, EnumSetType,
)]
pub enum AuthorFlag {
    Bold,
    Hidden,
    Right,
}

#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct BusyMessage {
    pub busy_msg: String,
}

// One GlyphStyle per TextView means one style per document line; the app
// flattens richer markup (e.g. micron) down to these.
pub const DOC_STYLE_REGULAR: u8 = 0;
pub const DOC_STYLE_BOLD: u8 = 1;
pub const DOC_STYLE_MONO: u8 = 2;
pub const DOC_STYLE_LARGE: u8 = 3;

pub const DOC_ALIGN_LEFT: u8 = 0;
pub const DOC_ALIGN_CENTER: u8 = 1;
pub const DOC_ALIGN_RIGHT: u8 = 2;

pub const DOC_KIND_TEXT: u8 = 0;
pub const DOC_KIND_DIVIDER: u8 = 1;
/// A selectable link line; `link_id` identifies it to the app.
pub const DOC_KIND_LINK: u8 = 2;

/// One line of a document-mode page (see DOC_STYLE/ALIGN/KIND constants).
#[derive(Archive, Serialize, Deserialize, Debug, Clone)]
pub struct DocLine {
    pub text: String,
    pub style: u8,
    pub align: u8,
    pub kind: u8,
    pub link_id: u16,
}

/// Request for [`ChatOp::DocumentBegin`].
#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct DocMeta {
    pub title: String,
}

/// Request for [`ChatOp::DocumentLines`]: a batch of lines to append.
#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct DocLines {
    pub lines: Vec<DocLine>,
}
