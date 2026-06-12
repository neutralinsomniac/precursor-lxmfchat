#[allow(dead_code)]
pub(crate) const SERVER_NAME_LXMFCHAT: &str = "_LXMF chat_";

/// Opcodes handled by the app's own server (driven by the Chat UI + menus).
#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum LxmfchatOp {
    /// Chat UI event (focus, navigation, …)
    Event = 0,
    /// App menu item clicked
    Menu,
    /// Chat UI committed a user post (outbound message text)
    Post,
    /// Chat UI raw keystroke
    Rawkeys,
    /// Exit the application
    Quit,
}

/// App menu actions.
#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum MenuOp {
    /// Browse the live list of seen announces; pick one to message (and save).
    Announces,
    /// Pick a peer to message from your saved contacts.
    Contacts,
    /// Give a saved contact a new display name.
    RenameContact,
    /// Add a contact from an address received in a message.
    ImportContact,
    /// (Re)connect to the configured hub and announce our address
    Connect,
    /// Announce our lxmf.delivery destination on the connected hub
    Announce,
    /// Show our own LXMF address
    MyAddress,
    /// Set the display name we announce to the network.
    SetName,
    /// Manually set the peer by pasting a 32-hex lxmf address (advanced/fallback)
    SetPeer,
    /// Set the transport hub (host / port)
    SetHub,
    /// Wipe the message history of the currently-open conversation (keeps the
    /// contact, its key, and any stamp ticket).
    ClearHistory,
    /// Download messages stored for us at the propagation node (store-and-forward).
    Sync,
    /// Open the page browser: raises its menu (bookmarks, URL entry, node pickers).
    Browser,
    /// Scan the open conversation for page links and open one in the browser.
    SelectUrl,
    /// no-op (close menu)
    Noop,
}
