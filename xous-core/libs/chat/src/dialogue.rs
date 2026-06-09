pub mod attach;
pub mod author;
pub mod post;

use core::slice::{Iter, IterMut};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};

use author::Author;
use gam::Gam;
use post::Post;
use rkyv::{Archive, Deserialize, Serialize};

use crate::ui::VisualProperties;
use crate::{default_textview, now};

// TODO do better than just allocate lots!
pub const MAX_BYTES: usize = 65536;
/// Hard cap on posts retained per dialogue, so the serialized value stays well
/// under [`MAX_BYTES`] (oldest posts are dropped). ~256 posts ≈ tens of KB.
pub const MAX_POSTS: usize = 256;
/// Serialized-size budget we trim a dialogue to. Kept comfortably under
/// [`MAX_BYTES`] so the rkyv archive (with its root, padding and pointers) never
/// approaches the fixed read buffer — a value that exceeds `MAX_BYTES` is
/// truncated on read and the rkyv root is lost, which on a 32-bit target turns
/// into a multi-megabyte bogus allocation that aborts the process every launch
/// (the dialogue is read at startup). A post-*count* cap alone is insufficient
/// because post text length is unbounded, so we also cap by estimated bytes.
const BYTE_BUDGET: usize = 56 * 1024;
/// Generous per-post serialization overhead (the `Post` struct fields, rkyv
/// relative pointers, alignment padding, and the author tables' share) on top of
/// the post's text — used by [`Dialogue::enforce_byte_budget`].
const PER_POST_OVERHEAD: usize = 128;

/// Magic prefixing a stored dialogue value (`MAGIC | len(4 BE) | crc(4 BE) | rkyv`).
/// The length lets the reader use the exact rkyv body and ignore any stale tail
/// (a PDDB key is not truncated by a shorter rewrite), and the checksum rejects a
/// partial/corrupt body before it reaches rkyv's *unchecked* accessor — which
/// would otherwise read a bogus length and abort with a huge allocation. A value
/// without this header is a pre-envelope (legacy) write: unverifiable, so it is
/// reset. See `ui::dialogue_read` / `ui::dialogue_save`.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"CHd1";
/// Total envelope header size (magic + len + crc).
pub const ENVELOPE_HEADER: usize = 12;

/// FNV-1a 32-bit checksum (no external dependency) over a stored dialogue body.
pub fn checksum(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// A Dialogue is a generic representation of a series of Posts
/// This might represent a room, group, or direct-message conversation
#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct Dialogue {
    /// A title of the Dialogue
    pub title: String,
    /// A time ordered sequence of posts in the Dialogue
    posts: Vec<Post>,
    /// An index of unique Author id's (internal)
    authors: HashMap<u16, Author>,
    /// A lookup on Author names
    author_lookup: HashMap<String, u16>,
    /// The timestamp on the most recent Post
    last_timestamp: u64,
    /// The id assigned to the most recent new Author
    last_author_id: u16,
}

impl Dialogue {
    /// Creates a new Dialogue with a single Author.
    /// Author id=0 is assigned to the user of this Chat App.
    pub fn new(title: &str) -> Self {
        let first_author_id = 0;
        let author = Author::new("me");
        let mut authors = HashMap::new();
        authors.insert(first_author_id, author);
        Self {
            title: title.to_string(),
            posts: Vec::<Post>::new(),
            authors,
            author_lookup: HashMap::<String, u16>::new(),
            last_timestamp: now(),
            last_author_id: first_author_id + 1,
        }
    }

    /// Add a new Post to the Dialogue
    ///
    /// TODO protect against Dialogue::MAX_BYTES overflow
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
    /// * `vp` - the visual properties of the system - so that we can pre-compute the size extents of the post
    pub fn post_add(
        &mut self,
        author: &str,
        timestamp: u64,
        text: &str,
        _attach_url: Option<&str>,
        vp: Option<(&VisualProperties, &Gam)>,
    ) -> Result<(), Error> {
        match self.author_id(author) {
            Some(author_id) => {
                let mut new = Post::new(
                    author_id, timestamp, text, None, // TODO implement
                );
                if self.posts.len() == 0 {
                    self.posts.push(new);
                    return Ok(());
                }
                let new_ts = new.timestamp();
                log::trace!("{:?}", new);

                // compute the bounds for the post if visual properties are specified
                if let Some((vp, gam)) = vp {
                    let mut layout_bubble = default_textview(&new, false, vp);
                    log::debug!("Computing bounds on {:?}", layout_bubble);
                    if gam.bounds_compute_textview(&mut layout_bubble).is_ok() {
                        new.bounding_box = layout_bubble.bounds_computed;
                    }
                }

                // Insert in timestamp order, AFTER any existing posts with the same
                // timestamp, so same-second messages keep arrival order. We never
                // replace here: two distinct messages can share a whole-second
                // timestamp (inbound timestamps are truncated to seconds), and
                // replacing would silently drop one of them. Editing an existing
                // post (e.g. the ✓ delivery-mark swap) goes through `post_update`
                // instead — a separate, explicit find-and-replace.
                let i = self.posts.partition_point(|p| p.timestamp() <= new_ts);
                self.posts.insert(i, new);
                // Hard cap the scrollback so the serialized dialogue can never
                // balloon past the PDDB value limit (an oversized value corrupts on
                // write and overflows the rkyv hash-table on the next read). Drops
                // the oldest posts.
                while self.posts.len() > MAX_POSTS {
                    self.posts.remove(0);
                }
                self.enforce_byte_budget();
                Ok(())
            }
            None => Err(Error::new(ErrorKind::Other, "max authors exceeeded")),
        }
    }

    /// Drop oldest posts until the estimated serialized size is within
    /// [`BYTE_BUDGET`], so the dialogue can never grow past the PDDB read buffer
    /// (see [`BYTE_BUDGET`] for why an oversized value is fatal). Always keeps at
    /// least the most recent post.
    fn enforce_byte_budget(&mut self) {
        let post_size = |p: &Post| p.text().len() + PER_POST_OVERHEAD;
        let mut total: usize = self.title.len() + 512; // base + author tables headroom
        for p in &self.posts {
            total += post_size(p);
        }
        while total > BYTE_BUDGET && self.posts.len() > 1 {
            total -= post_size(&self.posts[0]);
            self.posts.remove(0);
        }
    }

    /// Returns Some(index) of a matching Post by Author and Timestamp, or None
    ///
    /// # Arguments
    ///
    /// * `timestamp` - the Post timestamp criteria
    /// * `author` - the Post Author criteria
    pub fn post_find(&self, author: &str, timestamp: u64) -> Option<usize> {
        if let Some(author_id) = self.author_lookup.get(author) {
            let i = self.posts.partition_point(|p| p.timestamp() < timestamp);
            // Scan all posts with the matching timestamp, INCLUDING the last one
            // (an earlier `i..len-1` bound missed a match at the final position —
            // exactly the common case of updating the most-recent post).
            for n in i..self.posts.len() {
                let post = &self.posts[n];
                if post.timestamp() != timestamp {
                    break;
                }
                if post.author_id() == *author_id {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Atomically replace the text of the post matching `(author, timestamp)`,
    /// recomputing its layout. Returns true if a matching post was found. Doing
    /// the find and replace together (vs a separate find + delete + add) keeps it
    /// safe against concurrent posts shifting indices.
    pub fn post_update(
        &mut self,
        author: &str,
        timestamp: u64,
        new_text: &str,
        vp: Option<(&VisualProperties, &Gam)>,
    ) -> bool {
        let idx = match self.post_find(author, timestamp) {
            Some(i) => i,
            None => return false,
        };
        let author_id = self.posts[idx].author_id();
        let mut updated = Post::new(author_id, timestamp, new_text, None);
        if let Some((vp, gam)) = vp {
            let mut layout_bubble = default_textview(&updated, false, vp);
            if gam.bounds_compute_textview(&mut layout_bubble).is_ok() {
                updated.bounding_box = layout_bubble.bounds_computed;
            }
        }
        self.posts[idx] = updated;
        true
    }

    /// Remove the post at `index` (e.g. to replace a bubble with an updated one).
    pub fn post_del(&mut self, index: usize) -> Result<(), Error> {
        if index < self.posts.len() {
            self.posts.remove(index);
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "post index out of range"))
        }
    }

    /// Return Some<Post> by index in the Dialogue, or None.
    ///
    /// # Arguments
    ///
    /// * `index` - the index of the required Post
    pub fn post_get(&self, index: usize) -> Option<&Post> { self.posts.get(index) }

    /// Return the index of the most recent Post in the Dialogue
    pub fn post_last(&self) -> Option<usize> {
        if self.posts.len() == 0 { None } else { Some(self.posts.len() - 1) }
    }

    /// Return a slice of posts
    pub fn posts_as_slice(&self) -> &[Post] { &self.posts }

    pub fn posts_as_slice_mut(&mut self) -> &mut [Post] { &mut self.posts }

    /// Return an iterator over the Dialogue Posts (oldest first)
    pub fn posts(&self) -> Iter<Post> { return self.posts.iter(); }

    /// Return a mut iterator over the Dialogue Posts (oldest first)
    pub fn posts_mut(&mut self) -> IterMut<Post> { return self.posts.iter_mut(); }

    /// Return Some<Author> by id, or None.
    ///
    /// # Arguments
    ///
    /// * `id` - the index of the required Author
    pub fn author(&self, id: u16) -> Option<&Author> { self.authors.get(&id) }

    /// Return Some<author_id> by Author name, or None.
    ///
    /// # Arguments
    ///
    /// * `author` - the (external) name of the Author
    pub fn author_id(&mut self, author: &str) -> Option<u16> {
        let id = match self.author_lookup.get(author) {
            Some(id) => *id,
            None => {
                let id = self.author_id_next()?;
                self.authors.insert(id, Author::new(author));
                self.author_lookup.insert(author.to_string(), id);
                id
            }
        };
        // The local user's own posts render right-aligned, to distinguish them
        // from received messages. Applied idempotently (also to authors created
        // before this flag existed), so existing threads pick it up too.
        if author == crate::SELF_AUTHOR {
            if let Some(a) = self.authors.get_mut(&id) {
                let mut flags = a.flags_get();
                flags.insert(crate::api::AuthorFlag::Right);
                a.flags_set(flags);
            }
        }
        Some(id)
    }

    /// Assign and Return Some<author_id>, or None
    fn author_id_next(&mut self) -> Option<u16> {
        if self.last_author_id < u16::max_value() {
            self.last_author_id += 1;
            Some(self.last_author_id)
        } else {
            None
        }
    }
}
