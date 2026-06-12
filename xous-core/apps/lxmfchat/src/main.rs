#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

mod api;

use api::*;
use chat::{Chat, Event};
use gam::{MenuItem, MenuPayload};
use lxmfchat::LxmfChat;
use num_traits::*;
use xous_ipc::Buffer;

fn main() -> ! {
    let stack_size = 1024 * 1024;
    std::thread::Builder::new().stack_size(stack_size).spawn(wrapped_main).unwrap().join().unwrap()
}

fn wrapped_main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("LXMF chat PID is {}", xous::process::id());

    // Give ourselves a generous heap for the crypto + buffers.
    const HEAP_LARGER_LIMIT: usize = 2048 * 1024;
    let result = xous::rsyscall(xous::SysCall::AdjustProcessLimit(
        xous::Limits::HeapMaximum as usize,
        0,
        HEAP_LARGER_LIMIT,
    ));
    if let Ok(xous::Result::Scalar2(1, current_limit)) = result {
        xous::rsyscall(xous::SysCall::AdjustProcessLimit(
            xous::Limits::HeapMaximum as usize,
            current_limit,
            HEAP_LARGER_LIMIT,
        ))
        .unwrap();
        log::info!("Heap limit increased to: {}", HEAP_LARGER_LIMIT);
    }

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME_LXMFCHAT, None).expect("can't register server");

    let chat = Chat::new(
        gam::APP_NAME_LXMFCHAT,
        gam::APP_MENU_0_LXMFCHAT,
        Some(xous::connect(sid).unwrap()),
        Some(LxmfchatOp::Post as usize),
        Some(LxmfchatOp::Event as usize),
        Some(LxmfchatOp::Rawkeys as usize),
    );

    let cid = xous::connect(sid).unwrap();
    let menu_item = |name: &str, op: MenuOp| MenuItem {
        name: String::from(name),
        action_conn: Some(cid),
        action_opcode: LxmfchatOp::Menu as u32,
        action_payload: MenuPayload::Scalar([op as u32, 0, 0, 0]),
        close_on_select: true,
    };
    chat.menu_add(menu_item("Announces", MenuOp::Announces)).ok();
    chat.menu_add(menu_item("Contacts", MenuOp::Contacts)).ok();
    chat.menu_add(menu_item("Rename contact", MenuOp::RenameContact)).ok();
    chat.menu_add(menu_item("Import contact", MenuOp::ImportContact)).ok();
    chat.menu_add(menu_item("Connect", MenuOp::Connect)).ok();
    chat.menu_add(menu_item("Local peers", MenuOp::LocalPeers)).ok();
    chat.menu_add(menu_item("Announce", MenuOp::Announce)).ok();
    chat.menu_add(menu_item("My address", MenuOp::MyAddress)).ok();
    chat.menu_add(menu_item("My name", MenuOp::SetName)).ok();
    chat.menu_add(menu_item("Set peer", MenuOp::SetPeer)).ok();
    chat.menu_add(menu_item("Set hub", MenuOp::SetHub)).ok();
    chat.menu_add(menu_item("Sync messages", MenuOp::Sync)).ok();
    chat.menu_add(menu_item("Browser", MenuOp::Browser)).ok();
    chat.menu_add(menu_item("Select URL", MenuOp::SelectUrl)).ok();
    chat.menu_add(menu_item("Clear history", MenuOp::ClearHistory)).ok();
    chat.menu_add(menu_item("Close", MenuOp::Noop)).ok();

    let modals = modals::Modals::new(&xns).unwrap();
    let mut app = LxmfChat::new(&chat);
    let mut first_focus = true;
    let mut user_post: Option<String> = None;

    loop {
        let msg = xous::receive_message(sid).unwrap();
        log::debug!("got message {:?}", msg);
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(LxmfchatOp::Event) => {
                xous::msg_scalar_unpack!(msg, event_code, _, _, _, {
                    match FromPrimitive::from_usize(event_code) {
                        Some(Event::Focus) => {
                            if first_focus {
                                first_focus = false;
                                app.connect();
                            }
                            app.redraw();
                        }
                        // While the page browser is on screen the keys rebind
                        // (the icontray hints say so): ← back, → follow the
                        // selected link, F1 browser menu, F2/F3 page up/down,
                        // F4 exit. Otherwise the chat bindings apply, where
                        // Left/Right are no-ops (the chat lib already handled
                        // menus before forwarding them) and F4 stays unbound
                        // (it doubles as the power key).
                        Some(Event::F1) => {
                            if app.browsing() {
                                app.browser_menu(&modals)
                            } else {
                                app.jump_to_unread()
                            }
                        }
                        Some(Event::F2) => {
                            if app.browsing() {
                                app.browser_page(false)
                            } else {
                                app.jump_back()
                            }
                        }
                        Some(Event::F3) => {
                            if app.browsing() {
                                app.browser_page(true)
                            } else {
                                app.sync_now()
                            }
                        }
                        Some(Event::F4) => {
                            if app.browsing() {
                                app.browser_exit()
                            }
                        }
                        Some(Event::Left) => app.browser_back(),
                        Some(Event::Right) => app.follow_link(),
                        _ => {}
                    }
                });
            }
            Some(LxmfchatOp::Menu) => {
                xous::msg_scalar_unpack!(msg, menu_code, _, _, _, {
                    match FromPrimitive::from_usize(menu_code) {
                        Some(MenuOp::Announces) => app.show_announces_interactive(&modals),
                        Some(MenuOp::Contacts) => app.message_contact_interactive(&modals),
                        Some(MenuOp::RenameContact) => app.rename_contact_interactive(&modals),
                        Some(MenuOp::ImportContact) => app.import_contact_interactive(&modals),
                        Some(MenuOp::Connect) => app.connect(),
                        Some(MenuOp::LocalPeers) => app.toggle_local_peers(),
                        Some(MenuOp::Announce) => app.announce(),
                        Some(MenuOp::MyAddress) => {
                            modals
                                .show_notification(&format!("Your LXMF address:\n{}", app.our_address()), None)
                                .ok();
                        }
                        Some(MenuOp::SetName) => app.set_name_interactive(&modals),
                        Some(MenuOp::SetPeer) => app.set_peer_interactive(&modals),
                        Some(MenuOp::SetHub) => app.set_hub_interactive(&modals),
                        Some(MenuOp::ClearHistory) => app.clear_history_interactive(&modals),
                        Some(MenuOp::Sync) => app.sync_now(),
                        Some(MenuOp::Browser) => app.browser_open(&modals),
                        Some(MenuOp::SelectUrl) => app.select_url_interactive(&modals),
                        Some(MenuOp::Noop) | None => {}
                    }
                });
            }
            Some(LxmfchatOp::Post) => {
                let buffer = unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                let s = buffer.to_original::<String, _>().unwrap();
                if !s.is_empty() {
                    user_post = Some(s);
                }
            }
            Some(LxmfchatOp::Rawkeys) => {}
            Some(LxmfchatOp::Quit) => {
                log::info!("quitting LXMF chat");
                break;
            }
            None => log::warn!("unknown opcode {:?}", msg.body.id()),
        }
        if let Some(post) = user_post.take() {
            app.post(&post);
        }
    }

    xns.unregister_server(sid).unwrap();
    xous::destroy_server(sid).unwrap();
    xous::terminate_process(0)
}
