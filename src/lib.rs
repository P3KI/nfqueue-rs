//!  Netfilter NFQUEUE high-level bindings
//!
//! libnetfilter_queue is a userspace library providing an API to packets that
//! have been queued by the kernel packet filter. It is is part of a system that
//! deprecates the old ip_queue / libipq mechanism.
//!
//! libnetfilter_queue homepage is: http://netfilter.org/projects/libnetfilter_queue/
//!
//! The goal is to provide a library to gain access to packets queued by the
//! kernel packet filter
//!
//! **Using NFQUEUE requires root privileges, or the `CAP_NET_ADMIN` capability**
//!
//! The code is available on [Github](https://github.com/chifflier/nfqueue-rs)
//!
//! # Example
//!
//! ```rust,ignore
//! extern crate libc;
//! extern crate nfqueue;
//!
//! struct State {
//!     count: u32,
//! }
//!
//! impl State {
//!     pub fn new() -> State {
//!         State{ count:0 }
//!     }
//! }
//!
//! fn queue_callback(msg: nfqueue::Message, state:&mut State) -> i32 {
//!     println!("Packet received [id: 0x{:x}]\n", msg.get_id());
//!
//!     println!(" -> msg: {}", msg);
//!
//!     println!("XML\n{}", msg.as_xml_str(&[nfqueue::XMLFormatFlags::XmlAll]).unwrap());
//!
//!     state.count += 1;
//!     println!("count: {}", state.count);
//!
//!     msg.set_verdict(nfqueue::Verdict::Accept)
//! }
//!
//! fn main() {
//!     let mut q = nfqueue::Queue::new(State::new());
//!     println!("nfqueue example program: print packets metadata and accept packets");
//!
//!     let protocol_family = libc::AF_INET as u16;
//!
//!     q.open();
//!     q.unbind(protocol_family); // ignore result, failure is not critical here
//!
//!     let rc = q.bind(protocol_family);
//!     assert!(rc == 0);
//!
//!     q.create_queue(0, queue_callback);
//!     q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);
//!
//!     q.run_loop();
//!     q.close();
//! }
//!
//! ```

extern crate libc;

pub use hwaddr::*;
mod hwaddr;

pub use message::*;
mod message;

pub use bindings::*;
mod bindings;

/// Copy modes
pub enum CopyMode {
    /// Do not copy packet contents nor metadata
    CopyNone,
    /// Copy only packet metadata, not payload
    CopyMeta,
    /// Copy packet metadata and not payload
    CopyPacket,
}
const NFQNL_COPY_NONE : u8   = 0x00;
const NFQNL_COPY_META : u8   = 0x01;
const NFQNL_COPY_PACKET : u8 = 0x02;


/// Opaque struct `Queue`: abstracts an NFLOG queue
pub struct Queue<T> {
    qh  : *mut nfq_handle,
    qqh : *mut nfq_q_handle,
    cb  : Option<fn (Message, &mut T) -> i32>,
    data: T,
}


impl <T: Send> Queue<T> {
    /// Creates a new, uninitialized, `Queue`.
    pub fn new(data: T) -> Queue<T> {
        return Queue {
            qh : std::ptr::null_mut(),
            qqh : std::ptr::null_mut(),
            cb: None,
            data: data,
        };
    }

    /// Opens a NFLOG handler
    ///
    /// This function obtains a netfilter queue connection handle. When you are
    /// finished with the handle returned by this function, you should destroy it
    /// by calling `close()`.
    /// A new netlink connection is obtained internally
    /// and associated with the queue connection handle returned.
    pub fn open(&mut self) {
        self.qh = unsafe { nfq_open() };
    }

    /// Closes a NFLOG handler
    ///
    /// This function closes the nfqueue handler and free associated resources.
    pub fn close(&mut self) {
        assert!(!self.qh.is_null());
        unsafe { nfq_close(self.qh) };
        self.qh = std::ptr::null_mut();
    }

    /// Bind a nfqueue handler to a given protocol family
    ///
    /// Binds the given queue connection handle to process packets belonging to
    /// the given protocol family (ie. `PF_INET`, `PF_INET6`, etc).
    ///
    /// Arguments
    ///
    /// * `pf` - Protocol family (usually `AF_INET` or `AF_INET6`)
    ///
    /// Remarks:
    ///
    /// **Requires root privileges**
    pub fn bind(&self, pf: libc::c_ushort) -> i32 {
        assert!(!self.qh.is_null());
        return unsafe { nfq_bind_pf(self.qh,pf) };
    }

    /// Unbinds the nfqueue handler from a protocol family
    ///
    /// Unbinds the given nfqueue handle from processing packets belonging to the
    /// given protocol family.
    ///
    /// Arguments
    ///
    /// * `pf` - Protocol family (usually `AF_INET` or `AF_INET6`)
    ///
    /// Remarks:
    ///
    /// **Requires root privileges**
    pub fn unbind(&self, pf: libc::c_ushort) -> i32 {
        assert!(!self.qh.is_null());
        return unsafe { nfq_unbind_pf(self.qh,pf) }
    }

    /// Returns the C file descriptor associated with the nfqueue handler
    ///
    /// This function returns a file descriptor that can be used for
    /// communication over the netlink connection associated with the given queue
    /// connection handle.
    pub fn fd(&self) -> i32 {
        assert!(!self.qh.is_null());
        return unsafe { nfq_fd(self.qh) }
    }


    /// create a new queue handler bind it to a queue number, and to a callback.
    ///
    /// Creates a new queue handle, and returns it. The new queue is identified
    /// by `num`, and the callback specified by `cb` will be called for each
    /// enqueued packet.
    ///
    /// Arguments
    ///
    /// * `num`: the number of the queue to bind to
    /// * `cb`: callback function to call for each queued packet
    pub fn create_queue(&mut self, num: u16, cb: fn(Message, &mut T) -> i32) -> bool {
        assert!(!self.qh.is_null());
        assert!(self.qqh.is_null());
        let self_ptr = unsafe { std::mem::transmute(&*self) };
        self.cb = Some(cb);
        self.qqh = unsafe { nfq_create_queue(self.qh, num, Some(real_callback::<T>), self_ptr) };

        !self.qqh.is_null()
    }

    /// Destroys a group handle
    ///
    /// Removes the binding for the specified queue handle. This call also
    /// unbind from the nfqueue handler, so you don't need to call any extra
    /// function.
    pub fn destroy_queue(&mut self) {
        assert!(!self.qqh.is_null());
        unsafe { nfq_destroy_queue(self.qqh); }
        self.qqh = std::ptr::null_mut();
    }

    /// Set the amount of packet data that nfqueue copies to userspace
    ///
    /// Arguments:
    ///
    /// * `mode` - The part of the packet that we are interested in
    /// * `range` - Size of the packet that we want to get
    ///
    /// `mode` can be one of:
    ///
    /// * `NFQNL_COPY_NONE` - do not copy any data
    /// * `NFQNL_COPY_META` - copy only packet metadata
    /// * `NFQNL_COPY_PACKET` - copy entire packet
    pub fn set_mode(&self, mode: CopyMode, range: u32) {
        assert!(!self.qqh.is_null());
        let c_mode = match mode {
            CopyMode::CopyNone => NFQNL_COPY_NONE,
            CopyMode::CopyMeta => NFQNL_COPY_META,
            CopyMode::CopyPacket => NFQNL_COPY_PACKET,
        };
        unsafe { nfq_set_mode(self.qqh, c_mode, range); }
    }

    /// Set kernel queue maximum length parameter
    ///
    /// Arguments:
    ///
    /// * `queuelen` - The length of the queue
    ///
    /// Sets the size of the queue in kernel. This fixes the maximum number of
    /// packets the kernel will store before internally before dropping upcoming
    /// packets
    pub fn set_queue_maxlen(&self, queuelen: u32) -> i32 {
        assert!(!self.qqh.is_null());
        unsafe { nfq_set_queue_maxlen(self.qqh, queuelen) }
    }

    /// Runs an infinite loop, waiting for packets and triggering the callback.
    pub fn run_loop(&self) {
        assert!(!self.qh.is_null());
        assert!(!self.qqh.is_null());
        assert!(!self.cb.is_none());

        let fd = self.fd();
        let mut buf : [u8;65536] = [0;65536];
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_char;
        let buf_len = buf.len() as libc::size_t;

        loop {
            let rc = unsafe { libc::recv(fd, buf_ptr as *mut libc::c_void, buf_len, 0) };
            if rc < 0 { panic!("error in recv()"); };

            let rv = unsafe { nfq_handle_packet(self.qh, buf_ptr, rc as libc::c_int) };
            if rv < 0 { println!("error in nfq_handle_packet()"); }; // not critical
        }
    }

}

#[doc(hidden)]
extern "C" fn real_callback<T>(qqh: *mut nfq_q_handle, _nfmsg: *mut nfgenmsg, nfad: *mut nfq_data, data: *mut std::os::raw::c_void) -> i32 {
    let raw : *mut Queue<T> = unsafe { std::mem::transmute(data) };

    let ref mut q = unsafe { &mut *raw };
    let msg = Message::new (qqh, nfad);

    match q.cb {
        None => panic!("no callback registered"),
        Some(callback) => {
            callback(msg, &mut q.data)
        },
    }
}

#[cfg(test)]
mod tests {

    extern crate libc;

    #[test]
    fn nfqueue_open() {
        let mut q = ::Queue::new(());

        q.open();

        let raw = q.qh as *const i32;
        println!("nfq_open: 0x{:x}", unsafe{*raw});

        assert!(!q.qh.is_null());

        q.close();
    }

    // Can't  run this test by default as we do should not have enough rights.
    // You need to enable it manually to run it via `cargo test` after you ensured that the program
    // will have the right capabilities.
    #[test]
    #[ignore]
    fn nfqueue_bind() {
        let mut q = ::Queue::new(());

        q.open();

        let raw = q.qh as *const i32;
        println!("nfq_open: 0x{:x}", unsafe{*raw});

        assert!(!q.qh.is_null());

        let protocol_family = libc::AF_INET as u16;
        let rc = q.bind(protocol_family);

        println!("q.bind: {}", rc);
        assert!(q.bind(protocol_family) == 0);

        q.close();
    }
}

