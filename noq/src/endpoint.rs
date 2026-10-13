use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    mem,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    num::NonZeroUsize,
    pin::Pin,
    str,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

#[cfg(all(
    not(wasm_browser),
    any(feature = "runtime-tokio", feature = "runtime-smol"),
    any(feature = "aws-lc-rs", feature = "ring"),
))]
use crate::runtime::default_runtime;
use crate::{
    Instant,
    runtime::{AsyncUdpSocket, Runtime, UdpSender},
    udp_transmit,
};
use bytes::{Bytes, BytesMut};
use ipnet::IpNet;
use pin_project_lite::pin_project;
use proto::{
    self as proto, ClientConfig, ConnectError, ConnectionError, ConnectionHandle, DatagramEvent,
    EndpointEvent, FourTuple, NetworkChangeHint, ServerConfig,
};
use rustc_hash::FxHashMap;
#[cfg(all(
    not(wasm_browser),
    any(feature = "runtime-tokio", feature = "runtime-smol"),
    any(feature = "aws-lc-rs", feature = "ring"),
))]
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::{Notify, futures::Notified, mpsc};
use tracing::{Instrument, Span, trace};
use udp::{BATCH_SIZE, RecvMeta};

use crate::{
    ConnectionEvent, EndpointConfig, IO_LOOP_BOUND, RECV_TIME_BOUND, VarInt,
    connection::Connecting, incoming::Incoming, work_limiter::WorkLimiter,
};

/// A QUIC endpoint.
///
/// An endpoint owns one or more UDP sockets, may host many connections, and may act as both
/// client and server for different connections. With several sockets, each socket is received
/// from by its own task and outgoing datagrams go to the socket whose
/// [`ip_ranges`](AsyncUdpSocket::ip_ranges) match the destination.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
    runtime: Arc<dyn Runtime>,
}

impl Endpoint {
    /// Helper to construct an endpoint for use with outgoing connections only
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// If an IPv6 address is provided, attempts to make the socket dual-stack so as to allow
    /// communication with both IPv4 and IPv6 addresses. As such, calling `Endpoint::client` with
    /// the address `[::]:0` is a reasonable default to maximize the ability to connect to other
    /// address. For example:
    ///
    /// ```
    /// noq::Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into());
    /// ```
    ///
    /// Some environments may not allow creation of dual-stack sockets, in which case an IPv6
    /// client will only be able to connect to IPv6 servers. An IPv4 client is never dual-stack.
    #[cfg(all(
        not(wasm_browser),
        any(feature = "runtime-tokio", feature = "runtime-smol"),
        any(feature = "aws-lc-rs", feature = "ring"), // `EndpointConfig::default()` is only available with these
    ))]
    pub fn client(addr: SocketAddr) -> io::Result<Self> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6()
            && let Err(e) = socket.set_only_v6(false)
        {
            tracing::debug!(%e, "unable to make socket dual-stack");
        }
        socket.bind(&addr.into())?;
        let runtime =
            default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            runtime.wrap_udp_socket(socket.into())?,
            runtime,
        )
    }

    /// Returns relevant stats from this Endpoint
    pub fn stats(&self) -> EndpointStats {
        self.inner.state.lock().unwrap().stats
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// If an IPv6 address is provided, attempts to make the socket dual-stack so as to allow
    /// communication with both IPv4 and IPv6 clients. As such, calling `Endpoint::server` with
    /// the address `[::]:0` is a reasonable default to maximize the ability to accept connections
    /// from any address.
    ///
    /// Some environments may not allow creation of dual-stack sockets, in which case an IPv6
    /// server will only be able to accept connections from IPv6 clients. An IPv4 server is never
    /// dual-stack.
    #[cfg(all(
        not(wasm_browser),
        any(feature = "runtime-tokio", feature = "runtime-smol"),
        any(feature = "aws-lc-rs", feature = "ring"), // `EndpointConfig::default()` is only available with these
    ))]
    pub fn server(config: ServerConfig, addr: SocketAddr) -> io::Result<Self> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if addr.is_ipv6()
            && let Err(e) = socket.set_only_v6(false)
        {
            tracing::debug!(%e, "unable to make socket dual-stack");
        }
        socket.bind(&addr.into())?;
        let runtime =
            default_runtime().ok_or_else(|| io::Error::other("no async runtime found"))?;
        Self::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(config),
            runtime.wrap_udp_socket(socket.into())?,
            runtime,
        )
    }

    /// Construct an endpoint with arbitrary configuration and socket
    #[cfg(not(wasm_browser))]
    pub fn new(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: std::net::UdpSocket,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        let socket = runtime.wrap_udp_socket(socket)?;
        Self::new_with_abstract_socket(config, server_config, socket, runtime)
    }

    /// Construct an endpoint with arbitrary configuration and pre-constructed abstract socket
    ///
    /// Useful when `socket` has additional state (e.g. sidechannels) attached for which shared
    /// ownership is needed.
    pub fn new_with_abstract_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Box<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        Self::new_with_multiple_sockets(config, server_config, vec![socket], runtime)
    }

    /// Construct an endpoint with arbitrary configuration and several pre-constructed sockets
    ///
    /// Each socket is received from by its own task. Outgoing datagrams go to the socket with the
    /// longest [`ip_ranges`](AsyncUdpSocket::ip_ranges) entry that contains the destination. If
    /// several ranges tie, the earlier socket wins. Datagrams that match no socket are dropped.
    ///
    /// If any socket is IPv6, the endpoint represents every remote address as IPv6. IPv4 sockets
    /// then see IPv4-mapped addresses from the endpoint and get plain IPv4 destinations on send.
    ///
    /// A socket whose `poll_recv` returns an error is removed from the endpoint and closed.
    /// Connections keep running over the remaining sockets. When the last socket fails, the
    /// endpoint stops with that error, as a single-socket endpoint always did. Sockets should
    /// therefore handle errors they consider transient themselves and only return the ones they
    /// consider final.
    pub fn new_with_multiple_sockets(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        sockets: Vec<Box<dyn AsyncUdpSocket>>,
        runtime: Arc<dyn Runtime>,
    ) -> io::Result<Self> {
        let sockets = EndpointSocket::new_all(sockets)?;
        let allow_mtud = sockets
            .iter()
            .all(|s| !s.socket.lock().unwrap().may_fragment());
        let rc = EndpointRef::new(
            sockets,
            proto::Endpoint::new(Arc::new(config), server_config.map(Arc::new), allow_mtud),
            runtime.clone(),
        );
        {
            let state = rc.state.lock().unwrap();
            for socket in &state.sockets {
                SocketDriver::spawn(&rc.0, &state, socket.clone());
            }
        }
        let driver = EndpointDriver(rc.clone());
        runtime.spawn(Box::pin(
            async {
                if let Err(e) = driver.await {
                    tracing::error!("I/O error: {}", e);
                }
            }
            .instrument(Span::current()),
        ));
        Ok(Self { inner: rc, runtime })
    }

    /// Get the next incoming connection attempt from a client
    ///
    /// Yields [`Incoming`]s, or `None` if the endpoint is [`close`](Self::close)d. [`Incoming`]
    /// can be `await`ed to obtain the final [`Connection`](crate::Connection), or used to e.g.
    /// filter connection attempts or force address validation, or converted into an intermediate
    /// `Connecting` future which can be used to e.g. send 0.5-RTT data.
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            endpoint: self,
            notify: self.inner.shared.incoming.notified(),
        }
    }

    /// Set the client configuration used by `connect`
    pub fn set_default_client_config(&self, config: ClientConfig) {
        self.inner.0.state.lock().unwrap().default_client_config = Some(config);
    }

    /// Connect to a remote endpoint
    ///
    /// `server_name` must be covered by the certificate presented by the server. This prevents a
    /// connection from being intercepted by an attacker with a valid certificate for some other
    /// server.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Connecting, ConnectError> {
        let Some(config) = self
            .inner
            .0
            .state
            .lock()
            .unwrap()
            .default_client_config
            .clone()
        else {
            return Err(ConnectError::NoDefaultClientConfig);
        };

        self.connect_with(config, addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// See [`connect()`] for details.
    ///
    /// [`connect()`]: Endpoint::connect
    pub fn connect_with(
        &self,
        config: ClientConfig,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectError> {
        let mut endpoint = self.inner.state.lock().unwrap();
        if endpoint.driver_lost || endpoint.recv_state.connections.close.is_some() {
            return Err(ConnectError::EndpointStopping);
        }
        if addr.is_ipv6() && !endpoint.ipv6 {
            return Err(ConnectError::InvalidRemoteAddress(addr));
        }
        let addr = if endpoint.ipv6 {
            SocketAddr::V6(ensure_ipv6(addr))
        } else {
            addr
        };

        let (ch, conn) = endpoint
            .inner
            .connect(self.runtime.now(), config, addr, server_name)?;

        let sender = endpoint.create_sender();
        endpoint.stats.outgoing_handshakes += 1;
        Ok(endpoint
            .recv_state
            .connections
            .insert(ch, conn, sender, self.runtime.clone()))
    }

    /// Switch to a new UDP socket
    ///
    /// See [`Endpoint::rebind_abstract()`] for details.
    #[cfg(not(wasm_browser))]
    pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        self.rebind_abstract(self.runtime.wrap_udp_socket(socket)?)
    }

    /// Switch to a new UDP socket
    ///
    /// Allows the endpoint's address to be updated live, affecting all active connections. Incoming
    /// connections and connections to servers unreachable from the new address will be lost.
    ///
    /// On error, the old UDP socket is retained.
    pub fn rebind_abstract(&self, socket: Box<dyn AsyncUdpSocket>) -> io::Result<()> {
        self.rebind_multiple_sockets(vec![socket])
    }

    /// Switch to a new set of UDP sockets
    ///
    /// Replaces all current sockets. See [`Endpoint::rebind_abstract()`] and
    /// [`Endpoint::new_with_multiple_sockets()`] for details.
    pub fn rebind_multiple_sockets(&self, sockets: Vec<Box<dyn AsyncUdpSocket>>) -> io::Result<()> {
        let sockets = EndpointSocket::new_all(sockets)?;
        let mut inner = self.inner.state.lock().unwrap();
        // Only one retired generation is kept, as before with `prev_socket`.
        for socket in inner.retired.drain(..) {
            socket.stop();
        }
        inner.retired = mem::replace(&mut inner.sockets, sockets);
        inner.ipv6 = inner.sockets.iter().any(|s| s.ipv6);
        inner.sender = inner.create_sender();
        for socket in &inner.sockets {
            SocketDriver::spawn(&self.inner.0, &inner, socket.clone());
        }

        // Update connection socket references
        for sender in inner.recv_state.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::Rebind(inner.create_sender()));
        }

        Ok(())
    }

    /// Notify connections that the local network address has changed.
    ///
    /// This informs all active connections that the local address may have changed (e.g., due to a
    /// network interface change), triggering liveness checks and recovery procedures on each
    /// connection without requiring a socket rebind.
    ///
    /// Unlike [`Self::rebind`], this does not change the underlying socket. Use this when the
    /// network topology changes but the socket remains valid (e.g., if bound to the unspecified
    /// address and switching from WiFi to cellular, or when the local IP address changes).
    ///
    /// The optional `hint` allows callers to indicate which paths may still be recoverable after
    /// the network change. If `None`, all paths are assumed to be non-recoverable. For client-side
    /// multipath connections, unrecoverable paths will be closed and replaced with new paths to
    /// the same remote addresses.
    pub fn handle_network_change(&self, hint: Option<Arc<dyn NetworkChangeHint + Sync + Send>>) {
        let mut inner = self.inner.state.lock().unwrap();
        for sender in inner.recv_state.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::LocalAddressChanged(hint.clone()));
        }
        if let Some(driver) = inner.driver.take() {
            driver.wake();
        }
    }

    /// Replace the server configuration, affecting new incoming connections only
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing connections.
    pub fn set_server_config(&self, server_config: Option<ServerConfig>) {
        self.inner
            .state
            .lock()
            .unwrap()
            .inner
            .set_server_config(server_config.map(Arc::new))
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    ///
    /// With several sockets, this is the address of the first one.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.state.lock().unwrap().sockets[0]
            .socket
            .lock()
            .unwrap()
            .local_addr()
    }

    /// Get the number of connections that are currently open
    pub fn open_connections(&self) -> usize {
        self.inner.state.lock().unwrap().inner.open_connections()
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut endpoint = self.inner.state.lock().unwrap();
        endpoint.recv_state.connections.close = Some((error_code, reason.clone()));
        for sender in endpoint.recv_state.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            });
        }
        self.inner.shared.incoming.notify_waiters();
        // Wake the endpoint driver so that it can shutdown if the endpoint is already drained.
        if let Some(waker) = endpoint.driver.take() {
            waker.wake();
        }
    }

    /// Waits for all connections on the endpoint to be cleanly shut down and drained.
    ///
    /// This is equivalent to [`wait_all_draining()`] with additionally waiting for the connections
    /// to be drained. Please see its documentation for more information.
    ///
    /// Use `wait_idle()` in favor of `wait_all_draining()` if you care about waiting for the
    /// [`Connection`] structs to be dropped.
    ///
    /// [`wait_all_draining()`]: Self::wait_all_draining
    /// [`Connection`]: crate::Connection
    pub async fn wait_idle(&self) {
        loop {
            {
                let endpoint = &mut *self.inner.state.lock().unwrap();
                if endpoint.recv_state.connections.is_empty() {
                    break;
                }
                // Construct future while lock is held to avoid race
                self.inner.shared.idle.notified()
            }
            .await;
        }
    }

    /// Waits for all connections on the endpoint to be ready for shutting down.
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to notify
    /// peers of recent connection closes, whereas exiting immediately could force them to wait out
    /// the idle timeout period.
    ///
    /// Does not proactively close existing connections or cause incoming connections to be
    /// rejected. Consider calling [`close()`] if that is desired.
    ///
    /// Unlike [`wait_idle()`], this doesn't wait for the full draining period, so it can't be
    /// used to wait for all now-idle [`Connection`]s to be dropped.
    ///
    /// See also this section in the QUIC RFC: <https://datatracker.ietf.org/doc/html/rfc9000#section-10.2-6>
    ///
    /// [`close()`]: Self::close
    /// [`wait_idle()`]: Self::wait_idle
    /// [`Connection`]: crate::Connection
    pub async fn wait_all_draining(&self) {
        loop {
            {
                let endpoint = &mut *self.inner.state.lock().unwrap();
                if endpoint.recv_state.connections.active_connections == 0 {
                    break;
                }
                // Construct future while lock is held to avoid race
                self.inner.shared.all_draining.notified()
            }
            .await;
        }
    }
}

/// Statistics on [Endpoint] activity
#[non_exhaustive]
#[derive(Debug, Default, Copy, Clone)]
pub struct EndpointStats {
    /// Cumulative number of Quic handshakes accepted by this [Endpoint]
    pub accepted_handshakes: u64,
    /// Cumulative number of Quic handshakes sent from this [Endpoint]
    pub outgoing_handshakes: u64,
    /// Cumulative number of Quic handshakes refused on this [Endpoint]
    pub refused_handshakes: u64,
    /// Cumulative number of Quic handshakes ignored on this [Endpoint]
    pub ignored_handshakes: u64,
}

/// A future that drives IO on an endpoint
///
/// This task functions as the switch point between the UDP socket object and the
/// `Endpoint` responsible for routing datagrams to their owning `Connection`.
/// In order to do so, it also facilitates the exchange of different types of events
/// flowing between the `Endpoint` and the tasks managing `Connection`s. As such,
/// running this task is necessary to keep the endpoint's connections running.
///
/// `EndpointDriver` futures terminate when all clones of the `Endpoint` have been dropped, or when
/// an I/O error occurs.
#[must_use = "endpoint drivers must be spawned for I/O to occur"]
#[derive(Debug)]
pub(crate) struct EndpointDriver(pub(crate) EndpointRef);

impl Future for EndpointDriver {
    type Output = Result<(), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut endpoint = self.0.state.lock().unwrap();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(cx.waker().clone());
        }

        // A receive error on a current socket ends the endpoint, as it did when the driver
        // received itself.
        if let Some(e) = endpoint.io_error.take() {
            return Poll::Ready(Err(e));
        }
        let keep_going = endpoint.handle_events(cx, &self.0.shared);

        // Stop the driver if either:
        // - all `Endpoint` structs are dropped and all connections are drained,
        // - or `Endpoint::close` has been called and all connections are drained.
        if endpoint.recv_state.connections.is_empty()
            && (self.0.shared.ref_count.load(Ordering::Relaxed) == 0
                || endpoint.recv_state.connections.close.is_some())
        {
            trace!("endpoint driver stopping");
            Poll::Ready(Ok(()))
        } else {
            drop(endpoint);
            // If there is more work to do schedule the endpoint task again.
            // `wake_by_ref()` is called outside the lock to minimize
            // lock contention on a multithreaded runtime.
            if keep_going {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        let mut endpoint = self.0.state.lock().unwrap();
        endpoint.driver_lost = true;
        for socket in endpoint.sockets.iter().chain(&endpoint.retired) {
            socket.stop();
        }
        self.0.shared.incoming.notify_waiters();
        // Drop all outgoing channels, signaling the termination of the endpoint to the associated
        // connections.
        endpoint.recv_state.connections.senders.clear();
        endpoint.recv_state.connections.active_connections = 0;
        // Wake callers waiting for the connection state cleared above.
        self.0.shared.all_draining.notify_waiters();
        self.0.shared.idle.notify_waiters();
    }
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

impl EndpointInner {
    pub(crate) fn accept(
        &self,
        incoming: proto::Incoming,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<Connecting, ConnectionError> {
        let mut state = self.state.lock().unwrap();
        let mut response_buffer = Vec::new();
        let now = state.runtime.now();
        match state
            .inner
            .accept(incoming, now, &mut response_buffer, server_config)
        {
            Ok((handle, conn)) => {
                state.stats.accepted_handshakes += 1;
                let sender = state.create_sender();
                let runtime = state.runtime.clone();
                Ok(state
                    .recv_state
                    .connections
                    .insert(handle, conn, sender, runtime))
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    respond(transmit, &response_buffer, &mut state.sender);
                }
                Err(error.cause)
            }
        }
    }

    pub(crate) fn refuse(&self, incoming: proto::Incoming) {
        let mut state = self.state.lock().unwrap();
        state.stats.refused_handshakes += 1;
        let mut response_buffer = Vec::new();
        let transmit = state.inner.refuse(incoming, &mut response_buffer);
        respond(transmit, &response_buffer, &mut state.sender);
    }

    pub(crate) fn retry(&self, incoming: proto::Incoming) -> Result<(), proto::RetryError> {
        let mut state = self.state.lock().unwrap();
        let mut response_buffer = Vec::new();
        let transmit = state.inner.retry(incoming, &mut response_buffer)?;
        respond(transmit, &response_buffer, &mut state.sender);
        Ok(())
    }

    pub(crate) fn ignore(&self, incoming: proto::Incoming) {
        let mut state = self.state.lock().unwrap();
        state.stats.ignored_handshakes += 1;
        state.inner.ignore(incoming);
    }
}

#[derive(Debug)]
pub(crate) struct State {
    /// The current sockets, each received from by its own [`SocketDriver`]
    sockets: Vec<Arc<EndpointSocket>>,
    /// Sender for endpoint-generated responses, routing to all current sockets
    sender: Pin<Box<dyn UdpSender>>,
    /// During an active migration, the retired sockets receive traffic
    /// until the first packet arrives on a new socket.
    retired: Vec<Arc<EndpointSocket>>,
    /// A fatal receive error reported by a [`SocketDriver`], picked up by the endpoint driver
    io_error: Option<io::Error>,
    inner: proto::Endpoint,
    recv_state: RecvState,
    driver: Option<Waker>,
    ipv6: bool,
    events: mpsc::UnboundedReceiver<(ConnectionHandle, EndpointEvent)>,
    driver_lost: bool,
    runtime: Arc<dyn Runtime>,
    stats: EndpointStats,
    default_client_config: Option<ClientConfig>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    /// Notifies subscribers of new incoming connections.
    ///
    /// This enables the `Endpoint::accept` API.
    incoming: Notify,
    /// Notifies subscribers when *all* connections have entered the draining state.
    ///
    /// This powers the `Endpoint::wait_idle` API.
    all_draining: Notify,
    /// Notifies subscribesr when *all* connections have been dropped.
    ///
    /// This powers the `Endpoint::wait_drained` API.
    idle: Notify,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: AtomicUsize,
}

impl State {
    /// Creates a sender that routes transmits to the current sockets
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        if let [socket] = &self.sockets[..] {
            // Keep the single-socket path free of routing.
            return socket.socket.lock().unwrap().create_sender();
        }
        Box::pin(RoutingSender::new(&self.sockets))
    }

    /// Returns whether `socket` is one of the current sockets, as opposed to a retired one
    fn is_current(&self, socket: &Arc<EndpointSocket>) -> bool {
        self.sockets.iter().any(|s| Arc::ptr_eq(s, socket))
    }

    /// Dispatches a batch of datagrams received on `socket`
    fn handle_datagrams(
        &mut self,
        socket: &Arc<EndpointSocket>,
        metas: &[RecvMeta],
        bufs: &[IoSliceMut<'_>],
        now: Instant,
    ) {
        let mut received_connection_packet = false;
        for (meta, buf) in metas.iter().zip(bufs) {
            let mut data: BytesMut = buf[0..meta.len].into();
            // Mirror the sender, which hands IPv4 sockets plain IPv4 destinations.
            let addr = if self.ipv6 {
                SocketAddr::V6(ensure_ipv6(meta.addr))
            } else {
                meta.addr
            };
            while !data.is_empty() {
                let buf = data.split_to(meta.stride.min(data.len()));
                let mut response_buffer = Vec::new();
                let addresses = FourTuple::new(addr, meta.dst_ip);
                match self.inner.handle(
                    now,
                    addresses,
                    meta.ecn.map(proto_ecn),
                    buf,
                    &mut response_buffer,
                ) {
                    Some(DatagramEvent::NewConnection(incoming)) => {
                        if self.recv_state.connections.close.is_none() {
                            self.recv_state.incoming.push_back(incoming);
                        } else {
                            let transmit = self.inner.refuse(incoming, &mut response_buffer);
                            respond(transmit, &response_buffer, &mut self.sender);
                        }
                    }
                    Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                        // Ignoring errors from dropped connections that haven't yet
                        // been cleaned up
                        received_connection_packet = true;
                        let _ = self
                            .recv_state
                            .connections
                            .senders
                            .get_mut(&handle)
                            .unwrap()
                            .send(ConnectionEvent::Proto(event));
                    }
                    Some(DatagramEvent::Response(transmit)) => {
                        respond(transmit, &response_buffer, &mut self.sender);
                    }
                    None => {}
                }
            }
        }
        if received_connection_packet && !self.retired.is_empty() && self.is_current(socket) {
            // Traffic has arrived on a current socket, therefore there is no need for the
            // retired ones anymore. TODO: Account for multiple outgoing connections.
            for socket in self.retired.drain(..) {
                socket.stop();
            }
        }
    }

    fn handle_events(&mut self, cx: &mut Context<'_>, shared: &Shared) -> bool {
        for _ in 0..IO_LOOP_BOUND {
            let (ch, event) = match self.events.poll_recv(cx) {
                Poll::Ready(Some(x)) => x,
                Poll::Ready(None) => unreachable!("EndpointInner owns one sender"),
                Poll::Pending => {
                    return false;
                }
            };

            if event.is_draining() {
                self.recv_state.connections.active_connections -= 1;
                if self.recv_state.connections.active_connections == 0 {
                    shared.all_draining.notify_waiters();
                }
            } else if event.is_drained() {
                self.recv_state.connections.senders.remove(&ch);
                if self.recv_state.connections.is_empty() {
                    shared.idle.notify_waiters();
                }
            }
            let Some(event) = self.inner.handle_event(ch, event) else {
                continue;
            };
            // Ignoring errors from dropped connections that haven't yet been cleaned up
            let _ = self
                .recv_state
                .connections
                .senders
                .get_mut(&ch)
                .unwrap()
                .send(ConnectionEvent::Proto(event));
        }

        true
    }
}

impl Drop for State {
    fn drop(&mut self) {
        for incoming in self.recv_state.incoming.drain(..) {
            self.inner.ignore(incoming);
        }
    }
}

fn respond(
    transmit: proto::Transmit,
    response_buffer: &[u8],
    sender: &mut Pin<Box<dyn UdpSender>>,
) {
    // Send if there's kernel buffer space; otherwise, drop it
    //
    // As an endpoint-generated packet, we know this is an
    // immediate, stateless response to an unconnected peer,
    // one of:
    //
    // - A version negotiation response due to an unknown version
    // - A `CLOSE` due to a malformed or unwanted connection attempt
    // - A stateless reset due to an unrecognized connection
    // - A `Retry` packet due to a connection attempt when `use_retry` is set
    //
    // In each case, a well-behaved peer can be trusted to retry a
    // few times, which is guaranteed to produce the same response
    // from us. Repeated failures might at worst cause a peer's new
    // connection attempt to time out, which is acceptable if we're
    // under such heavy load that there's never room for this code
    // to transmit. This is morally equivalent to the packet getting
    // lost due to congestion further along the link, which
    // similarly relies on peer retries for recovery.

    // Copied from rust 1.85's std::task::Waker::noop() implementation for backwards compatibility
    const NOOP: RawWaker = {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            // Cloning just returns a new no-op raw waker
            |_| NOOP,
            // `wake` does nothing
            |_| {},
            // `wake_by_ref` does nothing
            |_| {},
            // Dropping does nothing as we don't allocate anything
            |_| {},
        );
        RawWaker::new(std::ptr::null(), &VTABLE)
    };
    // SAFETY: Copied from rust stdlib, the NOOP waker is thread-safe and doesn't violate the
    // RawWakerVTable contract, it doesn't access the data pointer at all.
    let waker = unsafe { Waker::from_raw(NOOP) };
    let mut cx = Context::from_waker(&waker);
    _ = sender.as_mut().poll_send(
        &udp_transmit(&transmit, &response_buffer[..transmit.size]),
        &mut cx,
    );
}

#[inline]
fn proto_ecn(ecn: udp::EcnCodepoint) -> proto::EcnCodepoint {
    match ecn {
        udp::EcnCodepoint::Ect0 => proto::EcnCodepoint::Ect0,
        udp::EcnCodepoint::Ect1 => proto::EcnCodepoint::Ect1,
        udp::EcnCodepoint::Ce => proto::EcnCodepoint::Ce,
    }
}

#[derive(Debug)]
struct ConnectionSet {
    /// Senders for communicating with the endpoint's connections
    senders: FxHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>,
    /// Stored to give out clones to new ConnectionInners
    sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
    /// Counter for all active (non-draining/drained) connections.
    ///
    /// This is directly related to the QUIC connection states "Initial", "Handshake",
    /// "Established", "Closed", "Draining" and "Drained" (see also
    /// `proto/src/connection/state.rs`).
    ///
    /// Any connection state that is not "Draining" or "Drained" is considered active.
    ///
    /// This counter is updated when new connections are added ([`ConnectionSet::insert`]) and when
    /// a connection informs us about entering the draining state ([`State::handle_events`]).
    active_connections: u64,
}

impl ConnectionSet {
    fn insert(
        &mut self,
        handle: ConnectionHandle,
        conn: proto::Connection,
        sender: Pin<Box<dyn UdpSender>>,
        runtime: Arc<dyn Runtime>,
    ) -> Connecting {
        let (send, recv) = mpsc::unbounded_channel();
        if let Some((error_code, ref reason)) = self.close {
            send.send(ConnectionEvent::Close {
                error_code,
                reason: reason.clone(),
            })
            .unwrap();
        }
        self.senders.insert(handle, send);
        self.active_connections += 1;
        Connecting::new(handle, conn, self.sender.clone(), recv, sender, runtime)
    }

    fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }
}

pub(crate) fn ensure_ipv6(x: SocketAddr) -> SocketAddrV6 {
    match x {
        SocketAddr::V6(x) => x,
        SocketAddr::V4(x) => SocketAddrV6::new(x.ip().to_ipv6_mapped(), x.port(), 0, 0),
    }
}

pin_project! {
    /// Future produced by [`Endpoint::accept`]
    pub struct Accept<'a> {
        endpoint: &'a Endpoint,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for Accept<'_> {
    type Output = Option<Incoming>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut endpoint = this.endpoint.inner.state.lock().unwrap();
        if endpoint.driver_lost {
            return Poll::Ready(None);
        }
        if let Some(incoming) = endpoint.recv_state.incoming.pop_front() {
            // Release the mutex lock on endpoint so cloning it doesn't deadlock
            drop(endpoint);
            let incoming = Incoming::new(incoming, this.endpoint.inner.clone());
            return Poll::Ready(Some(incoming));
        }
        if endpoint.recv_state.connections.close.is_some() {
            return Poll::Ready(None);
        }
        loop {
            match this.notify.as_mut().poll(ctx) {
                // `state` lock ensures we didn't race with readiness
                Poll::Pending => return Poll::Pending,
                // Spurious wakeup, get a new future
                Poll::Ready(()) => this
                    .notify
                    .set(this.endpoint.inner.shared.incoming.notified()),
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct EndpointRef(Arc<EndpointInner>);

impl EndpointRef {
    pub(crate) fn new(
        sockets: Vec<Arc<EndpointSocket>>,
        inner: proto::Endpoint,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        let (sender, events) = mpsc::unbounded_channel();
        let recv_state = RecvState::new(sender);
        let mut state = State {
            sockets,
            // Replaced below, once `State::create_sender` can see the sockets.
            sender: Box::pin(RoutingSender::new(&[])),
            retired: Vec::new(),
            io_error: None,
            inner,
            ipv6: false,
            events,
            driver: None,
            driver_lost: false,
            recv_state,
            runtime,
            stats: EndpointStats::default(),
            default_client_config: None,
        };
        state.ipv6 = state.sockets.iter().any(|s| s.ipv6);
        state.sender = state.create_sender();
        Self(Arc::new(EndpointInner {
            shared: Shared {
                incoming: Notify::new(),
                all_draining: Notify::new(),
                idle: Notify::new(),
                ref_count: AtomicUsize::new(0),
            },
            state: Mutex::new(state),
        }))
    }
}

impl Clone for EndpointRef {
    fn clone(&self) -> Self {
        self.0.shared.ref_count.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

impl Drop for EndpointRef {
    fn drop(&mut self) {
        if self.0.shared.ref_count.fetch_sub(1, Ordering::Relaxed) > 1 {
            return;
        }

        let endpoint = &mut *self.0.state.lock().unwrap();
        // If the driver is about to be on its own, ensure it can shut down if the last
        // connection is gone.
        if let Some(task) = endpoint.driver.take() {
            task.wake();
        }
    }
}

impl std::ops::Deref for EndpointRef {
    type Target = EndpointInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// State directly involved in handling incoming packets
#[derive(Debug)]
struct RecvState {
    incoming: VecDeque<proto::Incoming>,
    connections: ConnectionSet,
}

impl RecvState {
    fn new(sender: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>) -> Self {
        Self {
            connections: ConnectionSet {
                senders: FxHashMap::default(),
                sender,
                close: None,
                active_connections: 0,
            },
            incoming: VecDeque::new(),
        }
    }
}

/// A socket of the endpoint, shared between [`State`] and the socket's [`SocketDriver`]
#[derive(Debug)]
pub(crate) struct EndpointSocket {
    /// Locked by the driver for `poll_recv` and by the state to create senders
    socket: Mutex<Box<dyn AsyncUdpSocket>>,
    /// Destination ranges this socket sends to, see [`AsyncUdpSocket::ip_ranges`]
    ranges: Vec<IpNet>,
    /// Whether the socket's local address is IPv6
    ipv6: bool,
    max_receive_segments: NonZeroUsize,
    /// Stop signal for the socket's [`SocketDriver`]
    recv: Mutex<RecvTask>,
}

/// The waker and stop flag of a [`SocketDriver`]
#[derive(Debug, Default)]
struct RecvTask {
    waker: Option<Waker>,
    stopped: bool,
}

impl EndpointSocket {
    fn new_all(sockets: Vec<Box<dyn AsyncUdpSocket>>) -> io::Result<Vec<Arc<Self>>> {
        if sockets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an endpoint needs at least one socket",
            ));
        }
        sockets
            .into_iter()
            .map(|socket| {
                Ok(Arc::new(Self {
                    ipv6: socket.local_addr()?.is_ipv6(),
                    ranges: socket.ip_ranges(),
                    max_receive_segments: socket.max_receive_segments(),
                    socket: Mutex::new(socket),
                    recv: Mutex::new(RecvTask::default()),
                }))
            })
            .collect()
    }

    /// Tells the socket's [`SocketDriver`] to exit
    fn stop(&self) {
        let mut recv = self.recv.lock().unwrap();
        recv.stopped = true;
        if let Some(waker) = recv.waker.take() {
            waker.wake();
        }
    }
}

/// A future that receives datagrams from one socket and feeds them to the endpoint
///
/// One of these runs per socket, so a socket that is not ready is simply not polled, and sockets
/// are received from in parallel on a multi-threaded runtime. The socket is polled without the
/// endpoint [`State`] lock. The lock is taken only to dispatch a received batch.
///
/// The driver exits when its socket is stopped, see [`EndpointSocket::stop`].
struct SocketDriver {
    endpoint: Arc<EndpointInner>,
    socket: Arc<EndpointSocket>,
    runtime: Arc<dyn Runtime>,
    recv_buf: Box<[u8]>,
    recv_limiter: WorkLimiter,
}

impl SocketDriver {
    fn spawn(endpoint: &Arc<EndpointInner>, state: &State, socket: Arc<EndpointSocket>) {
        let recv_buf = vec![
            0;
            state
                .inner
                .config()
                .get_max_udp_payload_size()
                .min(64 * 1024) as usize
                * socket.max_receive_segments.get()
                * BATCH_SIZE
        ];
        let driver = Self {
            endpoint: endpoint.clone(),
            socket,
            runtime: state.runtime.clone(),
            recv_buf: recv_buf.into(),
            recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),
        };
        state
            .runtime
            .spawn(Box::pin(driver.instrument(Span::current())));
    }

    /// Reports a receive error
    ///
    /// Removes the socket from the endpoint. If it was the last one, the endpoint ends with the
    /// error instead. A socket that was already retired by a rebind is simply dropped.
    fn fail(&self, e: io::Error) {
        let mut state = self.endpoint.state.lock().unwrap();
        if !state.is_current(&self.socket) {
            return;
        }
        if state.sockets.len() == 1 {
            state.io_error = Some(e);
            if let Some(driver) = state.driver.take() {
                driver.wake();
            }
            return;
        }
        tracing::warn!(error = %e, "socket failed to receive, removing it from the endpoint");
        state.sockets.retain(|s| !Arc::ptr_eq(s, &self.socket));
        state.sender = state.create_sender();
        for sender in state.recv_state.connections.senders.values() {
            // Ignoring errors from dropped connections
            let _ = sender.send(ConnectionEvent::ReplaceSender(state.create_sender()));
        }
    }
}

impl Future for SocketDriver {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        let get_time = || this.runtime.now();
        this.recv_limiter.start_cycle(get_time);
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        let mut iovs: [IoSliceMut<'_>; BATCH_SIZE] = {
            let mut bufs = this
                .recv_buf
                .chunks_mut(this.recv_buf.len() / BATCH_SIZE)
                .map(IoSliceMut::new);

            // expect() safe as self.recv_buf is chunked into BATCH_SIZE items
            // and iovs will be of size BATCH_SIZE, thus from_fn is called
            // exactly BATCH_SIZE times.
            std::array::from_fn(|_| bufs.next().expect("BATCH_SIZE elements"))
        };
        let result = loop {
            if this.socket.recv.lock().unwrap().stopped {
                break Poll::Ready(());
            }
            let poll = this
                .socket
                .socket
                .lock()
                .unwrap()
                .poll_recv(cx, &mut iovs, &mut metas);
            match poll {
                Poll::Ready(Ok(msgs)) => {
                    this.recv_limiter.record_work(msgs);
                    let now = this.runtime.now();
                    let mut state = this.endpoint.state.lock().unwrap();
                    if state.driver_lost {
                        // The endpoint driver stopped between our stop check and here, and
                        // the connection senders are gone.
                        break Poll::Ready(());
                    }
                    state.handle_datagrams(&this.socket, &metas[..msgs], &iovs[..msgs], now);
                    let has_incoming = !state.recv_state.incoming.is_empty();
                    drop(state);
                    if has_incoming {
                        this.endpoint.shared.incoming.notify_waiters();
                    }
                }
                Poll::Pending => {
                    let mut recv = this.socket.recv.lock().unwrap();
                    if recv.stopped {
                        break Poll::Ready(());
                    }
                    recv.waker = Some(cx.waker().clone());
                    break Poll::Pending;
                }
                // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
                // attacker
                Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    this.fail(e);
                    break Poll::Ready(());
                }
            }
            if !this.recv_limiter.allow_work(get_time) {
                // Yield for fairness and continue in the next poll.
                cx.waker().wake_by_ref();
                break Poll::Pending;
            }
        };
        this.recv_limiter.finish_cycle(get_time);
        result
    }
}

/// Returns whether `ip` is in `range`, treating IPv4-mapped addresses as IPv4
fn route_contains(range: &IpNet, ip: IpAddr) -> bool {
    match (range, ip) {
        (IpNet::V4(range), IpAddr::V6(ip)) => {
            ip.to_ipv4_mapped().is_some_and(|ip| range.contains(&ip))
        }
        (range, ip) => range.contains(&ip),
    }
}

/// A [`UdpSender`] that routes each transmit to the socket with the longest matching range
struct RoutingSender {
    /// Routes sorted by prefix length, longest first, each pointing into `senders`
    routes: Vec<(IpNet, usize)>,
    senders: Vec<Pin<Box<dyn UdpSender>>>,
    max_transmit_segments: NonZeroUsize,
}

impl RoutingSender {
    fn new(sockets: &[Arc<EndpointSocket>]) -> Self {
        let mut routes: Vec<_> = sockets
            .iter()
            .enumerate()
            .flat_map(|(i, s)| s.ranges.iter().map(move |r| (*r, i)))
            .collect();
        // Stable sort keeps the socket order for equal prefix lengths.
        routes.sort_by_key(|(range, _)| std::cmp::Reverse(range.prefix_len()));
        let senders: Vec<_> = sockets
            .iter()
            .map(|s| s.socket.lock().unwrap().create_sender())
            .collect();
        let max_transmit_segments = senders
            .iter()
            .map(|s| s.max_transmit_segments())
            .min()
            .unwrap_or(NonZeroUsize::MIN);
        Self {
            routes,
            senders,
            max_transmit_segments,
        }
    }
}

impl fmt::Debug for RoutingSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutingSender")
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

impl UdpSender for RoutingSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let destination = transmit.destination;
        let Some(&(range, index)) = this
            .routes
            .iter()
            .find(|(range, _)| route_contains(range, destination.ip()))
        else {
            // Like a failed sendmsg, this counts as loss and is left to QUIC to recover from.
            trace!(%destination, "no socket for destination, dropping transmit");
            return Poll::Ready(Ok(()));
        };
        let sender = this.senders[index].as_mut();
        // An IPv4 socket gets a plain IPv4 destination, see `Endpoint::new_with_multiple_sockets`.
        if let (IpAddr::V4(_), IpAddr::V6(ip)) = (range.addr(), destination.ip())
            && let Some(ip) = ip.to_ipv4_mapped()
        {
            let transmit = udp::Transmit {
                destination: SocketAddr::new(ip.into(), destination.port()),
                ..transmit.clone()
            };
            return sender.poll_send(&transmit, cx);
        }
        sender.poll_send(transmit, cx)
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.max_transmit_segments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_contains_maps_ipv4() {
        let v4: IpNet = "10.0.0.0/8".parse().unwrap();
        let v6: IpNet = "fd15:70a:510b:1::/64".parse().unwrap();
        assert!(route_contains(&v4, "10.1.2.3".parse().unwrap()));
        assert!(route_contains(&v4, "::ffff:10.1.2.3".parse().unwrap()));
        assert!(!route_contains(&v4, "11.1.2.3".parse().unwrap()));
        assert!(!route_contains(&v4, "fd15:70a:510b:1::1".parse().unwrap()));
        assert!(route_contains(&v6, "fd15:70a:510b:1::1".parse().unwrap()));
        assert!(!route_contains(&v6, "fd15:70a:510b:2::1".parse().unwrap()));
        assert!(!route_contains(&v6, "10.1.2.3".parse().unwrap()));
    }
}
