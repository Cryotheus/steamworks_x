//! Types that are used by both [`networking_sockets`](../networking_sockets) and [`networking_messages`](../networking_messages).
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::networking_sockets::{InnerSocket, NetConnection};
use crate::networking_types::NetConnectionError::UnhandledType;
use crate::{Callback, Inner, SResult, SteamId};
use std::convert::{TryFrom, TryInto};
use std::ffi::{c_void, CString};
use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::panic::catch_unwind;
use std::sync::Arc;
use steamworks_x_sys as sys;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MessageNumber(pub(crate) u64);

impl From<MessageNumber> for u64 {
	fn from(number: MessageNumber) -> Self {
		number.0
	}
}

bitflags! {
	#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
	#[repr(C)]
	pub struct SendFlags: i32 {
		const UNRELIABLE = sys::k_nSteamNetworkingSend_Unreliable;
		const NO_NAGLE = sys::k_nSteamNetworkingSend_NoNagle;
		const UNRELIABLE_NO_NAGLE = sys::k_nSteamNetworkingSend_UnreliableNoNagle;
		const NO_DELAY = sys::k_nSteamNetworkingSend_NoDelay;
		const UNRELIABLE_NO_DELAY = sys::k_nSteamNetworkingSend_UnreliableNoDelay;
		const RELIABLE = sys::k_nSteamNetworkingSend_Reliable;
		const RELIABLE_NO_NAGLE = sys::k_nSteamNetworkingSend_ReliableNoNagle;
		const USE_CURRENT_THREAD = sys::k_nSteamNetworkingSend_UseCurrentThread;
		const AUTO_RESTART_BROKEN_SESSION = sys::k_nSteamNetworkingSend_AutoRestartBrokenSession;
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NetworkingConfigDataType {
	Int32,
	Int64,
	Float,
	String,
	Callback,
}

impl From<NetworkingConfigDataType> for sys::ESteamNetworkingConfigDataType {
	fn from(ty: NetworkingConfigDataType) -> sys::ESteamNetworkingConfigDataType {
		match ty {
			NetworkingConfigDataType::Int32 => sys::ESteamNetworkingConfigDataType::k_ESteamNetworkingConfig_Int32,
			NetworkingConfigDataType::Int64 => sys::ESteamNetworkingConfigDataType::k_ESteamNetworkingConfig_Int64,
			NetworkingConfigDataType::Float => sys::ESteamNetworkingConfigDataType::k_ESteamNetworkingConfig_Float,
			NetworkingConfigDataType::String => sys::ESteamNetworkingConfigDataType::k_ESteamNetworkingConfig_String,
			NetworkingConfigDataType::Callback => sys::ESteamNetworkingConfigDataType::k_ESteamNetworkingConfig_Ptr,
		}
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NetworkingConfigValue {
	CallbackAuthStatusChanged = 202,
	CallbackConnectionStatusChanged = 201,
	CallbackCreateConnectionSignaling = 206,
	CallbackFakeIPResult = 207,
	CallbackMessagesSessionFailed = 205,
	CallbackMessagesSessionRequest = 204,
	CallbackRelayNetworkStatusChanged = 203,
	ConnectionUserData = 40,
	DualWifiEnable = 39,
	Ecn = 999,
	EnableDiagnosticsUI = 46,
	FakePacketDupRecv = 27,
	FakePacketDupSend = 26,
	FakePacketDupTimeMax = 28,
	FakePacketLagRecv = 5,
	FakePacketLagSend = 4,
	FakePacketLossRecv = 3,
	FakePacketLossSend = 2,
	FakePacketReorderRecv = 7,
	FakePacketReorderSend = 6,
	FakePacketReorderTime = 8,
	FakeRateLimitRecvBurst = 45,
	FakeRateLimitRecvRate = 44,
	FakeRateLimitSendBurst = 43,
	FakeRateLimitSendRate = 42,
	IpAllowWithoutAuth = 23,
	LocalVirtualPort = 38,
	LogLevelAckRtt = 13,
	LogLevelMessage = 15,
	LogLevelP2pRendezvous = 17,
	LogLevelPacketDecode = 14,
	LogLevelPacketGaps = 16,
	LogLevelSdrRelayPings = 18,
	MtuDataSize = 33,
	MtuPacketSize = 32,
	NagleTime = 12,
	OutOfOrderCorrectionWindowMicroseconds = 51,
	P2pStunServerList = 103,
	P2pTransportIceEnable = 104,
	P2pTransportIceImplementation = 110,
	P2pTransportIcePenalty = 105,
	P2pTransportSdrPenalty = 106,
	P2pTurnPassList = 109,
	P2pTurnServerList = 107,
	P2pTurnUserList = 108,
	PacketTraceMaxBytes = 41,
	RecvBufferMessages = 48,
	RecvBufferSize = 47,
	RecvMaxMessageSize = 49,
	RecvMaxSegmentsPerPacket = 50,
	SdrClientConsecutitivePingTimeoutsFail = 20,
	SdrClientConsecutitivePingTimeoutsFailInitial = 19,
	SdrClientDevTicket = 30,
	SdrClientFakeClusterPing = 36,
	SdrClientForceProxyAddr = 31,
	SdrClientForceRelayCluster = 29,
	SdrClientLimitPingProbesToNearestN = 60,
	SdrClientMinPingsBeforePingAccurate = 21,
	SdrClientSingleSocket = 22,
	SendBufferSize = 9,
	SendRateMax = 11,
	SendRateMin = 10,
	SymmetricConnect = 37,
	TimeoutConnected = 25,
	TimeoutInitial = 24,
	Unencrypted = 34,
}

impl NetworkingConfigValue {
	pub fn data_type(&self) -> NetworkingConfigDataType {
		use NetworkingConfigDataType::*;
		use NetworkingConfigValue::*;

		match self {
			CallbackAuthStatusChanged => Callback,
			CallbackConnectionStatusChanged => Callback,
			CallbackCreateConnectionSignaling => Callback,
			CallbackFakeIPResult => Callback,
			CallbackMessagesSessionFailed => Callback,
			CallbackMessagesSessionRequest => Callback,
			CallbackRelayNetworkStatusChanged => Callback,
			ConnectionUserData => Int64,
			DualWifiEnable => Int32,
			Ecn => Int32,
			EnableDiagnosticsUI => Int32,
			FakePacketDupRecv => Float,
			FakePacketDupSend => Float,
			FakePacketDupTimeMax => Int32,
			FakePacketLagRecv => Int32,
			FakePacketLagSend => Int32,
			FakePacketLossRecv => Float,
			FakePacketLossSend => Float,
			FakePacketReorderRecv => Float,
			FakePacketReorderSend => Float,
			FakePacketReorderTime => Int32,
			FakeRateLimitRecvBurst => Int32,
			FakeRateLimitRecvRate => Int32,
			FakeRateLimitSendBurst => Int32,
			FakeRateLimitSendRate => Int32,
			IpAllowWithoutAuth => Int32,
			LocalVirtualPort => Int32,
			LogLevelAckRtt => Int32,
			LogLevelMessage => Int32,
			LogLevelP2pRendezvous => Int32,
			LogLevelPacketDecode => Int32,
			LogLevelPacketGaps => Int32,
			LogLevelSdrRelayPings => Int32,
			MtuDataSize => Int32,
			MtuPacketSize => Int32,
			NagleTime => Int32,
			OutOfOrderCorrectionWindowMicroseconds => Int32,
			P2pStunServerList => String,
			P2pTransportIceEnable => Int32,
			P2pTransportIceImplementation => Int32,
			P2pTransportIcePenalty => Int32,
			P2pTransportSdrPenalty => Int32,
			P2pTurnPassList => Int32,
			P2pTurnServerList => Int32,
			P2pTurnUserList => Int32,
			PacketTraceMaxBytes => Int32,
			RecvBufferMessages => Int32,
			RecvBufferSize => Int32,
			RecvMaxMessageSize => Int32,
			RecvMaxSegmentsPerPacket => Int32,
			SdrClientConsecutitivePingTimeoutsFail => Int32,
			SdrClientConsecutitivePingTimeoutsFailInitial => Int32,
			SdrClientDevTicket => String,
			SdrClientFakeClusterPing => String,
			SdrClientForceProxyAddr => String,
			SdrClientForceRelayCluster => String,
			SdrClientLimitPingProbesToNearestN => Int32,
			SdrClientMinPingsBeforePingAccurate => Int32,
			SdrClientSingleSocket => Int32,
			SendBufferSize => Int32,
			SendRateMax => Int32,
			SendRateMin => Int32,
			SymmetricConnect => Int32,
			TimeoutConnected => Int32,
			TimeoutInitial => Int32,
			Unencrypted => Int32,
		}
	}
}

impl From<NetworkingConfigValue> for sys::ESteamNetworkingConfigValue {
	fn from(value: NetworkingConfigValue) -> steamworks_x_sys::ESteamNetworkingConfigValue {
		use sys::ESteamNetworkingConfigValue::*;
		use NetworkingConfigValue::*;

		match value {
			CallbackAuthStatusChanged => k_ESteamNetworkingConfig_Callback_AuthStatusChanged,
			CallbackConnectionStatusChanged => k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged,
			CallbackCreateConnectionSignaling => k_ESteamNetworkingConfig_Callback_CreateConnectionSignaling,
			CallbackFakeIPResult => k_ESteamNetworkingConfig_Callback_FakeIPResult,
			CallbackMessagesSessionFailed => k_ESteamNetworkingConfig_Callback_MessagesSessionFailed,
			CallbackMessagesSessionRequest => k_ESteamNetworkingConfig_Callback_MessagesSessionRequest,
			CallbackRelayNetworkStatusChanged => k_ESteamNetworkingConfig_Callback_RelayNetworkStatusChanged,
			ConnectionUserData => k_ESteamNetworkingConfig_ConnectionUserData,
			DualWifiEnable => k_ESteamNetworkingConfig_DualWifi_Enable,
			Ecn => k_ESteamNetworkingConfig_ECN,
			EnableDiagnosticsUI => k_ESteamNetworkingConfig_EnableDiagnosticsUI,
			FakePacketDupRecv => k_ESteamNetworkingConfig_FakePacketDup_Recv,
			FakePacketDupSend => k_ESteamNetworkingConfig_FakePacketDup_Send,
			FakePacketDupTimeMax => k_ESteamNetworkingConfig_FakePacketDup_TimeMax,
			FakePacketLagRecv => k_ESteamNetworkingConfig_FakePacketLag_Recv,
			FakePacketLagSend => k_ESteamNetworkingConfig_FakePacketLag_Send,
			FakePacketLossRecv => k_ESteamNetworkingConfig_FakePacketLoss_Recv,
			FakePacketLossSend => k_ESteamNetworkingConfig_FakePacketLoss_Send,
			FakePacketReorderRecv => k_ESteamNetworkingConfig_FakePacketReorder_Recv,
			FakePacketReorderSend => k_ESteamNetworkingConfig_FakePacketReorder_Send,
			FakePacketReorderTime => k_ESteamNetworkingConfig_FakePacketReorder_Time,
			FakeRateLimitRecvBurst => k_ESteamNetworkingConfig_FakeRateLimit_Recv_Burst,
			FakeRateLimitRecvRate => k_ESteamNetworkingConfig_FakeRateLimit_Recv_Rate,
			FakeRateLimitSendBurst => k_ESteamNetworkingConfig_FakeRateLimit_Send_Burst,
			FakeRateLimitSendRate => k_ESteamNetworkingConfig_FakeRateLimit_Send_Rate,
			IpAllowWithoutAuth => k_ESteamNetworkingConfig_IP_AllowWithoutAuth,
			LocalVirtualPort => k_ESteamNetworkingConfig_LocalVirtualPort,
			LogLevelAckRtt => k_ESteamNetworkingConfig_LogLevel_AckRTT,
			LogLevelMessage => k_ESteamNetworkingConfig_LogLevel_Message,
			LogLevelP2pRendezvous => k_ESteamNetworkingConfig_LogLevel_P2PRendezvous,
			LogLevelPacketDecode => k_ESteamNetworkingConfig_LogLevel_PacketDecode,
			LogLevelPacketGaps => k_ESteamNetworkingConfig_LogLevel_PacketGaps,
			LogLevelSdrRelayPings => k_ESteamNetworkingConfig_LogLevel_SDRRelayPings,
			MtuDataSize => k_ESteamNetworkingConfig_MTU_DataSize,
			MtuPacketSize => k_ESteamNetworkingConfig_MTU_PacketSize,
			NagleTime => k_ESteamNetworkingConfig_NagleTime,
			OutOfOrderCorrectionWindowMicroseconds => k_ESteamNetworkingConfig_OutOfOrderCorrectionWindowMicroseconds,
			P2pStunServerList => k_ESteamNetworkingConfig_P2P_STUN_ServerList,
			P2pTransportIceEnable => k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable,
			P2pTransportIceImplementation => k_ESteamNetworkingConfig_P2P_Transport_ICE_Implementation,
			P2pTransportIcePenalty => k_ESteamNetworkingConfig_P2P_Transport_ICE_Penalty,
			P2pTransportSdrPenalty => k_ESteamNetworkingConfig_P2P_Transport_SDR_Penalty,
			P2pTurnPassList => k_ESteamNetworkingConfig_P2P_TURN_PassList,
			P2pTurnServerList => k_ESteamNetworkingConfig_P2P_TURN_ServerList,
			P2pTurnUserList => k_ESteamNetworkingConfig_P2P_TURN_UserList,
			PacketTraceMaxBytes => k_ESteamNetworkingConfig_PacketTraceMaxBytes,
			RecvBufferMessages => k_ESteamNetworkingConfig_RecvBufferMessages,
			RecvBufferSize => k_ESteamNetworkingConfig_RecvBufferSize,
			RecvMaxMessageSize => k_ESteamNetworkingConfig_RecvMaxMessageSize,
			RecvMaxSegmentsPerPacket => k_ESteamNetworkingConfig_RecvMaxSegmentsPerPacket,
			SdrClientConsecutitivePingTimeoutsFail => k_ESteamNetworkingConfig_SDRClient_ConsecutitivePingTimeoutsFail,
			SdrClientConsecutitivePingTimeoutsFailInitial => k_ESteamNetworkingConfig_SDRClient_ConsecutitivePingTimeoutsFailInitial,
			SdrClientDevTicket => k_ESteamNetworkingConfig_SDRClient_DevTicket,
			SdrClientFakeClusterPing => k_ESteamNetworkingConfig_SDRClient_FakeClusterPing,
			SdrClientForceProxyAddr => k_ESteamNetworkingConfig_SDRClient_ForceProxyAddr,
			SdrClientForceRelayCluster => k_ESteamNetworkingConfig_SDRClient_ForceRelayCluster,
			SdrClientLimitPingProbesToNearestN => k_ESteamNetworkingConfig_SDRClient_LimitPingProbesToNearestN,
			SdrClientMinPingsBeforePingAccurate => k_ESteamNetworkingConfig_SDRClient_MinPingsBeforePingAccurate,
			SdrClientSingleSocket => k_ESteamNetworkingConfig_SDRClient_SingleSocket,
			SendBufferSize => k_ESteamNetworkingConfig_SendBufferSize,
			SendRateMax => k_ESteamNetworkingConfig_SendRateMax,
			SendRateMin => k_ESteamNetworkingConfig_SendRateMin,
			SymmetricConnect => k_ESteamNetworkingConfig_SymmetricConnect,
			TimeoutConnected => k_ESteamNetworkingConfig_TimeoutConnected,
			TimeoutInitial => k_ESteamNetworkingConfig_TimeoutInitial,
			Unencrypted => k_ESteamNetworkingConfig_Unencrypted,
		}
	}
}

/// High level connection status
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NetworkingConnectionState {
	/// Dummy value used to indicate an error condition in the API.
	/// Specified connection doesn't exist or has already been closed.
	None,
	/// We are trying to establish whether peers can talk to each other,
	/// whether they WANT to talk to each other, perform basic auth,
	/// and exchange crypt keys.
	///
	/// - For connections on the "client" side (initiated locally):
	///   We're in the process of trying to establish a connection.
	///   Depending on the connection type, we might not know who they are.
	///   Note that it is not possible to tell if we are waiting on the
	///   network to complete handshake packets, or for the application layer
	///   to accept the connection.
	///
	/// - For connections on the "server" side (accepted through listen socket):
	///   We have completed some basic handshake and the client has presented
	///   some proof of identity.  The connection is ready to be accepted
	///   using AcceptConnection().
	///
	/// In either case, any unreliable packets sent now are almost certain
	/// to be dropped.  Attempts to receive packets are guaranteed to fail.
	/// You may send messages if the send mode allows for them to be queued.
	/// but if you close the connection before the connection is actually
	/// established, any queued messages will be discarded immediately.
	/// (We will not attempt to flush the queue and confirm delivery to the
	/// remote host, which ordinarily happens when a connection is closed.)
	Connecting,
	/// Some connection types use a back channel or trusted 3rd party
	/// for earliest communication.  If the server accepts the connection,
	/// then these connections switch into the rendezvous state.  During this
	/// state, we still have not yet established an end-to-end route (through
	/// the relay network), and so if you send any messages unreliable, they
	/// are going to be discarded.
	FindingRoute,
	/// We've received communications from our peer (and we know
	/// who they are) and are all good.  If you close the connection now,
	/// we will make our best effort to flush out any reliable sent data that
	/// has not been acknowledged by the peer.  (But note that this happens
	/// from within the application process, so unlike a TCP connection, you are
	/// not totally handing it off to the operating system to deal with it.)
	Connected,
	/// Connection has been closed by our peer, but not closed locally.
	/// The connection still exists from an API perspective.  You must close the
	/// handle to free up resources.  If there are any messages in the inbound queue,
	/// you may retrieve them.  Otherwise, nothing may be done with the connection
	/// except to close it.
	///
	/// This stats is similar to CLOSE_WAIT in the TCP state machine.
	ClosedByPeer,
	/// A disruption in the connection has been detected locally.  (E.g. timeout,
	/// local internet connection disrupted, etc.)
	///
	/// The connection still exists from an API perspective.  You must close the
	/// handle to free up resources.
	///
	/// Attempts to send further messages will fail.  Any remaining received messages
	/// in the queue are available.
	ProblemDetectedLocally,
}

impl From<NetworkingConnectionState> for sys::ESteamNetworkingConnectionState {
	fn from(state: NetworkingConnectionState) -> Self {
		match state {
			NetworkingConnectionState::None => sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_None,
			NetworkingConnectionState::Connecting => sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_Connecting,
			NetworkingConnectionState::FindingRoute => sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_FindingRoute,
			NetworkingConnectionState::Connected => sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_Connected,
			NetworkingConnectionState::ClosedByPeer => sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_ClosedByPeer,
			NetworkingConnectionState::ProblemDetectedLocally => {
				sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_ProblemDetectedLocally
			}
		}
	}
}

impl TryFrom<sys::ESteamNetworkingConnectionState> for NetworkingConnectionState {
	type Error = InvalidConnectionState;

	fn try_from(state: sys::ESteamNetworkingConnectionState) -> Result<Self, Self::Error> {
		match state {
			sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_None => Ok(NetworkingConnectionState::None),
			sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_Connecting => Ok(NetworkingConnectionState::Connecting),
			sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_FindingRoute => Ok(NetworkingConnectionState::FindingRoute),
			sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_Connected => Ok(NetworkingConnectionState::Connected),
			sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_ClosedByPeer => Ok(NetworkingConnectionState::ClosedByPeer),
			sys::ESteamNetworkingConnectionState::k_ESteamNetworkingConnectionState_ProblemDetectedLocally => {
				Ok(NetworkingConnectionState::ProblemDetectedLocally)
			}
			_ => Err(InvalidConnectionState),
		}
	}
}

#[derive(Debug, Error)]
#[error("Invalid state")]
pub struct InvalidConnectionState;

/// Enumerate various causes of connection termination.  These are designed to work similar
/// to HTTP error codes: the numeric range gives you a rough classification as to the source
/// of the problem.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NetConnectionEnd {
	//
	// Application codes.  These are the values you will pass to
	// ISteamNetworkingSockets::CloseConnection.  You can use these codes if
	// you want to plumb through application-specific reason codes.  If you don't
	// need this facility, feel free to always pass
	// k_ESteamNetConnectionEnd_App_Generic.
	//
	// The distinction between "normal" and "exceptional" termination is
	// one you may use if you find useful, but it's not necessary for you
	// to do so.  The only place where we distinguish between normal and
	// exceptional is in connection analytics.  If a significant
	// proportion of connections terminates in an exceptional manner,
	// this can trigger an alert.
	//

	// 1xxx: Application ended the connection in a "usual" manner.
	//       E.g.: user intentionally disconnected from the server,
	//             gameplay ended normally, etc
	AppGeneric,

	// 2xxx: Application ended the connection in some sort of exceptional
	//       or unusual manner that might indicate a bug or configuration
	//       issue.
	//
	AppException,

	//
	// System codes.  These will be returned by the system when
	// the connection state is k_ESteamNetworkingConnectionState_ClosedByPeer
	// or k_ESteamNetworkingConnectionState_ProblemDetectedLocally.  It is
	// illegal to pass a code in this range to ISteamNetworkingSockets::CloseConnection
	//

	// You cannot do what you want to do because you're running in offline mode.
	LocalOfflineMode,

	// We're having trouble contacting many (perhaps all) relays.
	// Since it's unlikely that they all went offline at once, the best
	// explanation is that we have a problem on our end.  Note that we don't
	// bother distinguishing between "many" and "all", because in practice,
	// it takes time to detect a connection problem, and by the time
	// the connection has timed out, we might not have been able to
	// actively probe all of the relay clusters, even if we were able to
	// contact them at one time.  So this code just means that:
	//
	// * We don't have any recent successful communication with any relay.
	// * We have evidence of recent failures to communicate with multiple relays.
	LocalManyRelayConnectivity,

	// A hosted server is having trouble talking to the relay
	// that the client was using, so the problem is most likely
	// on our end
	LocalHostedServerPrimaryRelay,

	// We're not able to get the SDR network config.  This is
	// *almost* always a local issue, since the network config
	// comes from the CDN, which is pretty darn reliable.
	LocalNetworkConfig,

	// Steam rejected our request because we don't have rights
	// to do this.
	LocalRights,

	// ICE P2P rendezvous failed because we were not able to
	// determine our "public" address (e.g. reflexive address via STUN)
	//
	// If relay fallback is available (it always is on Steam), then
	// this is only used internally and will not be returned as a high
	// level failure.
	LocalP2pICENoPublicAddresses,

	// 4xxx: Connection failed or ended, and it appears that the
	//       cause does NOT have to do with the local host or their
	//       connection to the Internet.  It could be caused by the
	//       remote host, or it could be somewhere in between.

	// The connection was lost, and as far as we can tell our connection
	// to relevant services (relays) has not been disrupted.  This doesn't
	// mean that the problem is "their fault", it just means that it doesn't
	// appear that we are having network issues on our end.
	RemoteTimeout,

	// Something was invalid with the cert or crypt handshake
	// info you gave me, I don't understand or like your key types,
	// etc.
	RemoteBadEncrypt,

	// You presented me with a cert that was I was able to parse
	// and *technically* we could use encrypted communication.
	// But there was a problem that prevents me from checking your identity
	// or ensuring that somebody int he middle can't observe our communication.
	// E.g.: - the CA key was missing (and I don't accept unsigned certs)
	// - The CA key isn't one that I trust,
	// - The cert doesn't was appropriately restricted by app, user, time, data center, etc.
	// - The cert wasn't issued to you.
	// - etc
	RemoteBadCert,

	// Something wrong with the protocol version you are using.
	// (Probably the code you are running is too old.)
	RemoteBadProtocolVersion,

	// NAT punch failed failed because we never received any public
	// addresses from the remote host.  (But we did receive some
	// signals form them.)
	//
	// If relay fallback is available (it always is on Steam), then
	// this is only used internally and will not be returned as a high
	// level failure.
	RemoteP2pICENoPublicAddresses,

	// A failure that isn't necessarily the result of a software bug,
	// but that should happen rarely enough that it isn't worth specifically
	// writing UI or making a localized message for.
	// The debug string should contain further details.
	MiscGeneric,

	// Generic failure that is most likely a software bug.
	MiscInternalError,

	// The connection to the remote host timed out, but we
	// don't know if the problem is on our end, in the middle,
	// or on their end.
	MiscTimeout,

	// There's some trouble talking to Steam.
	MiscSteamConnectivity,

	// A server in a dedicated hosting situation has no relay sessions
	// active with which to talk back to a client.  (It's the client's
	// job to open and maintain those sessions.)
	MiscNoRelaySessionsToClient,

	// While trying to initiate a connection, we never received
	// *any* communication from the peer.
	//k_ESteamNetConnectionEnd_Misc_ServerNeverReplied = 5007,

	// P2P rendezvous failed in a way that we don't have more specific
	// information
	MiscP2pRendezvous,

	// NAT punch failed, probably due to NAT/firewall configuration.
	//
	// If relay fallback is available (it always is on Steam), then
	// this is only used internally and will not be returned as a high
	// level failure.
	MiscP2pNatFirewall,

	// Our peer replied that it has no record of the connection.
	// This should not happen ordinarily, but can happen in a few
	// exception cases:
	//
	// - This is an old connection, and the peer has already cleaned
	//   up and forgotten about it.  (Perhaps it timed out and they
	//   closed it and were not able to communicate this to us.)
	// - A bug or internal protocol error has caused us to try to
	//   talk to the peer about the connection before we received
	//   confirmation that the peer has accepted the connection.
	// - The peer thinks that we have closed the connection for some
	//   reason (perhaps a bug), and believes that is it is
	//   acknowledging our closure.
	MiscPeerSentNoConnection,
}

impl From<NetConnectionEnd> for sys::ESteamNetConnectionEnd {
	fn from(end: NetConnectionEnd) -> Self {
		match end {
			NetConnectionEnd::AppGeneric => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_App_Generic,
			NetConnectionEnd::AppException => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_AppException_Generic,
			NetConnectionEnd::LocalOfflineMode => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_OfflineMode,
			NetConnectionEnd::LocalManyRelayConnectivity => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_ManyRelayConnectivity,
			NetConnectionEnd::LocalHostedServerPrimaryRelay => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_HostedServerPrimaryRelay,
			NetConnectionEnd::LocalNetworkConfig => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_NetworkConfig,
			NetConnectionEnd::LocalRights => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_Rights,
			NetConnectionEnd::LocalP2pICENoPublicAddresses => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_P2P_ICE_NoPublicAddresses,
			NetConnectionEnd::RemoteTimeout => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_Timeout,
			NetConnectionEnd::RemoteBadEncrypt => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_BadCrypt,
			NetConnectionEnd::RemoteBadCert => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_BadCert,
			NetConnectionEnd::RemoteBadProtocolVersion => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_BadProtocolVersion,
			NetConnectionEnd::RemoteP2pICENoPublicAddresses => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_P2P_ICE_NoPublicAddresses,
			NetConnectionEnd::MiscGeneric => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_Generic,
			NetConnectionEnd::MiscInternalError => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_InternalError,
			NetConnectionEnd::MiscTimeout => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_Timeout,
			NetConnectionEnd::MiscSteamConnectivity => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_SteamConnectivity,
			NetConnectionEnd::MiscNoRelaySessionsToClient => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_NoRelaySessionsToClient,
			NetConnectionEnd::MiscP2pRendezvous => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_P2P_Rendezvous,
			NetConnectionEnd::MiscP2pNatFirewall => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_P2P_NAT_Firewall,
			NetConnectionEnd::MiscPeerSentNoConnection => sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_PeerSentNoConnection,
		}
	}
}

impl From<NetConnectionEnd> for i32 {
	fn from(end: NetConnectionEnd) -> Self {
		sys::ESteamNetConnectionEnd::from(end) as i32
	}
}

impl TryFrom<i32> for NetConnectionEnd {
	type Error = InvalidEnumValue;
	fn try_from(end: i32) -> Result<Self, Self::Error> {
		match end {
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_App_Generic as i32 => Ok(NetConnectionEnd::AppGeneric),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_AppException_Generic as i32 => Ok(NetConnectionEnd::AppException),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_OfflineMode as i32 => Ok(NetConnectionEnd::LocalOfflineMode),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_ManyRelayConnectivity as i32 => {
				Ok(NetConnectionEnd::LocalManyRelayConnectivity)
			}
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_HostedServerPrimaryRelay as i32 => {
				Ok(NetConnectionEnd::LocalHostedServerPrimaryRelay)
			}
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_NetworkConfig as i32 => {
				Ok(NetConnectionEnd::LocalNetworkConfig)
			}
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_Rights as i32 => Ok(NetConnectionEnd::LocalRights),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_P2P_ICE_NoPublicAddresses as i32 => {
				Ok(NetConnectionEnd::LocalP2pICENoPublicAddresses)
			}
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_Timeout as i32 => Ok(NetConnectionEnd::RemoteTimeout),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_BadCrypt as i32 => Ok(NetConnectionEnd::RemoteBadEncrypt),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_BadCert as i32 => Ok(NetConnectionEnd::RemoteBadCert),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_BadProtocolVersion as i32 => {
				Ok(NetConnectionEnd::RemoteBadProtocolVersion)
			}
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_P2P_ICE_NoPublicAddresses as i32 => {
				Ok(NetConnectionEnd::RemoteP2pICENoPublicAddresses)
			}
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_Generic as i32 => Ok(NetConnectionEnd::MiscGeneric),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_InternalError as i32 => Ok(NetConnectionEnd::MiscInternalError),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_Timeout as i32 => Ok(NetConnectionEnd::MiscTimeout),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_SteamConnectivity as i32 => {
				Ok(NetConnectionEnd::MiscSteamConnectivity)
			}
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_NoRelaySessionsToClient as i32 => {
				Ok(NetConnectionEnd::MiscNoRelaySessionsToClient)
			}
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_P2P_Rendezvous as i32 => Ok(NetConnectionEnd::MiscP2pRendezvous),
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_P2P_NAT_Firewall as i32 => {
				Ok(NetConnectionEnd::MiscP2pNatFirewall)
			}
			end if end == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_PeerSentNoConnection as i32 => {
				Ok(NetConnectionEnd::MiscPeerSentNoConnection)
			}
			_ => panic!("invalid connection end"),
		}
	}
}

impl From<sys::ESteamNetConnectionEnd> for NetConnectionEnd {
	fn from(end: steamworks_x_sys::ESteamNetConnectionEnd) -> Self {
		match end {
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_App_Generic => NetConnectionEnd::AppGeneric,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_AppException_Generic => NetConnectionEnd::AppException,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_OfflineMode => NetConnectionEnd::LocalOfflineMode,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_ManyRelayConnectivity => NetConnectionEnd::LocalManyRelayConnectivity,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_HostedServerPrimaryRelay => NetConnectionEnd::LocalHostedServerPrimaryRelay,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_NetworkConfig => NetConnectionEnd::LocalNetworkConfig,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_Rights => NetConnectionEnd::LocalRights,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Local_P2P_ICE_NoPublicAddresses => NetConnectionEnd::LocalP2pICENoPublicAddresses,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_Timeout => NetConnectionEnd::RemoteTimeout,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_BadCrypt => NetConnectionEnd::RemoteBadEncrypt,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_BadCert => NetConnectionEnd::RemoteBadCert,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_BadProtocolVersion => NetConnectionEnd::RemoteBadProtocolVersion,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Remote_P2P_ICE_NoPublicAddresses => NetConnectionEnd::RemoteP2pICENoPublicAddresses,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_Generic => NetConnectionEnd::MiscGeneric,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_InternalError => NetConnectionEnd::MiscInternalError,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_Timeout => NetConnectionEnd::MiscTimeout,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_SteamConnectivity => NetConnectionEnd::MiscSteamConnectivity,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_NoRelaySessionsToClient => NetConnectionEnd::MiscNoRelaySessionsToClient,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_P2P_Rendezvous => NetConnectionEnd::MiscP2pRendezvous,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_P2P_NAT_Firewall => NetConnectionEnd::MiscP2pNatFirewall,
			sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Misc_PeerSentNoConnection => NetConnectionEnd::MiscPeerSentNoConnection,
			_ => panic!("invalid connection end"),
		}
	}
}

pub type NetworkingAvailabilityResult = Result<NetworkingAvailability, NetworkingAvailabilityError>;

/// Describe the status of a particular network resource
#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
pub enum NetworkingAvailability {
	/// We don't know because we haven't ever checked/tried
	NeverTried,
	/// We're waiting on a dependent resource to be acquired.  (E.g. we cannot obtain a cert until we are logged into Steam.  We cannot measure latency to relays until we have the network config.)
	Waiting,
	/// We're actively trying now, but are not yet successful.
	Attempting,
	/// Resource is online/available
	Current,
}

/// Describe a error of a particular network resource
/// In general, we will not automatically retry unless you take some action that
/// depends on of requests this resource, such as querying the status, attempting
/// to initiate a connection, receive a connection, etc.  If you do not take any
#[derive(Debug, Error, Eq, PartialEq, Hash, Copy, Clone)]
pub enum NetworkingAvailabilityError {
	/// Internal dummy/sentinal. The network resource is probably not initialized yet
	#[error("unknown")]
	Unknown,
	/// A dependent resource is missing, so this service is unavailable.  (E.g. we cannot talk to routers because Internet is down or we don't have the network config.)
	#[error("A dependent resource is missing, so this service is unavailable.")]
	CannotTry,
	/// We have tried for enough time that we would expect to have been successful by now.  We have never been successful
	#[error("We have tried for enough time that we would expect to have been successful by now.  We have never been successful")]
	Failed,
	/// We tried and were successful at one time, but now it looks like we have a problem
	#[error("We tried and were successful at one time, but now it looks like we have a problem")]
	Previously,
	/// We previously failed and are currently retrying
	#[error("We previously failed and are currently retrying")]
	Retrying,
}

impl TryFrom<sys::ESteamNetworkingAvailability> for NetworkingAvailability {
	type Error = NetworkingAvailabilityError;

	fn try_from(value: sys::ESteamNetworkingAvailability) -> Result<Self, Self::Error> {
		match value {
			sys::ESteamNetworkingAvailability::k_ESteamNetworkingAvailability_Unknown => Err(NetworkingAvailabilityError::Unknown),
			sys::ESteamNetworkingAvailability::k_ESteamNetworkingAvailability_CannotTry => Err(NetworkingAvailabilityError::CannotTry),
			sys::ESteamNetworkingAvailability::k_ESteamNetworkingAvailability_Failed => Err(NetworkingAvailabilityError::Failed),
			sys::ESteamNetworkingAvailability::k_ESteamNetworkingAvailability_Previously => Err(NetworkingAvailabilityError::Previously),
			sys::ESteamNetworkingAvailability::k_ESteamNetworkingAvailability_Retrying => Err(NetworkingAvailabilityError::Retrying),
			sys::ESteamNetworkingAvailability::k_ESteamNetworkingAvailability_NeverTried => Ok(NetworkingAvailability::NeverTried),
			sys::ESteamNetworkingAvailability::k_ESteamNetworkingAvailability_Waiting => Ok(NetworkingAvailability::Waiting),
			sys::ESteamNetworkingAvailability::k_ESteamNetworkingAvailability_Attempting => Ok(NetworkingAvailability::Attempting),
			sys::ESteamNetworkingAvailability::k_ESteamNetworkingAvailability_Current => Ok(NetworkingAvailability::Current),
			_ => panic!("invalid networking availability {:?}", value),
		}
	}
}

#[derive(Debug, Error)]
#[error("integer value could not be converted to enum")]
pub struct InvalidEnumValue;

/// Internal struct to handle network callbacks
#[derive(Clone)]
pub struct NetConnectionInfo {
	pub(crate) inner: sys::SteamNetConnectionInfo_t,
}

#[allow(dead_code)]
impl NetConnectionInfo {
	/// Return the network identity of the remote peer.
	///
	/// Depending on the connection type and phase of the connection, it may be unknown, in which case `None` is returned.
	/// If `Some` is returned, the return value is a valid `NetworkingIdentity`.
	pub fn identity_remote(&self) -> Option<NetworkingIdentity> {
		let identity = NetworkingIdentity::from(self.inner.m_identityRemote);
		if identity.is_valid() {
			Some(identity)
		} else {
			None
		}
	}

	pub fn user_data(&self) -> i64 {
		self.inner.m_nUserData
	}

	pub fn listen_socket(&self) -> Option<sys::HSteamNetConnection> {
		let handle = self.inner.m_hListenSocket;
		if handle == sys::k_HSteamListenSocket_Invalid {
			None
		} else {
			Some(handle)
		}
	}

	pub fn state(&self) -> Result<NetworkingConnectionState, InvalidConnectionState> {
		self.inner.m_eState.try_into()
	}

	pub fn end_reason(&self) -> Option<NetConnectionEnd> {
		if self.inner.m_eEndReason == sys::ESteamNetConnectionEnd::k_ESteamNetConnectionEnd_Invalid as _ {
			None
		} else {
			Some(self.inner.m_eEndReason.try_into().expect("Unknown end reason could not be converted"))
		}
	}
}

impl Debug for NetConnectionInfo {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("NetConnectionInfo")
			.field("identity_remote", &self.identity_remote())
			.field("user_data", &self.user_data())
			.field("listen_socket", &self.listen_socket())
			.field("state", &self.state())
			.field("end_reason", &self.end_reason())
			.finish()
	}
}

impl From<sys::SteamNetConnectionInfo_t> for NetConnectionInfo {
	fn from(info: steamworks_x_sys::SteamNetConnectionInfo_t) -> Self {
		Self { inner: info }
	}
}

/// SteamNetConnectionRealTimeStatus_t structure
#[derive(Clone)]
pub struct NetConnectionRealTimeInfo {
	pub(crate) inner: sys::SteamNetConnectionRealTimeStatus_t,
}

impl NetConnectionRealTimeInfo {
	pub fn connection_state(&self) -> Result<NetworkingConnectionState, InvalidConnectionState> {
		self.inner.m_eState.try_into()
	}

	// ping in ms
	pub fn ping(&self) -> i32 {
		self.inner.m_nPing
	}

	/// Connection quality measured locally, 0...1.  (Percentage of packets delivered)
	pub fn connection_quality_local(&self) -> f32 {
		self.inner.m_flConnectionQualityLocal
	}

	/// Packet delivery success rate as observed from remote host
	pub fn connection_quality_remote(&self) -> f32 {
		self.inner.m_flConnectionQualityRemote
	}

	/// Current data rates from recent history
	pub fn out_packets_per_sec(&self) -> f32 {
		self.inner.m_flOutPacketsPerSec
	}

	/// Current data rates from recent history
	pub fn out_bytes_per_sec(&self) -> f32 {
		self.inner.m_flOutBytesPerSec
	}
	/// Current data rates from recent history
	pub fn in_packets_per_sec(&self) -> f32 {
		self.inner.m_flInPacketsPerSec
	}

	/// Current data rates from recent history
	pub fn in_bytes_per_sec(&self) -> f32 {
		self.inner.m_flInBytesPerSec
	}

	/// Estimate rate that we believe that we can send data to our peer.
	/// Note that this could be significantly higher than m_flOutBytesPerSec,
	/// meaning the capacity of the channel is higher than you are sending data.
	/// (That's OK!)
	pub fn send_rate_bytes_per_sec(&self) -> i32 {
		self.inner.m_nSendRateBytesPerSecond
	}
	/// Number of bytes pending to be sent.  This is data that you have recently
	/// requested to be sent but has not yet actually been put on the wire.  The
	/// reliable number ALSO includes data that was previously placed on the wire,
	/// but has now been scheduled for re-transmission.  Thus, it's possible to
	/// observe m_cbPendingReliable increasing between two checks, even if no
	/// calls were made to send reliable data between the checks.  Data that is
	/// awaiting the Nagle delay will appear in these numbers.
	pub fn pending_unreliable(&self) -> i32 {
		self.inner.m_cbPendingUnreliable
	}
	/// Number of bytes pending to be sent.  This is data that you have recently
	/// requested to be sent but has not yet actually been put on the wire.  The
	/// reliable number ALSO includes data that was previously placed on the wire,
	/// but has now been scheduled for re-transmission.  Thus, it's possible to
	/// observe m_cbPendingReliable increasing between two checks, even if no
	/// calls were made to send reliable data between the checks.  Data that is
	/// awaiting the Nagle delay will appear in these numbers.
	pub fn pending_reliable(&self) -> i32 {
		self.inner.m_cbPendingReliable
	}

	/// Number of bytes of reliable data that has been placed the wire, but
	/// for which we have not yet received an acknowledgment, and thus we may
	/// have to re-transmit.
	pub fn sent_unacked_reliable(&self) -> i32 {
		self.inner.m_cbSentUnackedReliable
	}

	/// If you asked us to send a message right now, how long would that message
	/// sit in the queue before we actually started putting packets on the wire?
	/// (And assuming Nagle does not cause any packets to be delayed.)
	///
	/// In general, data that is sent by the application is limited by the
	/// bandwidth of the channel.  If you send data faster than this, it must
	/// be queued and put on the wire at a metered rate.  Even sending a small amount
	/// of data (e.g. a few MTU, say ~3k) will require some of the data to be delayed
	/// a bit.
	///
	/// In general, the estimated delay will be approximately equal to
	///
	///		( m_cbPendingUnreliable+m_cbPendingReliable ) / m_nSendRateBytesPerSecond
	///
	/// plus or minus one MTU.  It depends on how much time has elapsed since the last
	/// packet was put on the wire.  For example, the queue might have *just* been emptied,
	/// and the last packet placed on the wire, and we are exactly up against the send
	/// rate limit.  In that case we might need to wait for one packet's worth of time to
	/// elapse before we can send again.  On the other extreme, the queue might have data
	/// in it waiting for Nagle.  (This will always be less than one packet, because as soon
	/// as we have a complete packet we would send it.)  In that case, we might be ready
	/// to send data now, and this value will be 0.
	pub fn queued_send_bytes(&self) -> i64 {
		self.inner.m_usecQueueTime
	}
}

impl Debug for NetConnectionRealTimeInfo {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("NetQuickConnectionInfo")
			.field("connection_state", &self.connection_state())
			.field("ping", &self.ping())
			.field("connection_quality_local", &self.connection_quality_local())
			.field("connection_quality_remote", &self.connection_quality_remote())
			.field("out_packets_per_sec", &self.out_packets_per_sec())
			.field("out_bytes_per_sec", &self.out_bytes_per_sec())
			.field("in_packets_per_sec", &self.in_packets_per_sec())
			.field("in_bytes_per_sec", &self.in_bytes_per_sec())
			.field("send_rate_bytes_per_sec", &self.send_rate_bytes_per_sec())
			.field("pending_unreliable", &self.pending_unreliable())
			.field("pending_reliable", &self.pending_reliable())
			.field("sent_unacked_reliable", &self.sent_unacked_reliable())
			.field("queued_send_bytes", &self.queued_send_bytes())
			.finish()
	}
}

impl From<sys::SteamNetConnectionRealTimeStatus_t> for NetConnectionRealTimeInfo {
	fn from(info: steamworks_x_sys::SteamNetConnectionRealTimeStatus_t) -> Self {
		Self { inner: info }
	}
}

/// Quick status of a particular lane
#[derive(Clone)]
pub struct NetConnectionRealTimeLaneStatus {
	pub(crate) inner: sys::SteamNetConnectionRealTimeLaneStatus_t,
}

impl NetConnectionRealTimeLaneStatus {
	/// Number of bytes pending to be sent.  This is data that you have recently
	/// requested to be sent but has not yet actually been put on the wire.  The
	/// reliable number ALSO includes data that was previously placed on the wire,
	/// but has now been scheduled for re-transmission.  Thus, it's possible to
	/// observe m_cbPendingReliable increasing between two checks, even if no
	/// calls were made to send reliable data between the checks.  Data that is
	/// awaiting the Nagle delay will appear in these numbers.
	/// Lane-specific, for global look at NetConnectionRealTimeInfo.
	pub fn pending_unreliable(&self) -> i32 {
		self.inner.m_cbPendingUnreliable
	}
	/// Number of bytes pending to be sent.  This is data that you have recently
	/// requested to be sent but has not yet actually been put on the wire.  The
	/// reliable number ALSO includes data that was previously placed on the wire,
	/// but has now been scheduled for re-transmission.  Thus, it's possible to
	/// observe m_cbPendingReliable increasing between two checks, even if no
	/// calls were made to send reliable data between the checks.  Data that is
	/// awaiting the Nagle delay will appear in these numbers.
	/// Lane-specific, for global look at NetConnectionRealTimeInfo.
	pub fn pending_reliable(&self) -> i32 {
		self.inner.m_cbPendingReliable
	}
	/// Number of bytes of reliable data that has been placed the wire, but
	/// for which we have not yet received an acknowledgment, and thus we may
	/// have to re-transmit.
	/// Lane-specific, for global look at NetConnectionRealTimeInfo.
	pub fn sent_unacked_reliable(&self) -> i32 {
		self.inner.m_cbSentUnackedReliable
	}
	/// Lane-specific queue time.  This value takes into consideration lane priorities
	/// and weights, and how much data is queued in each lane, and attempts to predict
	/// how any data currently queued will be sent out.
	pub fn queued_send_bytes(&self) -> i64 {
		self.inner.m_usecQueueTime
	}
}

impl From<sys::SteamNetConnectionRealTimeLaneStatus_t> for NetConnectionRealTimeLaneStatus {
	fn from(info: steamworks_x_sys::SteamNetConnectionRealTimeLaneStatus_t) -> Self {
		Self { inner: info }
	}
}

/// This callback is posted whenever a connection is created, destroyed, or changes state.
/// The m_info field will contain a complete description of the connection at the time the
/// change occurred and the callback was posted.  In particular, m_eState will have the
/// new connection state.
///
/// You will usually need to listen for this callback to know when:
/// - A new connection arrives on a listen socket.
///   m_info.m_hListenSocket will be set, m_eOldState = k_ESteamNetworkingConnectionState_None,
///   and m_info.m_eState = k_ESteamNetworkingConnectionState_Connecting.
///   See ISteamNetworkigSockets::AcceptConnection.
/// - A connection you initiated has been accepted by the remote host.
///   m_eOldState = k_ESteamNetworkingConnectionState_Connecting, and
///   m_info.m_eState = k_ESteamNetworkingConnectionState_Connected.
///   Some connections might transition to k_ESteamNetworkingConnectionState_FindingRoute first.
/// - A connection has been actively rejected or closed by the remote host.
///   m_eOldState = k_ESteamNetworkingConnectionState_Connecting or k_ESteamNetworkingConnectionState_Connected,
///   and m_info.m_eState = k_ESteamNetworkingConnectionState_ClosedByPeer.  m_info.m_eEndReason
///   and m_info.m_szEndDebug will have for more details.
///   NOTE: upon receiving this callback, you must still destroy the connection using
///   ISteamNetworkingSockets::CloseConnection to free up local resources.  (The details
///   passed to the function are not used in this case, since the connection is already closed.)
/// - A problem was detected with the connection, and it has been closed by the local host.
///   The most common failure is timeout, but other configuration or authentication failures
///   can cause this.  m_eOldState = k_ESteamNetworkingConnectionState_Connecting or
///   k_ESteamNetworkingConnectionState_Connected, and m_info.m_eState = k_ESteamNetworkingConnectionState_ProblemDetectedLocally.
///   m_info.m_eEndReason and m_info.m_szEndDebug will have for more details.
///   NOTE: upon receiving this callback, you must still destroy the connection using
///   ISteamNetworkingSockets::CloseConnection to free up local resources.  (The details
///   passed to the function are not used in this case, since the connection is already closed.)
///
/// Remember that callbacks are posted to a queue, and networking connections can
/// change at any time.  It is possible that the connection has already changed
/// state by the time you process this callback.
///
/// Also note that callbacks will be posted when connections are created and destroyed by your own API calls.
#[derive(Debug, Clone)]
pub struct NetConnectionStatusChanged {
	/// The handle of the connection that has changed state
	// (only important for the ListenSocketEvent, so it can stay for now in the crate visibility)
	pub(crate) connection: sys::HSteamNetConnection,
	/// Full connection info
	pub connection_info: NetConnectionInfo,

	// Debug is intentionally ignored during dead-code analysis
	#[allow(dead_code)]
	/// Previous state.  (Current state is in m_info.m_eState)
	pub old_state: NetworkingConnectionState,
}

unsafe impl Callback for NetConnectionStatusChanged {
	const ID: i32 = sys::SteamNetConnectionStatusChangedCallback_t_k_iCallback as _;
	const SIZE: i32 = std::mem::size_of::<sys::SteamNetConnectionStatusChangedCallback_t>() as _;

	unsafe fn from_raw(raw: *mut c_void) -> Self {
		let val = &mut *(raw as *mut sys::SteamNetConnectionStatusChangedCallback_t);

		NetConnectionStatusChanged {
			connection: val.m_hConn,
			connection_info: val.m_info.into(),
			old_state: val.m_eOldState.try_into().unwrap(),
		}
	}
}

impl NetConnectionStatusChanged {
	pub(crate) fn into_listen_socket_event<Manager: 'static>(
		self,
		socket: Arc<InnerSocket<Manager>>,
	) -> Result<ListenSocketEvent<Manager>, NetConnectionError> {
		match self.connection_info.state() {
			Ok(NetworkingConnectionState::None) => Err(UnhandledType(NetworkingConnectionState::None)),
			Ok(NetworkingConnectionState::Connecting) => {
				if let Some(remote) = self.connection_info.identity_remote() {
					Ok(ListenSocketEvent::Connecting(ConnectionRequest {
						remote,
						user_data: self.connection_info.user_data(),
						connection: NetConnection::new(self.connection, socket.sockets, socket.inner.clone(), socket),
					}))
				} else {
					return Err(NetConnectionError::InvalidRemote);
				}
			}
			Ok(NetworkingConnectionState::FindingRoute) => Err(UnhandledType(NetworkingConnectionState::FindingRoute)),
			Ok(NetworkingConnectionState::Connected) => {
				if let Some(remote) = self.connection_info.identity_remote() {
					Ok(ListenSocketEvent::Connected(ConnectedEvent {
						remote,
						user_data: self.connection_info.user_data(),
						connection: NetConnection::new(self.connection, socket.sockets, socket.inner.clone(), socket.clone()),
					}))
				} else {
					return Err(NetConnectionError::InvalidRemote);
				}
			}
			Ok(NetworkingConnectionState::ClosedByPeer) | Ok(NetworkingConnectionState::ProblemDetectedLocally) => {
				if let Some(remote) = self.connection_info.identity_remote() {
					Ok(ListenSocketEvent::Disconnected(DisconnectedEvent {
						remote,
						user_data: self.connection_info.user_data(),
						end_reason: self
							.connection_info
							.end_reason()
							.expect("disconnect event received, but no valid end reason was given"),
					}))
				} else {
					return Err(NetConnectionError::InvalidRemote);
				}
			}
			Err(err) => Err(NetConnectionError::UnknownType(err)),
		}
	}
}

pub enum ListenSocketEvent<Manager> {
	Connecting(ConnectionRequest<Manager>),
	Connected(ConnectedEvent<Manager>),
	Disconnected(DisconnectedEvent),
}

pub struct ConnectionRequest<Manager> {
	remote: NetworkingIdentity,
	user_data: i64,
	connection: NetConnection<Manager>,
}

impl<Manager: 'static> ConnectionRequest<Manager> {
	pub fn remote(&self) -> NetworkingIdentity {
		self.remote.clone()
	}

	pub fn user_data(&self) -> i64 {
		self.user_data
	}

	pub fn accept(self) -> SResult<()> {
		self.connection.accept()
	}

	pub fn reject(self, end_reason: NetConnectionEnd, debug_string: Option<&str>) -> bool {
		self.connection.close(end_reason, debug_string, false)
	}
}

pub struct ConnectedEvent<Manager> {
	remote: NetworkingIdentity,
	user_data: i64,
	connection: NetConnection<Manager>,
}

impl<Manager> ConnectedEvent<Manager> {
	pub fn remote(&self) -> NetworkingIdentity {
		self.remote.clone()
	}
	pub fn user_data(&self) -> i64 {
		self.user_data
	}
	pub fn connection(&self) -> &NetConnection<Manager> {
		&self.connection
	}

	pub fn take_connection(self) -> NetConnection<Manager> {
		self.connection
	}
}

pub struct DisconnectedEvent {
	remote: NetworkingIdentity,
	user_data: i64,
	end_reason: NetConnectionEnd,
}

impl DisconnectedEvent {
	pub fn remote(&self) -> NetworkingIdentity {
		self.remote.clone()
	}
	pub fn user_data(&self) -> i64 {
		self.user_data
	}
	pub fn end_reason(&self) -> NetConnectionEnd {
		self.end_reason
	}
}

#[derive(Debug, Error)]
pub(crate) enum NetConnectionError {
	#[error("internal event type has no corresponding external event")]
	UnhandledType(NetworkingConnectionState),
	#[error("invalid event type")]
	UnknownType(InvalidConnectionState),
	#[error("invalid remote")]
	InvalidRemote,
}

#[derive(Clone)]
pub struct NetworkingConfigEntry {
	inner: sys::SteamNetworkingConfigValue_t,
}

impl NetworkingConfigEntry {
	fn new_uninitialized_config_value() -> sys::SteamNetworkingConfigValue_t {
		sys::SteamNetworkingConfigValue_t {
			m_eValue: sys::ESteamNetworkingConfigValue::k_ESteamNetworkingConfig_Invalid,
			m_eDataType: sys::ESteamNetworkingConfigDataType::k_ESteamNetworkingConfig_Int32,
			m_val: sys::SteamNetworkingConfigValue_t__bindgen_ty_1 { m_int32: 0 },
		}
	}

	pub fn new_int32(value_type: NetworkingConfigValue, value: i32) -> Self {
		debug_assert_eq!(value_type.data_type(), NetworkingConfigDataType::Int32);

		let mut config = Self::new_uninitialized_config_value();
		unsafe {
			sys::SteamAPI_SteamNetworkingConfigValue_t_SetInt32(&mut config, value_type.into(), value);
			NetworkingConfigEntry { inner: config }
		}
	}

	pub fn new_int64(value_type: NetworkingConfigValue, value: i64) -> Self {
		debug_assert_eq!(value_type.data_type(), NetworkingConfigDataType::Int64);

		let mut config = Self::new_uninitialized_config_value();
		unsafe {
			sys::SteamAPI_SteamNetworkingConfigValue_t_SetInt64(&mut config, value_type.into(), value);
			NetworkingConfigEntry { inner: config }
		}
	}

	pub fn new_float(value_type: NetworkingConfigValue, value: f32) -> Self {
		debug_assert_eq!(value_type.data_type(), NetworkingConfigDataType::Int64);

		let mut config = Self::new_uninitialized_config_value();
		unsafe {
			sys::SteamAPI_SteamNetworkingConfigValue_t_SetFloat(&mut config, value_type.into(), value);
			NetworkingConfigEntry { inner: config }
		}
	}

	pub fn new_string(value_type: NetworkingConfigValue, value: &str) -> Self {
		debug_assert_eq!(value_type.data_type(), NetworkingConfigDataType::String);

		let mut config = Self::new_uninitialized_config_value();
		unsafe {
			let c_str = CString::new(value).expect("Rust string could not be converted");
			sys::SteamAPI_SteamNetworkingConfigValue_t_SetString(&mut config, value_type.into(), c_str.as_ptr());
			NetworkingConfigEntry { inner: config }
		}
	}
}

impl From<NetworkingConfigEntry> for sys::SteamNetworkingConfigValue_t {
	fn from(entry: NetworkingConfigEntry) -> sys::SteamNetworkingConfigValue_t {
		entry.inner
	}
}

/// A safe wrapper for SteamNetworkingIdentity
#[derive(Clone)]
pub struct NetworkingIdentity {
	// Using a enum for NetworkingIdentity with variants for each identity type would be more idiomatic to use,
	// but would require converting between the internal and the rust representation whenever the API is used.
	// Maybe a second type could be used for matching to avoid get_ip, get_steam_id, etc.
	inner: sys::SteamNetworkingIdentity,
}

// const NETWORK_IDENTITY_STRING_BUFFER_SIZE: usize =
//     sys::SteamNetworkingIdentity__bindgen_ty_1::k_cchMaxString as usize;

impl NetworkingIdentity {
	pub fn new() -> Self {
		unsafe {
			let mut id = sys::SteamNetworkingIdentity {
				m_eType: sys::ESteamNetworkingIdentityType::k_ESteamNetworkingIdentityType_Invalid,
				m_cbSize: 0,
				__bindgen_anon_1: sys::SteamNetworkingIdentity__bindgen_ty_2 { m_steamID64: 0 },
			};
			sys::SteamAPI_SteamNetworkingIdentity_Clear(&mut id);
			Self { inner: id }
		}
	}

	pub fn new_steam_id(id: SteamId) -> Self {
		let mut identity = Self::new();
		identity.set_steam_id(id);
		identity
	}

	pub fn new_ip(addr: SocketAddr) -> Self {
		let mut identity = Self::new();
		identity.set_ip_addr(addr);
		identity
	}

	pub fn steam_id(&self) -> Option<SteamId> {
		unsafe {
			let id = sys::SteamAPI_SteamNetworkingIdentity_GetSteamID64(self.as_ptr() as *mut _);
			if id == 0 {
				None
			} else {
				Some(SteamId(id))
			}
		}
	}

	pub fn is_valid(&self) -> bool {
		!self.is_invalid()
	}

	pub fn is_invalid(&self) -> bool {
		unsafe { sys::SteamAPI_SteamNetworkingIdentity_IsInvalid(self.as_ptr() as *mut _) }
	}

	pub fn set_steam_id(&mut self, id: SteamId) {
		unsafe { sys::SteamAPI_SteamNetworkingIdentity_SetSteamID64(self.as_mut_ptr(), id.0) }
	}

	pub fn set_ip_addr(&mut self, addr: SocketAddr) {
		let addr = SteamIpAddr::from(addr);
		unsafe {
			sys::SteamAPI_SteamNetworkingIdentity_SetIPAddr(self.as_mut_ptr(), addr.as_ptr());
		}
	}

	#[allow(dead_code)]
	pub(crate) fn ip_addr(&self) -> Option<SteamIpAddr> {
		unsafe {
			let ip = sys::SteamAPI_SteamNetworkingIdentity_GetIPAddr(self.as_ptr() as *mut _);
			if ip.is_null() {
				None
			} else {
				Some(SteamIpAddr { inner: (*ip) })
			}
		}
	}

	pub fn set_local_host(&mut self) {
		unsafe { sys::SteamAPI_SteamNetworkingIdentity_SetLocalHost(self.as_mut_ptr()) }
	}

	pub fn is_local_host(&self) -> bool {
		unsafe { sys::SteamAPI_SteamNetworkingIdentity_IsLocalHost(self.as_ptr() as *mut _) }
	}

	pub fn debug_string(&self) -> String {
		// For some reason I can't get the original function to work,
		// so I decided to recreate the original from https://github.com/ValveSoftware/GameNetworkingSockets/blob/529901e7c1caf50928ac8814cad205d192bbf27d/src/steamnetworkingsockets/steamnetworkingsockets_shared.cpp

		// let mut buffer = vec![0i8; NETWORK_IDENTITY_STRING_BUFFER_SIZE];
		// let string = unsafe {
		//     sys::SteamAPI_SteamNetworkingIdentity_ToString(
		//         self.as_ptr() as *mut sys::SteamNetworkingIdentity,
		//         buffer.as_mut_ptr(),
		//         NETWORK_IDENTITY_STRING_BUFFER_SIZE as u32,
		//     );
		//     CString::from_raw(buffer.as_mut_ptr())
		// };
		// string.into_string().unwrap()

		unsafe {
			match self.inner.m_eType {
				sys::ESteamNetworkingIdentityType::k_ESteamNetworkingIdentityType_Invalid => "invalid".to_string(),
				sys::ESteamNetworkingIdentityType::k_ESteamNetworkingIdentityType_SteamID => {
					let id = self.inner.__bindgen_anon_1.m_steamID64;
					format!("steamid:{}", id)
				}
				sys::ESteamNetworkingIdentityType::k_ESteamNetworkingIdentityType_IPAddress => {
					let ip = SteamIpAddr::from(self.inner.__bindgen_anon_1.m_ip);
					format!("ip:{}", ip)
				}
				sys::ESteamNetworkingIdentityType::k_ESteamNetworkingIdentityType_GenericString => {
					unimplemented!()
				}
				sys::ESteamNetworkingIdentityType::k_ESteamNetworkingIdentityType_GenericBytes => {
					unimplemented!()
				}
				sys::ESteamNetworkingIdentityType::k_ESteamNetworkingIdentityType_UnknownType => {
					unimplemented!()
				}
				ty => format!("bad_type:{}", ty as u32),
			}
		}
	}

	pub(crate) fn as_ptr(&self) -> *const sys::SteamNetworkingIdentity {
		&self.inner
	}

	pub(crate) fn as_mut_ptr(&mut self) -> *mut sys::SteamNetworkingIdentity {
		&mut self.inner
	}
}

impl Debug for NetworkingIdentity {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.debug_string())
	}
}

impl From<sys::SteamNetworkingIdentity> for NetworkingIdentity {
	fn from(id: steamworks_x_sys::SteamNetworkingIdentity) -> Self {
		NetworkingIdentity { inner: id }
	}
}

impl From<SteamId> for NetworkingIdentity {
	fn from(id: SteamId) -> Self {
		Self::new_steam_id(id)
	}
}

impl Default for NetworkingIdentity {
	fn default() -> Self {
		Self::new()
	}
}

pub struct NetworkingMessage<Manager> {
	pub(crate) message: *mut sys::SteamNetworkingMessage_t,

	// Not sure if this is necessary here, we may not need a Manager to use free on messages
	pub(crate) _inner: Arc<Inner<Manager>>,
}

impl<Manager> NetworkingMessage<Manager> {
	/// For messages received on connections: what connection did this come from?
	/// For outgoing messages: what connection to send it to?
	/// Not used when using the ISteamNetworkingMessages interface
	#[allow(dead_code)]
	pub(crate) fn connection(&self) -> Option<sys::HSteamNetConnection> {
		let handle = unsafe { (*self.message).m_conn };
		if handle == sys::k_HSteamNetConnection_Invalid {
			None
		} else {
			Some(handle)
		}
	}

	/// Set the target connection for the connection.
	/// Make sure you don't close or drop the `NetConnection` before sending your message.
	///
	/// Use this with `ListenSocket::send_messages` for efficient sending.
	pub fn set_connection(&mut self, connection: &NetConnection<Manager>) {
		unsafe { (*self.message).m_conn = connection.handle }
	}

	/// For inbound messages: Who sent this to us?
	/// For outbound messages on connections: not used.
	/// For outbound messages on the ad-hoc ISteamNetworkingMessages interface: who should we send this to?
	pub fn identity_peer(&self) -> NetworkingIdentity {
		unsafe {
			let ident = &mut (*self.message).m_identityPeer;
			NetworkingIdentity { inner: *ident }
		}
	}

	/// The identity of the sender or, the receiver when used with the NetworkingMessages interface.
	pub fn set_identity_peer(&mut self, identity: NetworkingIdentity) {
		unsafe { (*self.message).m_identityPeer = identity.inner }
	}

	/// For messages received on connections, this is the user data
	/// associated with the connection.
	///
	/// This is *usually* the same as calling GetConnection() and then
	/// fetching the user data associated with that connection, but for
	/// the following subtle differences:
	///
	/// - This user data will match the connection's user data at the time
	///   is captured at the time the message is returned by the API.
	///   If you subsequently change the userdata on the connection,
	///   this won't be updated.
	/// - This is an inline call, so it's *much* faster.
	/// - You might have closed the connection, so fetching the user data
	///   would not be possible.
	///
	/// Not used when sending messages,
	pub fn connection_user_data(&self) -> i64 {
		unsafe { (*self.message).m_nConnUserData }
	}

	/// Message number assigned by the sender.
	/// This is not used for outbound messages
	pub fn message_number(&self) -> MessageNumber {
		unsafe { MessageNumber((*self.message).m_nMessageNumber as u64) }
	}

	/// Bitmask of k_nSteamNetworkingSend_xxx flags.
	/// For received messages, only the k_nSteamNetworkingSend_Reliable bit is valid.
	/// For outbound messages, all bits are relevant
	pub fn send_flags(&self) -> SendFlags {
		unsafe { SendFlags::from_bits((*self.message).m_nFlags).expect("send flags could not be converted to rust representation") }
	}

	pub fn set_send_flags(&mut self, send_flags: SendFlags) {
		unsafe { (*self.message).m_nFlags = send_flags.bits() }
	}

	/// Bitmask of k_nSteamNetworkingSend_xxx flags.
	/// For received messages, only the k_nSteamNetworkingSend_Reliable bit is valid.
	/// For outbound messages, all bits are relevant
	pub fn channel(&self) -> i32 {
		unsafe { (*self.message).m_nChannel }
	}

	pub fn set_channel(&mut self, channel: i32) {
		unsafe {
			(*self.message).m_nChannel = channel;
		}
	}

	/// Message payload
	pub fn data(&self) -> &[u8] {
		unsafe { std::slice::from_raw_parts((*self.message).m_pData as _, (*self.message).m_cbSize as usize) }
	}

	pub fn copy_data_into_buffer(&mut self, data: &[u8]) -> Result<(), MessageError> {
		unsafe {
			if (*self.message).m_pData.is_null() {
				return Err(MessageError::NullBuffer);
			}

			if ((*self.message).m_cbSize as usize) < data.len() {
				return Err(MessageError::BufferTooSmall);
			}

			((*self.message).m_pData as *mut u8).copy_from(data.as_ptr(), data.len());
		}

		Ok(())
	}

	/// Set a new buffer for the message.
	///
	/// Returns `Err(MessageError::BufferAlreadySet)` if the current buffer is not NULL.
	pub fn set_data(&mut self, data: Vec<u8>) -> Result<(), MessageError> {
		unsafe {
			if !(*self.message).m_pData.is_null() {
				return Err(MessageError::BufferAlreadySet);
			}

			let mut data = data.into_boxed_slice();
			(*self.message).m_pData = data.as_mut_ptr() as *mut c_void;
			(*self.message).m_cbSize = data.len() as _;
			(*self.message).m_pfnFreeData = Some(free_rust_message_buffer);
			std::mem::forget(data);
		}

		Ok(())
	}

	/// Arbitrary user data that you can use when sending messages using
	/// ISteamNetworkingUtils::AllocateMessage and ISteamNetworkingSockets::SendMessage.
	/// (The callback you set in m_pfnFreeData might use this field.)
	///
	/// Not used for received messages.
	pub fn user_data(&self) -> i64 {
		unsafe { (*self.message).m_nUserData }
	}

	/// Arbitrary user data that you can use when sending messages using
	/// ISteamNetworkingUtils::AllocateMessage and ISteamNetworkingSockets::SendMessage.
	/// (The callback you set in m_pfnFreeData might use this field.)
	///
	/// Not used for received messages.
	pub fn set_user_data(&mut self, user_data: i64) {
		unsafe {
			(*self.message).m_nUserData = user_data;
		}
	}

	/// Return the message pointer and prevent rust from releasing it
	pub(crate) fn take_message(mut self) -> *mut sys::SteamNetworkingMessage_t {
		let message = self.message;
		self.message = std::ptr::null_mut();
		message
	}
}

extern "C" fn free_rust_message_buffer(message: *mut sys::SteamNetworkingMessage_t) {
	// Panic in code called by C is undefined behaviour
	if let Err(e) = catch_unwind(|| unsafe {
		let buffer = std::slice::from_raw_parts_mut((*message).m_pData, (*message).m_cbSize as usize);
		// Create the box again and drop it immediately
		let _ = Box::from_raw(buffer.as_mut_ptr());
	}) {
		eprintln!("{:?}", e);
	}
}

impl<Manager> Drop for NetworkingMessage<Manager> {
	fn drop(&mut self) {
		if !self.message.is_null() {
			unsafe { sys::SteamAPI_SteamNetworkingMessage_t_Release(self.message) }
		}
	}
}

#[derive(Debug, Error)]
pub enum MessageError {
	#[error("failed to write data to message, the buffer is not set")]
	NullBuffer,
	#[error("copied data is too large for the current buffer")]
	BufferTooSmall,
	#[error("cannot set a new buffer, the message already has a valid buffer")]
	BufferAlreadySet,
}

#[derive(Copy, Clone)]
pub(crate) struct SteamIpAddr {
	inner: sys::SteamNetworkingIPAddr,
}

#[allow(dead_code)]
impl SteamIpAddr {
	pub fn new() -> Self {
		unsafe {
			let mut ip = sys::SteamNetworkingIPAddr {
				__bindgen_anon_1: sys::SteamNetworkingIPAddr__bindgen_ty_2 {
					m_ipv4: sys::SteamNetworkingIPAddr_IPv4MappedAddress {
						m_8zeros: 0,
						m_0000: 0,
						m_ffff: 0,
						m_ip: [0; 4],
					},
				},
				m_port: 0,
			};
			sys::SteamAPI_SteamNetworkingIPAddr_Clear(&mut ip);
			Self { inner: ip }
		}
	}

	pub fn new_ip(ip: IpAddr, port: u16) -> Self {
		SocketAddr::new(ip, port).into()
	}

	pub fn set_ip(&mut self, ip: SocketAddr) {
		match ip {
			SocketAddr::V4(ip) => {
				self.set_ipv4(ip);
			}
			SocketAddr::V6(ip) => {
				self.set_ipv6(ip);
			}
		}
	}

	pub fn set_ipv4(&mut self, ip: SocketAddrV4) {
		unsafe {
			sys::SteamAPI_SteamNetworkingIPAddr_SetIPv4(&mut self.inner, (*ip.ip()).into(), ip.port());
		}
	}

	pub fn set_ipv6(&mut self, ip: SocketAddrV6) {
		unsafe {
			sys::SteamAPI_SteamNetworkingIPAddr_SetIPv6(&mut self.inner, ip.ip().octets().as_ptr(), ip.port());
		}
	}

	pub fn get_ipv4(&self) -> Option<Ipv4Addr> {
		let ip = unsafe { sys::SteamAPI_SteamNetworkingIPAddr_GetIPv4(&self.inner as *const _ as *mut _) };
		if ip == 0 {
			None
		} else {
			Some(Ipv4Addr::from(ip))
		}
	}

	pub fn is_ipv4(&self) -> bool {
		unsafe { sys::SteamAPI_SteamNetworkingIPAddr_IsIPv4(self.as_ptr() as *mut _) }
	}

	pub fn as_ptr(&self) -> *const sys::SteamNetworkingIPAddr {
		&self.inner
	}

	pub fn as_mut_ptr(&mut self) -> *mut sys::SteamNetworkingIPAddr {
		&mut self.inner
	}

	pub fn to_string(&self, with_port: bool) -> String {
		// Similar as with NetworkIdentity, I wasn't able to get the C function to work,
		// so I'm recreating it from https://github.com/ValveSoftware/GameNetworkingSockets/blob/529901e7c1caf50928ac8814cad205d192bbf27d/src/steamnetworkingsockets/steamnetworkingsockets_shared.cpp
		// let mut buffer = vec![0; sys::SteamNetworkingIPAddr_k_cchMaxString as usize];
		// let c_str;
		// unsafe {
		//     sys::SteamAPI_SteamNetworkingIPAddr_ToString(
		//         &self.inner as *const _ as *mut _,
		//         buffer.as_mut_ptr(),
		//         buffer.len() as _,
		//         false,
		//     );
		//     c_str = CStr::from_ptr(buffer.as_ptr());
		// }
		// let str_slice = c_str.to_str().unwrap();
		// str_slice.to_owned()

		unsafe {
			if self.is_ipv4() {
				let ip4 = self.inner.__bindgen_anon_1.m_ipv4.m_ip;
				if with_port {
					// This variable is necessary, format will create a unaligned reference to m_port, which can cause undefined bahavior
					let port = self.inner.m_port;
					format!("{}.{}.{}.{}:{}", ip4[0], ip4[1], ip4[2], ip4[3], port)
				} else {
					format!("{}.{}.{}.{}", ip4[0], ip4[1], ip4[2], ip4[3])
				}
			} else {
				// I'm just assuming that steam and rust have the same representation of ip6
				let ip6 = Ipv6Addr::from(self.inner.__bindgen_anon_1.m_ipv6);
				if with_port {
					// Same as with ipv4, don't remove this temp variable
					let port = self.inner.m_port;
					format!("[{}]:{}", ip6, port)
				} else {
					format!("{}", ip6)
				}
			}
		}
	}
}

impl Debug for SteamIpAddr {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.to_string(true))
	}
}

impl Display for SteamIpAddr {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.to_string(true))
	}
}

impl Default for SteamIpAddr {
	fn default() -> Self {
		Self::new()
	}
}

impl PartialEq for SteamIpAddr {
	fn eq(&self, other: &Self) -> bool {
		unsafe { sys::SteamAPI_SteamNetworkingIPAddr_IsEqualTo(&self.inner as *const _ as *mut _, &other.inner) }
	}
}

impl Eq for SteamIpAddr {}

impl From<SocketAddr> for SteamIpAddr {
	fn from(ip: SocketAddr) -> Self {
		let mut steam_ip = Self::new();
		steam_ip.set_ip(ip);
		steam_ip
	}
}

impl From<SocketAddrV4> for SteamIpAddr {
	fn from(ip: SocketAddrV4) -> Self {
		let mut steam_ip = Self::new();
		steam_ip.set_ipv4(ip);
		steam_ip
	}
}

impl From<SocketAddrV6> for SteamIpAddr {
	fn from(ip: SocketAddrV6) -> Self {
		let mut steam_ip = Self::new();
		steam_ip.set_ipv6(ip);
		steam_ip
	}
}
impl From<sys::SteamNetworkingIPAddr> for SteamIpAddr {
	fn from(inner: sys::SteamNetworkingIPAddr) -> Self {
		Self { inner }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Client;
	use std::net::Ipv4Addr;

	#[test]
	fn test_new_ip() {
		let ip = SteamIpAddr::new();
		assert_eq!(&ip.to_string(true), "[::]:0");
	}

	#[test]
	fn test_set_ipv4() {
		let mut ip = SteamIpAddr::new();
		let addr = Ipv4Addr::new(192, 168, 0, 123);
		ip.set_ipv4(SocketAddrV4::new(addr, 5555));
		assert_eq!(Some(addr), ip.get_ipv4());
		assert_eq!(&ip.to_string(true), "192.168.0.123:5555");
	}

	#[test]
	fn test_network_identity_steam_id() {
		let id = NetworkingIdentity::new_steam_id(SteamId(123456));
		assert_eq!("steamid:123456", &id.debug_string())
	}

	#[test]
	fn test_network_identity_ip() {
		let id = NetworkingIdentity::new_ip(SocketAddr::new(Ipv4Addr::new(192, 168, 0, 5).into(), 1234));
		assert_eq!("ip:192.168.0.5:1234", &id.debug_string())
	}

	#[test]
	fn test_allocate_and_free_message() {
		let (client, _single) = Client::init().unwrap();
		let utils = client.networking_utils();

		// With C buffer
		{
			let _message = utils.allocate_message(200);
			// Drop it immediately
		}

		// With rust buffer
		{
			let mut message = utils.allocate_message(0);
			message.set_data(vec![1, 2, 3, 4, 5]).unwrap();

			// Drop it immediately
		}
	}
}
