package p2p

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/certusone/wormhole/node/pkg/common"
	"github.com/certusone/wormhole/node/pkg/guardiansigner"
	"github.com/certusone/wormhole/node/pkg/query"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/protobuf/proto"

	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	ccqP2pMessagesSent = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "wormhole_ccqp2p_broadcast_messages_sent_total",
			Help: "Total number of ccq p2p pubsub broadcast messages sent",
		})
	ccqP2pMessagesReceived = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wormhole_ccqp2p_broadcast_messages_received_total",
			Help: "Total number of ccq p2p pubsub broadcast messages received",
		}, []string{"type"})
	ccqP2pReceiveChannelOverflow = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wormhole_ccqp2p_receive_channel_overflow_total",
			Help: "Total number of ccq p2p pubsub messages dropped due to full channel",
		}, []string{"type"})
)

type ccqP2p struct {
	logger *zap.Logger

	h             host.Host
	th_req        *pubsub.Topic
	th_resp       *pubsub.Topic
	sub           *pubsub.Subscription
	allowedPeers  map[string]struct{}
	p2pComponents *Components
}

func newCcqRunP2p(
	logger *zap.Logger,
	allowedPeersStr string,
	components *Components,
) *ccqP2p {
	l := logger.With(zap.String("component", "ccqp2p"))
	allowedPeers := make(map[string]struct{})
	for _, peerID := range strings.Split(allowedPeersStr, ",") {
		if peerID != "" {
			l.Info("will allow requests from peer", zap.String("peerID", peerID))
			allowedPeers[peerID] = struct{}{}
		}
	}

	return &ccqP2p{
		logger:        l,
		allowedPeers:  allowedPeers,
		p2pComponents: components,
	}
}

func (ccq *ccqP2p) run(
	ctx context.Context,
	priv crypto.PrivKey,
	guardianSigner guardiansigner.GuardianSigner,
	p2pNetworkID string,
	bootstrapPeers string,
	port uint,
	signedQueryReqC chan<- *gossipv1.SignedQueryRequest,
	queryResponseReadC <-chan *query.QueryResponsePublication,
	protectedPeers []string,
	errC chan error,
) error {
	networkID := p2pNetworkID + "/ccq"
	var err error

	components := DefaultComponents()
	if components == nil {
		return fmt.Errorf("components is not initialized")
	}
	components.Port = port

	// Pass the gossip advertize address through to NewHost() if it was defined
	components.GossipAdvertiseAddress = ccq.p2pComponents.GossipAdvertiseAddress

	ccq.logger.Info("Creating CCQ P2P host", 
		zap.String("networkID", networkID), 
		zap.Uint("port", port),
		zap.String("bootstrapPeers", bootstrapPeers))
	
	ccq.h, err = NewHost(ccq.logger, ctx, networkID, bootstrapPeers, components, priv)
	if err != nil {
		return fmt.Errorf("failed to create p2p: %w", err)
	}

	ccq.logger.Info("CCQ P2P host created successfully", 
		zap.String("peerID", ccq.h.ID().String()),
		zap.Strings("addresses", getHostAddressStrings(ccq.h)))

	if len(protectedPeers) != 0 {
		ccq.logger.Info("Protecting configured peers", zap.Strings("protectedPeers", protectedPeers))
		for _, peerId := range protectedPeers {
			components.ConnMgr.Protect(peer.ID(peerId), "configured")
		}
	}

	// Build a map of bootstrap peers so we can always allow subscribe requests from them.
	bootstrapPeersMap := map[string]struct{}{}
	bootstrappers, _ := BootstrapAddrs(ccq.logger, bootstrapPeers, ccq.h.ID())
	for _, peer := range bootstrappers {
		bootstrapPeersMap[peer.ID.String()] = struct{}{}
	}

	ccq.logger.Info("Bootstrap peers mapped", zap.Int("bootstrapPeerCount", len(bootstrapPeersMap)))

	topic_req := fmt.Sprintf("%s/%s", networkID, "ccq_req")
	topic_resp := fmt.Sprintf("%s/%s", networkID, "ccq_resp")

	ccq.logger.Info("Creating pubsub topics", zap.String("request_topic", topic_req), zap.String("response_topic", topic_resp))
	
	// Log allowed peer information
	if len(ccq.allowedPeers) > 0 {
		allowedPeerList := make([]string, 0, len(ccq.allowedPeers))
		for peer := range ccq.allowedPeers {
			allowedPeerList = append(allowedPeerList, peer)
		}
		ccq.logger.Info("CCQ allowed peers configured", zap.Strings("allowedPeers", allowedPeerList))
	} else {
		ccq.logger.Info("No CCQ allowed peers configured - all peers will be accepted")
	}

	ps, err := pubsub.NewGossipSub(ctx, ccq.h,
		// We only want to accept subscribes from peers in the allow list.
		pubsub.WithPeerFilter(func(peerID peer.ID, topic string) bool {
			ccq.logger.Info("peer request received", zap.String("peerID", peerID.String()), zap.String("topic", topic))
			if len(ccq.allowedPeers) == 0 {
				return true
			}
			if _, found := ccq.allowedPeers[peerID.String()]; found {
				return true
			}
			ccq.p2pComponents.ProtectedHostByGuardianKeyLock.Lock()
			defer ccq.p2pComponents.ProtectedHostByGuardianKeyLock.Unlock()
			for _, guardianPeerID := range ccq.p2pComponents.ProtectedHostByGuardianKey {
				if peerID == guardianPeerID {
					return true
				}
			}
			if _, found := bootstrapPeersMap[peerID.String()]; found {
				return true
			}
			ccq.logger.Debug("Dropping subscribe attempt from unknown peer", zap.String("peerID", peerID.String()))
			return false
		}))
	if err != nil {
		return fmt.Errorf("failed to create new gossip sub for req: %w", err)
	}

	// We want to join and subscribe to the request topic. We will receive messages from there, but never write to it.
	ccq.th_req, err = ps.Join(topic_req)
	if err != nil {
		return fmt.Errorf("failed to join topic_req: %w", err)
	}

	// We only want to join the response topic. We will only write to it.
	ccq.th_resp, err = ps.Join(topic_resp)
	if err != nil {
		return fmt.Errorf("failed to join topic_resp: %w", err)
	}

	// We only want to accept messages from peers in the allow list.
	err = ps.RegisterTopicValidator(topic_req, func(ctx context.Context, from peer.ID, msg *pubsub.Message) bool {
		if len(ccq.allowedPeers) == 0 {
			return true
		}
		if _, found := ccq.allowedPeers[msg.GetFrom().String()]; found {
			return true
		}
		ccq.logger.Debug("Dropping message from unknown peer",
			zap.String("fromPeerID", from.String()),
			zap.String("msgPeerID", msg.ReceivedFrom.String()),
			zap.String("msgFrom", msg.GetFrom().String()))
		return false
	})
	if err != nil {
		return fmt.Errorf("failed to register message filter: %w", err)
	}

	// Increase the buffer size to prevent failed delivery to slower subscribers
	ccq.sub, err = ccq.th_req.Subscribe(pubsub.WithBufferSize(1024))
	if err != nil {
		return fmt.Errorf("failed to subscribe topic_req: %w", err)
	}

	common.StartRunnable(ctx, errC, false, "ccqp2p_listener", func(ctx context.Context) error {
		return ccq.listener(ctx, signedQueryReqC)
	})

	common.StartRunnable(ctx, errC, false, "ccqp2p_publisher", func(ctx context.Context) error {
		return ccq.publisher(ctx, guardianSigner, queryResponseReadC)
	})

	ccq.logger.Info("Node has been started", zap.String("peer_id", ccq.h.ID().String()), zap.String("addrs", fmt.Sprintf("%v", ccq.h.Addrs())))
	return nil
}

func (ccq *ccqP2p) close() {
	ccq.logger.Info("entering close")

	if err := ccq.th_req.Close(); err != nil && !errors.Is(err, context.Canceled) {
		ccq.logger.Error("Error closing the topic_req", zap.Error(err))
	}
	if err := ccq.th_resp.Close(); err != nil && !errors.Is(err, context.Canceled) {
		ccq.logger.Error("Error closing the topic_req", zap.Error(err))
	}

	ccq.sub.Cancel()

	if err := ccq.h.Close(); err != nil {
		ccq.logger.Error("error closing the host", zap.Error(err))
	}
}

func (ccq *ccqP2p) listener(ctx context.Context, signedQueryReqC chan<- *gossipv1.SignedQueryRequest) error {
	// Add logging for listener connectivity
	ccq.logger.Info("CCQ listener started", 
		zap.Int("connectedPeers", len(ccq.h.Network().Peers())),
		zap.String("topic", ccq.th_req.String()))
	
	// Start a periodic connectivity checker to log peer connections
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				currentPeers := ccq.h.Network().Peers()
				ccq.logger.Info("CCQ periodic connection status", 
					zap.Int("connectedPeerCount", len(currentPeers)))
				
				if ccq.logger.Level().Enabled(zapcore.DebugLevel) {
					peerList := make([]string, 0, len(currentPeers))
					for _, p := range currentPeers {
						peerList = append(peerList, p.String())
					}
					ccq.logger.Debug("CCQ connected peers detail", zap.Strings("peers", peerList))
				}
			}
		}
	}()

	for {
		envelope, err := ccq.sub.Next(ctx) // Note: sub.Next(ctx) will return an error once ctx is canceled
		if err != nil {
			ccq.logger.Error("failed to receive pubsub message", zap.Error(err))
			return fmt.Errorf("failed to receive pubsub message: %w", err)
		}

		ccq.logger.Debug("received message on CCQ request topic",
			zap.String("from", envelope.GetFrom().String()),
			zap.Int("dataSize", len(envelope.Data)))

		var msg gossipv1.GossipMessage
		err = proto.Unmarshal(envelope.Data, &msg)
		if err != nil {
			ccq.logger.Info("received invalid message",
				zap.Binary("data", envelope.Data),
				zap.String("from", envelope.GetFrom().String()),
				zap.Error(err))
			ccqP2pMessagesReceived.WithLabelValues("invalid").Inc()
			continue
		}

		if envelope.GetFrom() == ccq.h.ID() {
			ccq.logger.Debug("received message from ourselves, ignoring")
			ccqP2pMessagesReceived.WithLabelValues("loopback").Inc()
			continue
		}

		ccq.logger.Debug("received CCQ message",
			zap.Any("payload", msg.Message),
			zap.String("from", envelope.GetFrom().String()))

		switch m := msg.Message.(type) {
		case *gossipv1.GossipMessage_SignedQueryRequest:
			s := m.SignedQueryRequest

			ccq.logger.Debug("received signed query request",
				zap.Binary("signature", s.Signature),
				zap.String("from", envelope.GetFrom().String()),
				zap.Int("queryRequestSize", len(s.QueryRequest)))

			select {
			case signedQueryReqC <- s:
				ccqP2pMessagesReceived.WithLabelValues("signed_query_request").Inc()
				ccq.logger.Info("forwarded signed query request",
					zap.String("signature", hex.EncodeToString(s.Signature[:10])))
			default:
				ccq.logger.Warn("dropping signed query request - channel full",
					zap.String("signature", hex.EncodeToString(s.Signature[:10])))
				ccqP2pReceiveChannelOverflow.WithLabelValues("signed_query_request").Inc()
			}
		default:
			ccqP2pMessagesReceived.WithLabelValues("unknown").Inc()
			ccq.logger.Warn("received unknown message type (running outdated software?)",
				zap.Any("payload", msg.Message),
				zap.String("from", envelope.GetFrom().String()))
		}
	}
}

func (ccq *ccqP2p) publisher(ctx context.Context, guardianSigner guardiansigner.GuardianSigner, queryResponseReadC <-chan *query.QueryResponsePublication) error {
	ccq.logger.Info("CCQ publisher started", 
		zap.Int("connectedPeers", len(ccq.h.Network().Peers())),
		zap.String("topic", ccq.th_resp.String()))
	
	// Log connected peers at startup
	connectedPeers := ccq.h.Network().Peers()
	if len(connectedPeers) > 0 {
		peerList := make([]string, 0, len(connectedPeers))
		for _, p := range connectedPeers {
			peerList = append(peerList, p.String())
		}
		ccq.logger.Info("CCQ connected peers", zap.Strings("peers", peerList))
	} else {
		ccq.logger.Warn("CCQ has no connected peers at startup")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case msg := <-queryResponseReadC:
			ccq.logger.Debug("Received query response for publishing",
				zap.String("requestSignature", msg.Signature()),
				zap.Int("numResponses", len(msg.PerChainResponses)))
			
			// Get current connected peers
			currentPeers := ccq.h.Network().Peers()
			ccq.logger.Debug("Current CCQ peer connections",
				zap.Int("connectedPeerCount", len(currentPeers)))
			
			msgBytes, err := msg.Marshal()
			if err != nil {
				ccq.logger.Error("failed to marshal query response", zap.Error(err))
				continue
			}
			digest := query.GetQueryResponseDigestFromBytes(msgBytes)
			sig, err := guardianSigner.Sign(ctx, digest.Bytes())
			if err != nil {
				ccq.logger.Error("failed to sign query response", zap.Error(err))
				panic(err)
			}
			envelope := &gossipv1.GossipMessage{
				Message: &gossipv1.GossipMessage_SignedQueryResponse{
					SignedQueryResponse: &gossipv1.SignedQueryResponse{
						QueryResponse: msgBytes,
						Signature:     sig,
					},
				},
			}
			b, err := proto.Marshal(envelope)
			if err != nil {
				ccq.logger.Error("failed to marshal envelope", zap.Error(err))
				panic(err)
			}
			
			ccq.logger.Debug("Publishing query response", 
				zap.String("requestSignature", msg.Signature()),
				zap.Int("payloadSize", len(b)),
				zap.String("topic", ccq.th_resp.String()))
			
			err = ccq.th_resp.Publish(ctx, b)
			if err != nil {
				ccq.logger.Error("failed to publish query response",
					zap.String("requestSignature", msg.Signature()),
					zap.Any("query_response", msg),
					zap.Any("signature", sig),
					zap.Error(err),
				)
			} else {
				ccqP2pMessagesSent.Inc()
				ccq.logger.Info("published signed query response",
					zap.String("requestSignature", msg.Signature()),
					zap.Any("query_response", msg),
					zap.String("signature", hex.EncodeToString(sig[:10])), // Only log first few bytes of signature
					zap.Int("payloadSize", len(b)),
					zap.Int("connectedPeers", len(currentPeers)),
				)
			}
		}
	}
}

// Helper function to convert host addresses to strings
func getHostAddressStrings(h host.Host) []string {
	addrStrings := make([]string, 0, len(h.Addrs()))
	for _, addr := range h.Addrs() {
		addrStrings = append(addrStrings, addr.String())
	}
	return addrStrings
}
