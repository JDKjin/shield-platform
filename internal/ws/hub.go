package ws

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"shield-platform/internal/util"
)

// Message 面板 <-> Agent / 浏览器 通用消息
type Message struct {
	ID   string          `json:"id"`
	Type string          `json:"type"` // hello|heartbeat|monitor|alert|cmd_result|exec|harden|scan|deploy_waf|ack
	To   string          `json:"to,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
	TS   int64           `json:"ts"`
}

// NewMsg 构造消息
func NewMsg(typ string, data interface{}) *Message {
	var raw json.RawMessage
	if data != nil {
		raw, _ = json.Marshal(data)
	}
	return &Message{ID: util.GenID(), Type: typ, Data: raw, TS: time.Now().Unix()}
}

// AgentConn 一台靶机 Agent 的连接
type AgentConn struct {
	TargetID string
	Name     string
	OS       string
	Arch     string
	Conn     *websocket.Conn
	LastSeen int64
}

// Hub WebSocket 中心
type Hub struct {
	mu        sync.RWMutex
	agents    map[string]*AgentConn
	panelCh   chan []byte // 推送给浏览器的广播
	onMessage func(m *Message) // 收到 agent 消息回调（由 api 层注入）
	logger    *util.Logger
}

func NewHub(logger *util.Logger) *Hub {
	return &Hub{
		agents:    make(map[string]*AgentConn),
		panelCh:   make(chan []byte, 512),
		onMessage: func(m *Message) {},
		logger:    logger,
	}
}

// SetMessageHandler 注入消息处理回调
func (h *Hub) SetMessageHandler(fn func(m *Message)) {
	h.onMessage = fn
}

// PanelChannel 浏览器广播通道
func (h *Hub) PanelChannel() chan []byte {
	return h.panelCh
}

// BroadcastPanel 广播给所有浏览器客户端
func (h *Hub) BroadcastPanel(m *Message) {
	b, _ := json.Marshal(m)
	select {
	case h.panelCh <- b:
	default:
		h.logger.Warnf("panel channel full, drop msg %s", m.Type)
	}
}

// RegisterAgent 注册 agent
func (h *Hub) RegisterAgent(a *AgentConn) {
	h.mu.Lock()
	h.agents[a.TargetID] = a
	h.mu.Unlock()
	h.logger.Infof("agent online: %s (%s/%s)", a.Name, a.OS, a.Arch)
}

// UnregisterAgent 移除 agent
func (h *Hub) UnregisterAgent(id string) {
	h.mu.Lock()
	delete(h.agents, id)
	h.mu.Unlock()
	h.logger.Infof("agent offline: %s", id)
}

// GetAgent 获取 agent 连接
func (h *Hub) GetAgent(id string) (*AgentConn, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	a, ok := h.agents[id]
	return a, ok
}

// OnlineAgents 在线 agent 列表
func (h *Hub) OnlineAgents() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []string
	for id := range h.agents {
		out = append(out, id)
	}
	return out
}

// SendToAgent 给指定 agent 发送消息
func (h *Hub) SendToAgent(ctx context.Context, targetID string, m *Message) error {
	a, ok := h.GetAgent(targetID)
	if !ok {
		return ErrAgentOffline
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return wsjson.Write(ctx, a.Conn, m)
}

// ErrAgentOffline agent 不在线
var ErrAgentOffline = &util.AppError{Msg: "agent offline"}

// ReadAgentLoop 读取 agent 消息循环
func (h *Hub) ReadAgentLoop(a *AgentConn) {
	ctx := a.Conn.CloseRead(context.Background())
	defer h.UnregisterAgent(a.TargetID)
	for {
		var m Message
		if err := wsjson.Read(ctx, a.Conn, &m); err != nil {
			h.logger.Debugf("agent %s read closed: %v", a.TargetID, err)
			return
		}
		a.LastSeen = time.Now().Unix()
		h.onMessage(&m)
	}
}

// WriteAgentLoop 后台向 agent 发送 pending 消息（当前使用即时写，保留该结构便于扩展）
func (h *Hub) WriteAgentLoop(a *AgentConn) {}

// HandlePanelConn 处理浏览器连接，持续推送广播
func (h *Hub) HandlePanelConn(conn *websocket.Conn, clientID string, done func()) {
	ctx := conn.CloseRead(context.Background())
	defer done()
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case b := <-h.panelCh:
			if err := wsjson.Write(ctx, conn, json.RawMessage(b)); err != nil {
				return
			}
		case <-heartbeat.C:
			if err := wsjson.Write(ctx, conn, NewMsg("ping", nil)); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
