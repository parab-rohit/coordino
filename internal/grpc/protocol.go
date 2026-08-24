package grpc

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const SocketPath = "/var/run/coordino/cni.sock"

// AddRequest defines the parameters for adding a container to the network.
type AddRequest struct {
	ContainerID  string            `json:"containerID"`
	Netns        string            `json:"netns"`
	IfName       string            `json:"ifName"`
	PodName      string            `json:"podName"`
	PodNamespace string            `json:"podNamespace"`
	Args         map[string]string `json:"args"`
}

// Route defines a network route.
type Route struct {
	Dst string `json:"dst"`
	GW  string `json:"gw"`
}

// DNSConfig defines DNS configuration.
type DNSConfig struct {
	Nameservers []string `json:"nameservers"`
	Domain      string   `json:"domain"`
	Search      []string `json:"search"`
}

// AddResponse defines the response to an AddRequest.
type AddResponse struct {
	IP      string    `json:"ip"`
	Gateway string    `json:"gateway"`
	Routes  []Route   `json:"routes"`
	DNS     DNSConfig `json:"dns"`
	Error   string    `json:"error,omitempty"`
}

// DelRequest defines the parameters for removing a container from the network.
type DelRequest struct {
	ContainerID  string `json:"containerID"`
	Netns        string `json:"netns"`
	IfName       string `json:"ifName"`
	PodName      string `json:"podName"`
	PodNamespace string `json:"podNamespace"`
}

// DelResponse defines the response to a DelRequest.
type DelResponse struct {
	Error string `json:"error,omitempty"`
}

// CheckRequest defines the parameters for checking a container's network status.
type CheckRequest struct {
	ContainerID  string `json:"containerID"`
	Netns        string `json:"netns"`
	IfName       string `json:"ifName"`
	PodName      string `json:"podName"`
	PodNamespace string `json:"podNamespace"`
}

// CheckResponse defines the response to a CheckRequest.
type CheckResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// HealthResponse defines the health status of the node agent.
type HealthResponse struct {
	Healthy bool   `json:"healthy"`
	Version string `json:"version"`
	Uptime  int64  `json:"uptime"`
}

// Client is a client for the node agent gRPC-like protocol.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// NewClient creates a new Client.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		timeout:    30 * time.Second,
	}
}

type requestWrapper struct {
	Method string      `json:"method"`
	Data   interface{} `json:"data"`
}

func (c *Client) sendRequest(method string, req interface{}) ([]byte, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to node agent: %v", err)
	}
	defer conn.Close()

	wrapper := requestWrapper{
		Method: method,
		Data:   req,
	}

	if err := json.NewEncoder(conn).Encode(wrapper); err != nil {
		return nil, fmt.Errorf("failed to encode request: %v", err)
	}

	// Read everything until connection is closed as the response
	// In a simple JSON protocol, we expect one JSON object
	// For simplicity, we'll use a buffer
	respData, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	return respData, nil
}

func (c *Client) Add(req *AddRequest) (*AddResponse, error) {
	resp := &AddResponse{}
	data, err := c.sendRequest("ADD", req)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return resp, nil
}

func (c *Client) Del(req *DelRequest) (*DelResponse, error) {
	resp := &DelResponse{}
	data, err := c.sendRequest("DEL", req)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return resp, nil
}

func (c *Client) Check(req *CheckRequest) (*CheckResponse, error) {
	resp := &CheckResponse{}
	data, err := c.sendRequest("CHECK", req)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return resp, nil
}

func (c *Client) Health() (*HealthResponse, error) {
	resp := &HealthResponse{}
	data, err := c.sendRequest("HEALTH", nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return resp, nil
}

// RequestHandler defines the interface for handling node agent requests.
type RequestHandler interface {
	HandleAdd(req *AddRequest) (*AddResponse, error)
	HandleDel(req *DelRequest) (*DelResponse, error)
	HandleCheck(req *CheckRequest) (*CheckResponse, error)
}

// Server is a server for the node agent gRPC-like protocol.
type Server struct {
	socketPath string
	listener   net.Listener
	handler    RequestHandler
}

// NewServer creates a new Server.
func NewServer(socketPath string, handler RequestHandler) *Server {
	return &Server{
		socketPath: socketPath,
		handler:    handler,
	}
}

// Start starts the server.
func (s *Server) Start() error {
	if _, err := os.Stat(s.socketPath); err == nil {
		if err := os.Remove(s.socketPath); err != nil {
			return fmt.Errorf("failed to remove existing socket: %v", err)
		}
	}

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket: %v", err)
	}
	s.listener = l

	// Set permissions for the socket
	if err := os.Chmod(s.socketPath, 0660); err != nil {
		return fmt.Errorf("failed to set socket permissions: %v", err)
	}

	go s.acceptLoop()
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	var wrapper struct {
		Method string          `json:"method"`
		Data   json.RawMessage `json:"data"`
	}

	if err := json.NewDecoder(conn).Decode(&wrapper); err != nil {
		return
	}

	var resp interface{}
	var err error

	switch wrapper.Method {
	case "ADD":
		var req AddRequest
		if err = json.Unmarshal(wrapper.Data, &req); err == nil {
			resp, err = s.handler.HandleAdd(&req)
		}
	case "DEL":
		var req DelRequest
		if err = json.Unmarshal(wrapper.Data, &req); err == nil {
			resp, err = s.handler.HandleDel(&req)
		}
	case "CHECK":
		var req CheckRequest
		if err = json.Unmarshal(wrapper.Data, &req); err == nil {
			resp, err = s.handler.HandleCheck(&req)
		}
	case "HEALTH":
		// Server handles health internally or we could add it to handler
		resp = &HealthResponse{Healthy: true, Version: "1.0.0", Uptime: time.Now().Unix()}
	default:
		err = fmt.Errorf("unknown method: %s", wrapper.Method)
	}

	if err != nil {
		// Try to send error response back if possible, but for simplicity here we just use the Error field in structs
		// In a real implementation we'd have a more robust error handling
	}

	if resp != nil {
		json.NewEncoder(conn).Encode(resp)
	}
}

// Stop stops the server.
func (s *Server) Stop() error {
	if s.listener != nil {
		err := s.listener.Close()
		os.Remove(s.socketPath)
		return err
	}
	return nil
}
