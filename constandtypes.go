package ANNetflowv9

const (
	IPV4_SRC_ADDR            = 8
	IPV4_DST_ADDR            = 12
	PROTOCOL                 = 4
	INBYTES                  = 1
	OUTPUTBYTES              = 23
	INITIATOR_OCTETS         = 231
	RESPONDER_OCTETS         = 232
	SOURCE_PORT              = 7
	DSTPORT                  = 11
	NF_F_FW_EVENT            = 233
	NF_F_XLATE_SRC_ADDR_IPV4 = 225
	NF_F_XLATE_DST_ADDR_IPV4 = 226
	NF_F_XLATE_SRC_PORT      = 227
	NF_F_XLATE_DST_PORT      = 228
	NF_F_CONN_ID             = 148
	NF_F_CONN_ID_LENGHT      = 4
	NF_F_SRC_INTF_ID         = 10
	NF_F_DST_INTF_ID         = 14

	NF_F_FW_EVENT_Default = 0 //—Default (ignore)
	NF_F_FW_EVENT_Created = 1 //—Flow created
	NF_F_FW_EVENT_Delete  = 2 //—Flow deleted
	NF_F_FW_EVENT_Denied  = 3 //—Flow denied
	NF_F_FW_EVENT_Alert   = 4 //—Flow alert
	NF_F_FW_EVENT__Update = 5 //—Flow update
	RXBUFFERSIZE          = 4096
)

type NetFlowV9Collector struct {
	Hosts     map[string]*HostData
	Protocols map[uint16]string
	//HostRefreshMutex 		sync.Mutex
	initialized bool
}

//data of single Flow
//Данные о записи - Flow
type NetflofJSONData struct {
	FlowUID                  int    `json:"flow_uid"`
	DeviceIP                 string `json:"deviceip"`
	FlowDataUnixTime         string `json:"flowdataunixtime"`
	SRC_ip                   string `json:"srcip"`
	DST_ip                   string `json:"dstip"`
	Protocol                 string `json:"protocol"`
	SRC_port                 int    `json:"srcport"`
	DST_port                 int    `json:"dstport"`
	RX_bytes                 int    `json:"rxbytes"`
	TX_bytes                 int    `json:"txbytes"`
	FirewallEvent            int    `json:"firewall_event"`
	PostNATSource_ip         string `json:"PostNATsrcip"`
	PostNATDestionation_ip   string `json:"PostNATdstip"`
	PostNATSource_port       int    `json:"PostNATsrcport"`
	PostNATDestionation_port int    `json:"PostNATdstport"`
	InrgressIf               int    `json:"IngressIf"`
	EgressIf                 int    `json:"EgressIf"`
}

//Netflow header
//Заголовок NetFlow
type Netflowheader struct {
	Version           uint16
	Count             uint16
	SystemUpTimeInt32 uint32
	UnixSecondsInt32  uint32
	PackageSequence   uint32
	SourceID          uint32
}

//Templete ID and source IP addres
//Идкнтификатор шаблона и IP адрес источника
type HostData struct {
	IpAddress        string
	UpTimeMs         uint64
	NetFlowTempletes map[uint16]FlowsetTemplete
}

type FieldRec struct {
	FType   uint16
	FLenght uint16
}

type FlowsetTemplete struct {
	FieldCount uint16
	Fields     []FieldRec
}

type Rawflow struct {
	Rawflowdata []byte
}

type rawflows struct {
	Rawflowsdata []Rawflow
}
