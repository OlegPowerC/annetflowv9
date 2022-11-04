package ANNetflowv9

import (
	"errors"
	"fmt"
	"net"
	"time"
)

//Go style exception handling
//Обработка исключений в стиле Го
func (NfOj *NetFlowV9Collector) recoverNetflowFuctionCrashes(err *error) {
	if nferr := recover(); nferr != nil {
		*err = fmt.Errorf("%s", nferr)
	}
}

func NewNetFlowV9Collector() *NetFlowV9Collector {
	var Nc NetFlowV9Collector
	Nc.Hosts = make(map[string]*HostData)

	//Список протоколов
	Nc.Protocols = map[uint16]string{
		1:  "icmp",
		2:  "igmp",
		4:  "ipv4",
		5:  "st",
		6:  "tcp",
		8:  "egp",
		9:  "igp",
		17: "udp",
		41: "ipv6",
		47: "gre",
		50: "esp",
		51: "ah",
		94: "ipip",
	}
	Nc.initialized = true
	return &Nc
}

func (NfOj *NetFlowV9Collector) templetePaceInside(dataf []byte, debuglevel int) (error int, templetear []FieldRec) {
	var retar []FieldRec
	retar = make([]FieldRec, 0)
	if len(dataf) < 4 {
		return 1, nil
	}
	if len(dataf)%2 != 0 {
		return 2, nil
	}
	mindex := 0
	var ftype, flenght uint16

	if debuglevel > 200 {
		fmt.Println(dataf)
	}

	for mindex < len(dataf) {
		ftype = uint16(dataf[mindex+1])
		ftype |= uint16(dataf[mindex]) << 8
		flenght = uint16(dataf[mindex+3])
		flenght |= uint16(dataf[mindex+2]) << 8
		retar = append(retar, FieldRec{FType: ftype, FLenght: flenght})
		mindex = mindex + 4
	}
	return 0, retar
}

func (NfOj *NetFlowV9Collector) parcetemplete(data []byte, agentip string, debuglevel int) (err error) {
	err = nil
	defer NfOj.recoverNetflowFuctionCrashes(&err)
	var alllenght uint16
	alllenght = uint16(data[3])
	alllenght |= uint16(data[2]) << 8

	var bindex uint16
	var eindex uint16
	bindex = 4
	eindex = 4

	var fcount uint16
	fcount = uint16(data[7])
	fcount |= uint16(data[6]) << 8

	var tdata1 []byte
	var TTempleteID uint16
	var FlowTemplete FlowsetTemplete
	lasttempleteinset := false
	if alllenght > 0 {
		for {

			TTempleteID = uint16(data[bindex+1])
			TTempleteID |= uint16(data[bindex]) << 8

			if debuglevel > 249 {
				fmt.Println(data)
				fmt.Println("Find Flowset templete id:", TTempleteID)
			}
			FlowTemplete.FieldCount = uint16(data[bindex+3])
			FlowTemplete.FieldCount |= uint16(data[bindex+2]) << 8

			bindex = bindex + 4
			eindex = bindex + FlowTemplete.FieldCount*4

			//checking for last templete in set
			//Проверяем не последний ли это шаблон в наборе
			if int(eindex) < len(data) {
				lasttempleteinset = false
			} else {
				lasttempleteinset = true
			}

			tdata1 = data[bindex:eindex]
			_, FlowTemplete.Fields = NfOj.templetePaceInside(tdata1, debuglevel)
			NfOj.Hosts[agentip].NetFlowTempletes[TTempleteID] = FlowTemplete

			//if ti is last templete - break
			//Если это последний темплат - выходим из цикла
			if lasttempleteinset {
				break
			}

			bindex = eindex
		}
	}
	return nil
}

func (NfOj *NetFlowV9Collector) decodedata(data []byte, TempleteId uint16, IP string, debuglevel int) rawflows {
	var flowsize uint16
	flowsize = 0
	flowcount := 0

	//подсчет длинны текущего потока (flow)по длинам полей
	for _, Aelm := range NfOj.Hosts[IP].NetFlowTempletes[TempleteId].Fields {
		flowsize = flowsize + Aelm.FLenght
	}

	var rawfd rawflows
	var oneflowsind, onefloweind uint16
	rawfd.Rawflowsdata = make([]Rawflow, 0)
	oneflowsind = 4
	onefloweind = oneflowsind + flowsize

	var tbs1 []byte
	fend := false

	for {
		if onefloweind <= uint16(len(data)) {
			if onefloweind < uint16(len(data)) {
				tbs1 = data[oneflowsind:onefloweind]
			} else {
				tbs1 = data[oneflowsind:]
			}
			flowcount++
		} else {
			fend = true
		}

		oneflowsind = onefloweind
		onefloweind = onefloweind + flowsize

		if fend {
			break
		}
		rawfd.Rawflowsdata = append(rawfd.Rawflowsdata, Rawflow{tbs1})
	}
	if debuglevel > 199 {
		fmt.Println("Flow count:", flowcount, "Flow in array", len(rawfd.Rawflowsdata))
	}
	return rawfd
}

//Конвертируем массив байт (до 8 штук) в uint64
func (NfOj *NetFlowV9Collector) convertbytestouint(buffer []byte) (uint64, error) {
	if len(buffer) > 8 {
		return 0, fmt.Errorf("error conver []byte to uint64, to many bytes: %d", len(buffer))
	}
	var uiresult uint64 = 0
	var offsett uint = 1
	for bcbytes := len(buffer) - 1; bcbytes >= 0; bcbytes-- {
		if bcbytes == len(buffer)-1 {
			uiresult = uint64(buffer[bcbytes])
		} else {
			uiresult |= uint64(buffer[bcbytes]) << (8 * offsett)
			offsett++
		}
	}
	return uiresult, nil
}

func (NfOj *NetFlowV9Collector) ParceNetflov9data(buffer *[]byte, IP string, debuglevel int) (NetflowData []NetflofJSONData, err error) {
	defer NfOj.recoverNetflowFuctionCrashes(&err)

	if !NfOj.initialized {
		return NetflowData, errors.New("object need to be inicialized")
	}

	NetflowData = make([]NetflofJSONData, 0)

	//Заполняем структуру заголовка NetFlow
	versionf64, err1 := NfOj.convertbytestouint((*buffer)[0:2])
	countf64, err2 := NfOj.convertbytestouint((*buffer)[2:4])
	suptime64, err3 := NfOj.convertbytestouint((*buffer)[4:8])
	unixseconds64, err4 := NfOj.convertbytestouint((*buffer)[8:12])
	packagesequence64, err5 := NfOj.convertbytestouint((*buffer)[12:16])
	sourceid64, err6 := NfOj.convertbytestouint((*buffer)[16:20])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil {
		return NetflowData, errors.New("parcing error")
	}

	versionf := uint16(versionf64)
	countf := uint16(countf64)
	suptime := uint32(suptime64)
	unixseconds := uint32(unixseconds64)
	packagesequence := uint32(packagesequence64)
	sourceid := uint32(sourceid64)

	if versionf != 9 {
		return NetflowData, fmt.Errorf("unsupported version: %d", versionf)
	}

	NH := Netflowheader{Version: versionf, Count: countf, SystemUpTimeInt32: suptime, UnixSecondsInt32: unixseconds, PackageSequence: packagesequence, SourceID: sourceid}
	uttm := time.Unix(int64(NH.UnixSecondsInt32), 0)

	llenght := NH.Count
	DataIndex := 20 //Где начанаются данные

	//Перебор всех наборов потоков (FlowSet)
	flowsetcount := 0
	cpind := true
	var FlowSetID uint16
	for cpind {
		var currentflenght uint16
		FlowSetID = uint16((*buffer)[DataIndex+1])
		FlowSetID |= uint16((*buffer)[DataIndex]) << 8
		currentflenght = uint16((*buffer)[DataIndex+3])
		currentflenght |= uint16((*buffer)[DataIndex+2]) << 8
		lastindex := DataIndex + int(currentflenght)
		var flowdata []byte

		flowdata = (*buffer)[DataIndex:lastindex]

		//Если FlowSet ID равно нулю, значит это шабон
		if FlowSetID == 0 {
			//Check host exist
			//Проверяем наличие хоста
			_, HostExist := NfOj.Hosts[IP]
			if !HostExist {
				TmMap := make(map[uint16]FlowsetTemplete)
				var TmHost HostData
				TmHost.NetFlowTempletes = TmMap
				TmHost.IpAddress = IP
				TmHost.UpTimeMs = uint64(NH.SystemUpTimeInt32)
				NfOj.Hosts[IP] = &TmHost
			} else {
				//Refresh UpTime
				//Обновляем UpTime
				NfOj.Hosts[IP].UpTimeMs = uint64(NH.SystemUpTimeInt32)
			}
			//Parce templete
			//Разбираем шаблон
			ParceTempleteErr := NfOj.parcetemplete(flowdata, IP, debuglevel)
			if ParceTempleteErr != nil {
				return NetflowData, ParceTempleteErr
			}

		} else {
			//It is data, find host and templete
			//Это не шаблон, ищем хост а в нем шаблоны
			if debuglevel > 100 {
				fmt.Println("Data templete is:", FlowSetID, "Ip is:", IP)
			}
			flowsetcount++
			ok := false
			_, okhost := NfOj.Hosts[IP]
			if okhost {
				_, ok = NfOj.Hosts[IP].NetFlowTempletes[FlowSetID]
			}

			if ok {
				if debuglevel > 100 {
					fmt.Println("Found templete")
				}
				//Разбивка данных на наборы (FlowSet)
				rdt1 := NfOj.decodedata(flowdata, FlowSetID, IP, debuglevel)
				//Разбор набора потоков (Flow), при этом шаблон у них один
				for _, flowdata := range rdt1.Rawflowsdata {
					var jsd NetflofJSONData
					var starti, endi uint16
					var pdata []byte
					starti = 0
					endi = 0
					jsd.DeviceIP = IP
					jsd.FlowDataUnixTime = uttm.String()
					for _, s := range NfOj.Hosts[IP].NetFlowTempletes[FlowSetID].Fields {
						endi = starti + s.FLenght
						if endi < uint16(len(flowdata.Rawflowdata)) {
							pdata = flowdata.Rawflowdata[starti:endi]
						} else {
							pdata = flowdata.Rawflowdata[starti:]
						}
						protostring := ""

						switch s.FType {
						case IPV4_SRC_ADDR:
							jsd.SRC_ip = net.IP(pdata).String()
							break
						case IPV4_DST_ADDR:
							jsd.DST_ip = net.IP(pdata).String()
							break
						case NF_F_XLATE_SRC_ADDR_IPV4:
							jsd.PostNATSource_ip = net.IP(pdata).String()
							break
						case NF_F_XLATE_DST_ADDR_IPV4:
							jsd.PostNATDestionation_ip = net.IP(pdata).String()
							break
						case INITIATOR_OCTETS:
							if debuglevel > 0 {
								if debuglevel > 249 {
									fmt.Println("FlowSetID", FlowSetID, "Field", s.FType, "Fieldlenght", s.FLenght)
									fmt.Println(pdata)
								}
							}

							TxBytes64, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.TX_bytes = int(TxBytes64)
							break
						case RESPONDER_OCTETS:
							if debuglevel > 0 {
								if debuglevel > 249 {
									fmt.Println("FlowSetID", FlowSetID, "Field", s.FType, "Fieldlenght", s.FLenght)
									fmt.Println(pdata)
								}
							}

							RXbytes64, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.RX_bytes = int(RXbytes64)
							break

						case NF_F_FW_EVENT:
							if debuglevel > 0 {
								if debuglevel > 249 {
									fmt.Println("FlowSetID", FlowSetID, "Field", s.FType, "Fieldlenght", s.FLenght)
									fmt.Println(pdata)
								}
							}

							Fevent64, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.FirewallEvent = int(Fevent64)
							break

						case NF_F_CONN_ID:
							if debuglevel > 0 {
								if debuglevel > 249 {
									fmt.Println("FlowSetID", FlowSetID, "Field", s.FType, "Fieldlenght", s.FLenght)
									fmt.Println(pdata)
								}
							}

							FconnectionUid, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.FlowUID = int(FconnectionUid)
							break

						case PROTOCOL:
							//Проверяем список протоколов
							_, pexist := NfOj.Protocols[uint16(pdata[0])]
							if pexist {
								//Найден - пишем протокол строкой
								protostring = NfOj.Protocols[uint16(pdata[0])]
							} else {
								//Не найден, пишем Protocol и его номер
								protostring = fmt.Sprintf("Protocol-%d", pdata[0])
							}
							jsd.Protocol = protostring
							break
						case SOURCE_PORT:
							SRCport64, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.SRC_port = int(SRCport64)
							break
						case DSTPORT:
							DSTport64, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.DST_port = int(DSTport64)
							break

						case NF_F_XLATE_SRC_PORT:
							PostNATSRCport64, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.PostNATSource_port = int(PostNATSRCport64)
							break
						case NF_F_XLATE_DST_PORT:
							PostNATDSTport64, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.PostNATDestionation_port = int(PostNATDSTport64)
							break

						case NF_F_SRC_INTF_ID:
							SRCintindex, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.InrgressIf = int(SRCintindex)
							break
						case NF_F_DST_INTF_ID:
							DSTintindex, err := NfOj.convertbytestouint(pdata)
							if err != nil {
								continue
							}
							jsd.EgressIf = int(DSTintindex)
							break
						default:
							break
						}
						starti = endi
					}
					NetflowData = append(NetflowData, jsd)
				}
			}
		}

		if lastindex >= len(*buffer) {
			cpind = false
		}
		llenght = llenght - 1
		DataIndex = DataIndex + int(currentflenght)
	}
	return NetflowData, nil
}
