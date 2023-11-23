package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/xtaci/kcp-go"
)

type Packet struct {
	Time       int64       `json:"time"`
	FromServer bool        `json:"fromServer"`
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
	Meta       []byte      `json:"meta"`
}

type UniCmdItem struct {
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

var getPlayerTokenRspPacketId uint16
var unionCmdNotifyPacketId uint16
var noMetadataPacketId uint16

var initialKey = make(map[uint16][]byte)
var sessionSeed uint64
var serverSeed uint64
var sentMs uint64

var cmdIdKey uint16
var metaLenKey uint16
var packetList []*Packet
var keyPacket *Packet

var captureHandler *pcap.Handle
var kcpMap map[string]*kcp.KCP
var packetFilter = make(map[string]bool)
var pcapFile *os.File

func openPcap(fileName string) {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenOffline(fileName)
	if err != nil {
		log.Println("Could not open pacp file", err)
		return
	}
	startSniffer()
}

func openCapture() {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenLive(config.DeviceName, 1500, true, -1)
	if err != nil {
		log.Println("Could not open capture", err)
		return
	}

	if config.AutoSavePcapFiles {
		pcapFile, err = os.Create(time.Now().Format("06-01-02 15.04.05") + ".pcapng")
		if err != nil {
			log.Println("Could not create pcapng file", err)
		}
		defer pcapFile.Close()
	}

	startSniffer()
}

func closeHandle() {
	if captureHandler != nil {
		captureHandler.Close()
		captureHandler = nil
	}
	if pcapFile != nil {
		pcapFile.Close()
		pcapFile = nil
	}
}

func readKeys() {
	var initialKeyJson map[uint16]string
	file, err := os.ReadFile("./data/Keys.json")
	if err != nil {
		log.Fatal("Could not load initial key @ ./data/Keys.json #1", err)
	}
	err = json.Unmarshal(file, &initialKeyJson)
	if err != nil {
		log.Fatal("Could not load initial key @ ./data/Keys.json #2", err)
	}

	for k, v := range initialKeyJson {
		decode, _ := base64.RawStdEncoding.DecodeString(v)
		initialKey[k] = decode
	}

	getPlayerTokenRspPacketId = packetNameMap["GetPlayerTokenRsp"]
	unionCmdNotifyPacketId = packetNameMap["UnionCmdNotify"]
	noMetadataPacketId = 26219
}

func startSniffer() {
	defer captureHandler.Close()

	err := captureHandler.SetBPFFilter("udp portrange 22101-22102")
	if err != nil {
		log.Println("Could not set the filter of capture")
		return
	}

	packetSource := gopacket.NewPacketSource(captureHandler, captureHandler.LinkType())
	packetSource.NoCopy = true

	kcpMap = make(map[string]*kcp.KCP)

	var pcapWriter *pcapgo.NgWriter
	if pcapFile != nil {
		pcapWriter, err = pcapgo.NewNgWriter(pcapFile, captureHandler.LinkType())
		if err != nil {
			log.Println("Could not create pcapng writer", err)
		}
	}

	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Println("Could not write packet to pcap file", err)
			}
		}

		data := packet.ApplicationLayer().Payload()
		udp := packet.TransportLayer().(*layers.UDP)

		kcpPacket := &Packet{
			Time:       packet.Metadata().Timestamp.UnixMilli(),
			FromServer: udp.SrcPort == 22101 || udp.SrcPort == 22102,
			Raw:        data,
		}

		if len(data) <= 20 {
			handleSpecialPacket(kcpPacket)
			continue
		}

		handleKcp(kcpPacket)
	}
}

func handleKcp(packet *Packet) {
	packet.Raw = reformData(packet.Raw)
	conv := binary.LittleEndian.Uint32(packet.Raw[:4])
	key := strconv.Itoa(int(conv))
	if packet.FromServer {
		key += "svr"
	} else {
		key += "cli"
	}

	if _, ok := kcpMap[key]; !ok {
		kcpInstance := kcp.NewKCP(conv, func(buf []byte, size int) {})
		kcpInstance.WndSize(1024, 1024)
		kcpMap[key] = kcpInstance
	}
	kcpInstance := kcpMap[key]
	_ = kcpInstance.Input(packet.Raw, true, true)

	size := kcpInstance.PeekSize()
	for size > 0 {
		kcpBytes := make([]byte, size)
		kcpInstance.Recv(kcpBytes)
		kcpPacket := &Packet{
			Time:       packet.Time,
			FromServer: packet.FromServer,
			Raw:        kcpBytes,
		}
		findKey(kcpPacket)
		size = kcpInstance.PeekSize()
	}
	kcpInstance.Update()
}

func handleSpecialPacket(packet *Packet) {
	sessionSeed = 0
	serverSeed = 0
	sentMs = 0
	cmdIdKey = 0
	metaLenKey = 0
	packetList = nil
	keyPacket = nil
	switch binary.BigEndian.Uint32(packet.Raw[:4]) {
	case 0xFF:
		packet.Object = "Hamdshanke pls."
		buildPacketToSend(packet)
	case 404:
		packet.Object = "Disconnected."
		buildPacketToSend(packet)
	default:
		packet.Object = "Hamdshanke estamblished."
		buildPacketToSend(packet)
	}
}

func findKey(packet *Packet) {
	key := binary.BigEndian.Uint16(packet.Raw[:4])
	key = key ^ 0x4567
	var xorPad []byte

	packetList = append(packetList, packet)
	xorPad = initialKey[key]
	if xorPad == nil && cmdIdKey == 0 {
		seed := sessionSeed
		if seed == 0 {
			seed = sentMs
		}
		seed, xorPad = bruteforce(seed, serverSeed, packet.Raw)
		if xorPad == nil {
			log.Println("Could not found key to decrypt", key)
			if cmdIdKey == 0 {
				cmdIdRaw := binary.BigEndian.Uint16(packet.Raw[2:4])
				cmdId := packetNameMap["PlayerLoginReq"]
				cmdIdKey = cmdId ^ cmdIdRaw
			}
			return
			// closeHandle()
		}
		if sessionSeed == 0 {
			sessionSeed = seed
		}
		initialKey[key] = xorPad
	} else if cmdIdKey != 0 && metaLenKey == 0 {
		cmdId := binary.BigEndian.Uint16(packet.Raw[2:4]) ^ cmdIdKey
		if cmdId == packetNameMap["WindSeedType1Notify"] {
			keyPacket = packet
		}
		if cmdId == noMetadataPacketId {
			metaLenKey = 0 ^ binary.BigEndian.Uint16(packet.Raw[4:6])
		}
		return
	} else if cmdIdKey != 0 && metaLenKey != 0 && xorPad == nil {
		cmdId := binary.BigEndian.Uint16(packet.Raw[2:4]) ^ cmdIdKey
		if cmdId == packetNameMap["WindSeedType1Notify"] || keyPacket != nil {
			if keyPacket == nil {
				keyPacket = packet
			}
			metaLen := metaLenKey ^ binary.BigEndian.Uint16(keyPacket.Raw[4:6])
			packetRaw := keyPacket.Raw[10+metaLen : len(keyPacket.Raw)-2]
			xorDecrypt(packetRaw, initialKey[packetNameMap["WindSeedType1Notify"]])
			var buf bytes.Buffer
			binary.Write(&buf, binary.BigEndian, binary.BigEndian.Uint16(keyPacket.Raw[0:2])^0x4567)
			binary.Write(&buf, binary.BigEndian, cmdIdKey)
			binary.Write(&buf, binary.BigEndian, metaLenKey)
			prefix := buf.Bytes()
			packetString := hex.EncodeToString(packetRaw)
			combinedKeyFeature := hex.EncodeToString(prefix)

			lastIndex := -1
			index := 0
			dict := make(map[string]int)

			for {
				index = strings.Index(packetString[lastIndex+1:], combinedKeyFeature)
				if index == -1 {
					break
				}
				index += lastIndex + 1
				if lastIndex > 0 && index-lastIndex == 4096*2 {
					potentialKey := packetString[lastIndex:index]
					dict[potentialKey]++
				}
				lastIndex = index
			}

			if len(dict) > 0 {
				maxKey := ""
				maxValue := 0
				for k, v := range dict {
					if v > maxValue {
						maxKey = k
						maxValue = v
					}
				}
				log.Printf("Key: %s Count: %d\n", maxKey[:32], maxValue)
				xorPad, _ = hex.DecodeString(maxKey)
				initialKey[key] = xorPad
				return
			}
		} else {
			return
		}
	}

	if xorPad == nil {
		log.Println("Could not found packet to force decrypt", key)
		closeHandle()
	}

	for len(packetList) > 0 {
		p := packetList[0]
		packetList = packetList[1:]

		handleProtoPacket(p, xorPad)
	}
}

func handleProtoPacket(packet *Packet, xorPad []byte) {
	xorDecrypt(packet.Raw, xorPad)

	packetId := binary.BigEndian.Uint16(packet.Raw[2:4])
	metaLen := binary.BigEndian.Uint16(packet.Raw[4:6])
	meta := packet.Raw[10 : 10+metaLen]

	packet.PacketId = packetId
	packet.PacketName = GetProtoNameById(packetId)
	packet.Meta = meta
	packet.Raw = removeHeaderForParse(packet.Raw)
	packet.Object = parseProtoToInterface(packetId, packet.Raw)

	if !packet.FromServer && sentMs == 0 && len(packet.Raw) > 300 {
		metadataJson := parseProtoToInterface(0, meta)
		metadataMap := (*metadataJson).(map[string]interface{})
		sentMs = uint64(metadataMap["6"].(float64))
	} else if packet.FromServer && sessionSeed == 0 && len(packet.Raw) > 600 {
		handleGetPlayerTokenRspPacket(packet)
	} else if unionCmdNotifyPacketId != 0 && packetId == unionCmdNotifyPacketId {
		packet.Object = handleUnionCmdNotifyPacket(packet)
	}

	buildPacketToSend(packet)
}

func handleGetPlayerTokenRspPacket(packet *Packet) {
	var serverRandKey string
	objectInterface := packet.Object.(*interface{})
	objMap := (*objectInterface).(map[string]interface{})
	for _, v := range objMap {
		switch v := v.(type) {
		case string:
			serverRandKey = v
		case map[string]interface{}:
			if s, ok := v["__string"]; ok {
				serverRandKey, _ = s.(string)
			}
		}
		if strings.HasSuffix(serverRandKey, "==") {
			seed, err := base64.StdEncoding.DecodeString(serverRandKey)
			if err != nil {
				log.Println("Failed to decode server rand key")
				continue
			}
			seed, err = decrypt("data/private_key_4.pem", seed)
			if err != nil {
				log.Println("Failed to decrypt server rand key")
				continue
			}
			serverSeed = binary.BigEndian.Uint64(seed)
			log.Println("Server seed", serverSeed)
			break
		}
	}
}

func handleUnionCmdNotifyPacket(packet *Packet) interface{} {
	dMsg, err := parseProto(packet.PacketId, packet.Raw)
	if err != nil {
		log.Println("Could not parse UnionCmdNotify proto", err)
	}

	cmdList := dMsg.GetFieldByName("cmd_list").([]interface{})
	cmdListJson := make([]*UniCmdItem, len(cmdList))
	for i, item := range cmdList {
		msgItem := item.(*dynamic.Message)
		itemPacketId := uint16(msgItem.GetFieldByName("message_id").(uint32))
		itemData := msgItem.GetFieldByName("body").([]byte)

		childJson := parseProtoToInterface(itemPacketId, itemData)

		cmdListJson[i] = &UniCmdItem{
			PacketId:   itemPacketId,
			PacketName: GetProtoNameById(itemPacketId),
			Object:     childJson,
			Raw:        itemData,
		}
	}
	var objectJson interface{} = cmdListJson
	return objectJson
}

func buildPacketToSend(packet *Packet) {
	jsonResult, err := json.Marshal(packet)
	if err != nil {
		log.Println("Json marshal error", err)
	}
	logPacket(packet)

	// if packetFilter[GetProtoNameById(packetId)] {
	// 	return
	// }
	sendStreamMsg(string(jsonResult))
}

func logPacket(packet *Packet) {
	from := "[Client]"
	if packet.FromServer {
		from = "[Server]"
	}
	forward := ""
	if strings.Contains(packet.PacketName, "Rsp") {
		forward = "<--"
	} else if strings.Contains(packet.PacketName, "Req") {
		forward = "-->"
	} else if strings.Contains(packet.PacketName, "Notify") && packet.FromServer {
		forward = "<-i"
	} else if strings.Contains(packet.PacketName, "Notify") {
		forward = "i->"
	}

	log.Println(color.GreenString(from),
		"\t",
		color.CyanString(forward),
		"\t",
		color.RedString(packet.PacketName),
		color.YellowString("#"+strconv.Itoa(int(packet.PacketId))),
		"\t",
		len(packet.Raw),
	)

	if packet.PacketId == unionCmdNotifyPacketId {
		logUnionCmdNotifyPacket(packet)
	}
}

func logUnionCmdNotifyPacket(packet *Packet) {
	uniCmdItem := packet.Object.([]*UniCmdItem)

	for i, item := range uniCmdItem {
		group := "├─"
		if i == len(uniCmdItem) {
			group = "└─"
		}

		log.Println("\t",
			"\t",
			color.CyanString(group),
			"\t",
			color.RedString(item.PacketName),
			color.YellowString("#"+strconv.Itoa(int(item.PacketId))),
			"\t",
			len(item.Raw),
		)
	}
}
