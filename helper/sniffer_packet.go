package helper

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

var kcpMap map[string]*kcp.KCP

func ReadKeys() {
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

	kcpMap = make(map[string]*kcp.KCP)
}

func HandleKcp(packet *Packet) []*Packet {
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

	kcpList := make([]*Packet, 0)
	size := kcpInstance.PeekSize()
	for size > 0 {
		kcpBytes := make([]byte, size)
		kcpInstance.Recv(kcpBytes)
		kcpPacket := &Packet{
			Time:       packet.Time,
			FromServer: packet.FromServer,
			Raw:        kcpBytes,
		}
		kcpList = append(kcpList, findKey(kcpPacket)...)
		size = kcpInstance.PeekSize()
	}
	kcpInstance.Update()
	return kcpList
}

func HandleSpecialPacket(packet *Packet) *Packet {
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
	case 404:
		packet.Object = "Disconnected."
	default:
		packet.Object = "Hamdshanke estamblished."
	}
	return packet
}

func findKey(packet *Packet) []*Packet {
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
				cmdId := uint16(24761)
				cmdIdKey = cmdId ^ cmdIdRaw
			}
			return nil
		}
		if sessionSeed == 0 {
			sessionSeed = seed
		}
		initialKey[key] = xorPad
	} else if cmdIdKey != 0 && metaLenKey == 0 {
		cmdId := binary.BigEndian.Uint16(packet.Raw[2:4]) ^ cmdIdKey
		if cmdId == uint16(22320) {
			keyPacket = packet
		}
		if cmdId == noMetadataPacketId {
			metaLenKey = 0 ^ binary.BigEndian.Uint16(packet.Raw[4:6])
		}
		return nil
	} else if cmdIdKey != 0 && metaLenKey != 0 && xorPad == nil {
		cmdId := binary.BigEndian.Uint16(packet.Raw[2:4]) ^ cmdIdKey
		if cmdId == uint16(22320) || keyPacket != nil {
			if keyPacket == nil {
				keyPacket = packet
			}
			metaLen := metaLenKey ^ binary.BigEndian.Uint16(keyPacket.Raw[4:6])
			packetRaw := keyPacket.Raw[10+metaLen : len(keyPacket.Raw)-2]
			xorDecrypt(packetRaw, initialKey[uint16(22320)])
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
				return nil
			}
		} else {
			return nil
		}
	}

	if xorPad == nil {
		log.Fatalln("Could not found packet to force decrypt", key)
	}

	protoList := make([]*Packet, 0)
	for len(packetList) > 0 {
		p := packetList[0]
		packetList = packetList[1:]

		protoList = append(protoList, handleProtoPacket(p, xorPad))
	}
	return protoList
}

func handleProtoPacket(packet *Packet, xorPad []byte) *Packet {
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
	} else if packet.FromServer && serverSeed == 0 && len(packet.Raw) > 600 {
		handleGetPlayerTokenRspPacket(packet)
	} else if unionCmdNotifyPacketId != 0 && packetId == unionCmdNotifyPacketId {
		packet.Object = handleUnionCmdNotifyPacket(packet)
	}

	return packet
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
