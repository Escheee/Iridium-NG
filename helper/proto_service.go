package helper

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/syucream/protodump"
)

var msgMap = make(map[string]*desc.MessageDescriptor)
var packetIdMap map[uint16]string
var packetNameMap = make(map[string]uint16)
var protoParser = protoparse.Parser{}

func InitProto() {
	packetIdFile, _ := os.ReadFile("./data/packetIds.json")
	err := json.Unmarshal(packetIdFile, &packetIdMap)
	if err != nil {
		log.Fatalln("Could not load ./data/packetIds.json", err)
	}

	for k, v := range packetIdMap {
		packetNameMap[v] = k
	}

	protoParser.ImportPaths = []string{"./data/proto/"}
	for _, v := range packetIdMap {
		LoadProto(v)
	}

}

func LoadProto(protoName string) {
	fileDesc, err := protoParser.ParseFiles(protoName + ".proto")
	if err != nil {
		log.Println("Could not load proto file", protoName, err)
		return
	}

	msgMap[protoName] = fileDesc[0].FindMessage(protoName)
}

func GetProtoById(id uint16) *desc.MessageDescriptor {
	protoName, ok := packetIdMap[id]
	if !ok {
		return nil
	}
	return msgMap[protoName]
}

func GetProtoNameById(id uint16) string {
	protoName, ok := packetIdMap[id]
	if !ok {
		return strconv.Itoa(int(id))
	}
	return protoName
}

func parseProto(id uint16, data []byte) (*dynamic.Message, error) {
	msg := GetProtoById(id)
	if msg == nil {
		return nil, errors.New("not found")
	}
	dMsg := dynamic.NewMessage(msg)

	err := dMsg.Unmarshal(data)
	return dMsg, err
}

func parseProtoToJson(id uint16, data []byte) string {
	dMsg, err := parseProto(id, data)
	if err != nil {
		msg := protodump.Message{}
		err := protodump.Unmarshal(data, msg)
		if err != nil {
			return ""
		}
		jsonStr, err := json.Marshal(msg)
		if err != nil {
			return ""
		}
		return string(jsonStr)
	}

	marshalJSON, err := dMsg.MarshalJSON()
	if err != nil {
		return ""
	}

	return string(marshalJSON)
}

func parseProtoToInterface(id uint16, data []byte) *interface{} {
	object := parseProtoToJson(id, data)

	var result *interface{}
	err := json.Unmarshal([]byte(object), &result)
	if err != nil {
		return nil
	}

	return result
}