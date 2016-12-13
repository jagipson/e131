package e132

import (
	"encoding/binary"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"os"
)

type Universe struct {
	Slots  [512]byte
	Number uint8
}

func (u Universe) StartCode() *byte {
	return &u.Slots[0]
}

func (u Universe) Data() []byte {
	return u.Slots[1:]
}

// e1.31 Root Layer Packet (rlp) constants
var (
	rlpPreambleSize                  = []byte{0x00, 0x10}
	rlpPostambleSize                 = []byte{0x00, 0x00}
	rlpAcnPacketIdentifier           = []byte{0x41, 0x53, 0x43, 0x2d, 0x45, 0x31, 0x2e, 0x31, 0x37, 0x00, 0x00, 0x00}
	rlpProtoFlags             uint16 = 0x7000
	rlpVectorRootE131Data            = []byte{0x00, 0x00, 0x00, 0x04}
	rlpVectorRootE131Extended        = []byte{0x00, 0x00, 0x00, 0x08}
)

// e1.31 rlp vars

// rlpCid is the UUID that corresponds to a network component. For hardware this
// is in ROM. For software, it should be generated.
var rlpCid uuid.UUID

// e1.31 Framing Layer Packet (flp) constants
var (
	flpProtoFlags             uint16 = 0x7000
	flpVectorE131DataPacket          = []byte{0x00, 0x00, 0x00, 0x02}
	flpVectorE131ExtendedSync        = []byte{0x00, 0x00, 0x00, 0x01}
	flpVectorE131ExtendedDisc        = []byte{0x00, 0x00, 0x00, 0x02}
	flpPreviewDataFlag               = []byte{0x80}
	flpStreamTerminateFlag           = []byte{0x40}
	flpForceSyncFlag                 = []byte{0x20}
)

// e1.31 flp vars

// flpSourceName is a user-assigned name. It's default value will be
// go131-[PID]
var flpSourceName []byte

// SetSourceName sets the user-assigned source name for the framing layer of
// the sACN packet.
func SetSourceName(s string) error {
	if len(s) == 0 {
		return fmt.Errorf("Cannot set empty e131 Source Name")
	}
	if len(s) > 63 {
		return fmt.Errorf("Cannot set e131 Source Name longer than 63 bytes")
	}
	copy(flpSourceName[:], s)
	return nil
}

// SourceName returns the user-assigned source name used by the framing layer
// of the sACN packet.
func SourceName() string {
	return string(flpSourceName[:])
}

// DMX Priority must be from 0-200, default 100
var flpPriority uint8

// SetPriority sets the DMX message priority. It should be from 0-200 with 100
// being the default. The priority 100 has greater priority than 0 and less
// priority than 200.
func SetPriority(i int) error {
	if i >= 0 && i <= 200 {
		flpPriority = uint8(i)
		return nil
	}
	return fmt.Errorf("Unable to set Priority (out of bounds)")
}

// e1.31 DMP Layer Packet (dmp) constants
var (
	dmpProtoFlags           uint16 = 0x7000
	dmpVectorDmpSetProperty        = []byte{0x02}
	dmpAddressTypeDataType         = []byte{0xa1}
	dmpFirstPropertyAddress        = []byte{0x00, 0x00}
	dmpAddressIncrement            = []byte{0x00, 0x01}
)

// e1.31 Universe Discovery Layer (udl) constants
var (
	udlProtoFlags             uint16 = 0x7000
	udlVectorUnivDiscUnivList        = []byte{0x00, 0x00, 0x00, 0x01}
)

func init() {
	rlpCid = uuid.NewV4()
	if err := SetSourceName(fmt.Sprintf("go131-%d", os.Getpid())); err != nil {
		panic(err)
	}
	if err := SetPriority(100); err != nil {
		panic(err)
	}
}

// build the root layer
func packetRootLayer(vector []byte, dataLength uint16) []byte {
	var data []byte

	data = append(data, rlpPreambleSize...)
	data = append(data, rlpPostambleSize...)
	data = append(data, rlpAcnPacketIdentifier...)
	data = append(data, byte(dataLength|rlpProtoFlags))
	data = append(data, []byte(vector)...)
	return data
}

func discPacket(syncAddr uint16, seqID uint8, universes []Universe) ([]byte, error) {
	var universeIDs []uint8
	for _, v := range universes {
		universeIDs = append(universeIDs, v.Number)
	}

	var data []byte
	// build the root layer
	data = append(data, packetRootLayer(rlpVectorRootE131Extended, uint16(len(universeIDs)*2+104))...)

	// build the framing layer
	data = append(data, 0x00, 0x00)
	flpLength := uint16((len(universeIDs)*2 + 82)) | flpProtoFlags
	binary.BigEndian.PutUint16(data[len(data)-2:], flpLength)

	data = append(data, flpVectorE131ExtendedDisc...)
	data = append(data, flpSourceName...)
	data = append(data, 0x00, 0x00, 0x00, 0x00)

	// build the universe discovery layer
	data = append(data, 0x00, 0x00)
	udlLength := uint16((len(universeIDs) + 8)) | flpProtoFlags
	binary.BigEndian.PutUint16(data[len(data)-2:], udlLength)

	// hard-coding page=0 lastpage=0 gives us a max of 512 universes
	data = append(data, udlVectorUnivDiscUnivList...)
	data = append(data, 0x00, 0x00)
	data = append(data, universeIDs...)

	return data, nil
}

func syncPacket(syncAddr uint8, seqID uint8) ([]byte, error) {
	var data []byte
	// build the root layer
	data = packetRootLayer(rlpVectorRootE131Extended, 33)

	// build the framing layer
	data = append(data, 0x00, 0x00)
	flpLength := 11 | flpProtoFlags
	binary.BigEndian.PutUint16(data[len(data)-2:], flpLength)

	data = append(data, flpVectorE131ExtendedSync...)
	data = append(data, seqID)
	data = append(data, syncAddr)
	data = append(data, 0x00, 0x00) // reserved bytes
	return data, nil
}

// return data packet payload or error
func DataPacket(syncAddr uint16, seqID uint8, optionsFlags byte, universe Universe) ([]byte, error) {
	var data []byte
	// build the root layer
	data = packetRootLayer(rlpVectorRootE131Data, uint16(len(universe.Slots)+109))

	// build the framing layer
	data = append(data, 0x00, 0x00)
	flpLength := uint16((len(universe.Slots) + 87)) | flpProtoFlags
	binary.BigEndian.PutUint16(data[len(data)-2:], flpLength)

	data = append(data, flpVectorE131DataPacket...)
	data = append(data, flpSourceName...)
	data = append(data, flpPriority)
	addrBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(addrBytes, syncAddr)
	data = append(data, addrBytes...)
	data = append(data, seqID)
	data = append(data, optionsFlags)
	data = append(data, universe.Number)

	// build the dmp layer
	data = append(data, 0x00, 0x00)
	dmpLength := uint16((len(universe.Slots) + 10)) | dmpProtoFlags
	binary.BigEndian.PutUint16(data[len(data)-2:], dmpLength)

	data = append(data, dmpVectorDmpSetProperty...)
	data = append(data, dmpAddressTypeDataType...)
	data = append(data, dmpFirstPropertyAddress...)
	data = append(data, dmpAddressIncrement...)
	// we hard-code 513 as the Property Value Count since we send the entire
	// 512 byte universe and the start code, then we encode a 0-value start
	// code
	data = append(data, 0x02, 0x01, 0x00)
	data = append(data, universe.Slots[:]...)

	return data, nil
}
