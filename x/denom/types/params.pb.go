// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: kujira/denom/params.proto

package types

import (
	fmt "fmt"
	_ "github.com/cosmos/cosmos-proto"
	github_com_cosmos_cosmos_sdk_types "github.com/cosmos/cosmos-sdk/types"
	types "github.com/cosmos/cosmos-sdk/types"
	_ "github.com/cosmos/gogoproto/gogoproto"
	proto "github.com/cosmos/gogoproto/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Params holds parameters for the denom module
type Params struct {
	CreationFee github_com_cosmos_cosmos_sdk_types.Coins `protobuf:"bytes,1,rep,name=creation_fee,json=creationFee,proto3,castrepeated=github.com/cosmos/cosmos-sdk/types.Coins" json:"creation_fee" yaml:"creation_fee"`
	// whitelisted accounts that do not require paying creation fees
	NoFeeAccounts []string `protobuf:"bytes,2,rep,name=no_fee_accounts,json=noFeeAccounts,proto3" json:"no_fee_accounts,omitempty"`
}

func (m *Params) Reset()         { *m = Params{} }
func (m *Params) String() string { return proto.CompactTextString(m) }
func (*Params) ProtoMessage()    {}
func (*Params) Descriptor() ([]byte, []int) {
	return fileDescriptor_438872cf7b898b83, []int{0}
}
func (m *Params) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params.Merge(m, src)
}
func (m *Params) XXX_Size() int {
	return m.Size()
}
func (m *Params) XXX_DiscardUnknown() {
	xxx_messageInfo_Params.DiscardUnknown(m)
}

var xxx_messageInfo_Params proto.InternalMessageInfo

func (m *Params) GetCreationFee() github_com_cosmos_cosmos_sdk_types.Coins {
	if m != nil {
		return m.CreationFee
	}
	return nil
}

func (m *Params) GetNoFeeAccounts() []string {
	if m != nil {
		return m.NoFeeAccounts
	}
	return nil
}

func init() {
	proto.RegisterType((*Params)(nil), "kujira.denom.Params")
}

func init() { proto.RegisterFile("kujira/denom/params.proto", fileDescriptor_438872cf7b898b83) }

var fileDescriptor_438872cf7b898b83 = []byte{
	// 322 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x54, 0x90, 0xb1, 0x4e, 0x3a, 0x41,
	0x10, 0xc6, 0xef, 0xfe, 0x24, 0x24, 0xff, 0x03, 0x63, 0x82, 0x16, 0x40, 0xb1, 0x10, 0x62, 0x0c,
	0x16, 0xdc, 0x06, 0xed, 0xec, 0x84, 0x04, 0x0b, 0x63, 0x62, 0x88, 0x95, 0x0d, 0x99, 0x5b, 0x46,
	0x38, 0xf1, 0x76, 0xc8, 0xed, 0x9e, 0x91, 0x07, 0xb0, 0xf7, 0x39, 0x7c, 0x02, 0x1f, 0x81, 0x92,
	0xd2, 0x0a, 0x0d, 0xbc, 0x81, 0x4f, 0x60, 0x6e, 0x77, 0x4d, 0xb0, 0xda, 0x9d, 0xf9, 0xe6, 0xfb,
	0xcd, 0xe4, 0x0b, 0x6a, 0xb3, 0xec, 0x21, 0x4e, 0x81, 0x8f, 0x51, 0x52, 0xc2, 0xe7, 0x90, 0x42,
	0xa2, 0xc2, 0x79, 0x4a, 0x9a, 0x2a, 0x65, 0x2b, 0x85, 0x46, 0xaa, 0x1f, 0x4e, 0x68, 0x42, 0x46,
	0xe0, 0xf9, 0xcf, 0xce, 0xd4, 0x8f, 0xfe, 0xd8, 0x21, 0xd3, 0x53, 0x4a, 0x63, 0xbd, 0xb8, 0x46,
	0x0d, 0x63, 0xd0, 0xe0, 0xa6, 0x6a, 0x82, 0x54, 0x42, 0x6a, 0x64, 0xed, 0xb6, 0x70, 0x12, 0xb3,
	0x15, 0x8f, 0x40, 0x21, 0x7f, 0xea, 0x46, 0xa8, 0xa1, 0xcb, 0x05, 0xc5, 0xd2, 0xea, 0xad, 0x77,
	0x3f, 0x28, 0xde, 0x98, 0xab, 0x2a, 0x2f, 0x7e, 0x50, 0x16, 0x29, 0x82, 0x8e, 0x49, 0x8e, 0xee,
	0x11, 0xab, 0x7e, 0xb3, 0xd0, 0x2e, 0x9d, 0xd6, 0x42, 0x07, 0xcc, 0x11, 0xa1, 0x43, 0x84, 0x7d,
	0x8a, 0x65, 0xef, 0x72, 0xb9, 0x6e, 0x78, 0xdf, 0xeb, 0xc6, 0xc1, 0x02, 0x92, 0xc7, 0xf3, 0xd6,
	0xae, 0xb9, 0xf5, 0xf6, 0xd9, 0x68, 0x4f, 0x62, 0x3d, 0xcd, 0xa2, 0x50, 0x50, 0xe2, 0x8e, 0x72,
	0x4f, 0x47, 0x8d, 0x67, 0x5c, 0x2f, 0xe6, 0xa8, 0x0c, 0x47, 0x0d, 0x4b, 0xbf, 0xd6, 0x01, 0x62,
	0xe5, 0x38, 0xd8, 0x97, 0x94, 0x33, 0x46, 0x20, 0x04, 0x65, 0x52, 0xab, 0xea, 0xbf, 0x66, 0xa1,
	0xfd, 0x7f, 0xb8, 0x27, 0x69, 0x80, 0x78, 0xe1, 0x9a, 0xbd, 0xfe, 0x72, 0xc3, 0xfc, 0xd5, 0x86,
	0xf9, 0x5f, 0x1b, 0xe6, 0xbf, 0x6e, 0x99, 0xb7, 0xda, 0x32, 0xef, 0x63, 0xcb, 0xbc, 0xbb, 0x93,
	0x9d, 0xc5, 0xb7, 0x08, 0x49, 0xe7, 0xca, 0xa6, 0x28, 0x28, 0x45, 0xfe, 0xec, 0xc2, 0x34, 0xfb,
	0xa3, 0xa2, 0x89, 0xe1, 0xec, 0x27, 0x00, 0x00, 0xff, 0xff, 0x8f, 0xc5, 0xe4, 0xbb, 0xa8, 0x01,
	0x00, 0x00,
}

func (m *Params) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Params) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.NoFeeAccounts) > 0 {
		for iNdEx := len(m.NoFeeAccounts) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.NoFeeAccounts[iNdEx])
			copy(dAtA[i:], m.NoFeeAccounts[iNdEx])
			i = encodeVarintParams(dAtA, i, uint64(len(m.NoFeeAccounts[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
	}
	if len(m.CreationFee) > 0 {
		for iNdEx := len(m.CreationFee) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.CreationFee[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintParams(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func encodeVarintParams(dAtA []byte, offset int, v uint64) int {
	offset -= sovParams(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Params) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.CreationFee) > 0 {
		for _, e := range m.CreationFee {
			l = e.Size()
			n += 1 + l + sovParams(uint64(l))
		}
	}
	if len(m.NoFeeAccounts) > 0 {
		for _, s := range m.NoFeeAccounts {
			l = len(s)
			n += 1 + l + sovParams(uint64(l))
		}
	}
	return n
}

func sovParams(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozParams(x uint64) (n int) {
	return sovParams(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Params) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowParams
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Params: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Params: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CreationFee", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowParams
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthParams
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthParams
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.CreationFee = append(m.CreationFee, types.Coin{})
			if err := m.CreationFee[len(m.CreationFee)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NoFeeAccounts", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowParams
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthParams
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthParams
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.NoFeeAccounts = append(m.NoFeeAccounts, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipParams(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthParams
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipParams(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowParams
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowParams
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowParams
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthParams
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupParams
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthParams
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthParams        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowParams          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupParams = fmt.Errorf("proto: unexpected end of group")
)
