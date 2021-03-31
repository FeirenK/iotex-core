package action

import (
	"github.com/golang/protobuf/proto"
	"github.com/iotexproject/go-pkgs/crypto"
	"github.com/iotexproject/go-pkgs/hash"
	"github.com/iotexproject/iotex-proto/golang/iotextypes"
	"github.com/pkg/errors"

	"github.com/iotexproject/iotex-core/pkg/util/byteutil"
)

// SealedEnvelope is a signed action envelope.
type SealedEnvelope struct {
	Envelope

	srcPubkey crypto.PublicKey
	signature []byte
}

// Hash returns the hash value of SealedEnvelope.
func (sealed *SealedEnvelope) Hash() hash.Hash256 {
	var ser []byte
	if sealed.Envelope.IsRLP() {
		ser = sealed.Envelope.Serialize()
	} else {
		ser = byteutil.Must(proto.Marshal(sealed.Proto()))
	}
	return hash.Hash256b(ser)
}

// SrcPubkey returns the source public key
func (sealed *SealedEnvelope) SrcPubkey() crypto.PublicKey { return sealed.srcPubkey }

// Signature returns signature bytes
func (sealed *SealedEnvelope) Signature() []byte {
	sig := make([]byte, len(sealed.signature))
	copy(sig, sealed.signature)
	return sig
}

// Proto converts it to it's proto scheme.
func (sealed *SealedEnvelope) Proto() *iotextypes.Action {
	return &iotextypes.Action{
		Core:         sealed.Envelope.Proto(),
		SenderPubKey: sealed.srcPubkey.Bytes(),
		Signature:    sealed.signature,
	}
}

// LoadProto loads from proto scheme.
func (sealed *SealedEnvelope) LoadProto(pbAct *iotextypes.Action) error {
	if pbAct == nil {
		return errors.New("empty action proto to load")
	}
	if sealed == nil {
		return errors.New("nil action to load proto")
	}

	var (
		elp     Envelope
		core    = pbAct.GetCore()
		chainID = core.GetChainID()
	)
	switch {
	case IsNative(chainID):
		elp = &envelope{}
	case IsRLP(chainID):
		elp = &envelopeRLP{}
	default:
		return errors.Errorf("invalid chain ID = %v", chainID)
	}
	if err := elp.LoadProto(core); err != nil {
		return err
	}

	// populate pubkey and signature
	srcPub, err := crypto.BytesToPublicKey(pbAct.GetSenderPubKey())
	if err != nil {
		return err
	}

	// clear 'sealed' and populate new value
	*sealed = SealedEnvelope{}
	sealed.Envelope = elp
	sealed.srcPubkey = srcPub
	sealed.signature = make([]byte, len(pbAct.GetSignature()))
	copy(sealed.signature, pbAct.GetSignature())
	sealed.Action().SetEnvelopeContext(*sealed)
	return sealed.Envelope.Decode(sealed.Signature())
}

// IsNative returns whether the tx is native or not
func IsNative(chainID uint32) bool {
	return chainID == 0
}

// IsRLP returns whether the tx is RLP-encoded or not
func IsRLP(chainID uint32) bool {
	// TODO: use a global chain ID
	return chainID != 0 && chainID == 4689
}
