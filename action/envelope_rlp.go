package action

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/iotexproject/go-pkgs/hash"
	"github.com/iotexproject/iotex-address/address"
	"github.com/iotexproject/iotex-proto/golang/iotextypes"
	"github.com/pkg/errors"

	"github.com/iotexproject/iotex-core/pkg/util/byteutil"
)

type envelopeRLP struct {
	envelope
	chainID  uint32
	rawTx    *types.Transaction
	signedTx *types.Transaction
}

func (er *envelopeRLP) Serialize() []byte {
	if er.signedTx == nil {
		return nil
	}
	return byteutil.Must(rlp.EncodeToBytes(er.signedTx))
}

func (er *envelopeRLP) Hash() hash.Hash256 {
	if er.rawTx == nil {
		return hash.ZeroHash256
	}
	h := types.NewEIP155Signer(big.NewInt(int64(er.chainID))).Hash(er.rawTx)
	return hash.BytesToHash256(h[:])
}

func (er *envelopeRLP) Proto() *iotextypes.ActionCore {
	core := er.envelope.Proto()
	core.ChainID = er.chainID
	return core
}

func (er *envelopeRLP) LoadProto(pbAct *iotextypes.ActionCore) error {
	if pbAct == nil {
		return errors.New("empty action proto to load")
	}

	switch {
	case pbAct.GetTransfer() != nil:
	case pbAct.GetExecution() != nil:
	default:
		return errors.Errorf("no applicable action to handle proto type %T", pbAct.Action)
	}

	er.chainID = pbAct.GetChainID()
	return er.envelope.LoadProto(pbAct)
}

func (er *envelopeRLP) IsRLP() bool {
	return true
}

func (er *envelopeRLP) Decode(sig []byte) error {
	var (
		tx  rlpTransaction
		err error
	)
	switch act := er.payload.(type) {
	case *Transfer:
		tx = (*Transfer)(act)
	case *Execution:
		tx = (*Execution)(act)
	default:
		return errors.Errorf("invalid action type %T not supported", act)
	}

	er.rawTx, er.signedTx, err = generateRlpTx(tx, er.chainID, sig)
	return err
}

type rlpTransaction interface {
	Nonce() uint64
	GasPrice() *big.Int
	GasLimit() uint64
	Recipient() string
	Amount() *big.Int
	Payload() []byte
}

func generateRlpTx(act rlpTransaction, chainID uint32, sig []byte) (*types.Transaction, *types.Transaction, error) {
	var (
		to    = act.Recipient()
		rawTx *types.Transaction
	)

	// generate raw tx
	if to != EmptyAddress {
		addr, err := address.FromString(to)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "invalid recipient address %s", to)
		}
		ethAddr := common.BytesToAddress(addr.Bytes())
		rawTx = types.NewTransaction(act.Nonce(), ethAddr, act.Amount(), act.GasLimit(), act.GasPrice(), act.Payload())
	} else {
		rawTx = types.NewContractCreation(act.Nonce(), act.Amount(), act.GasLimit(), act.GasPrice(), act.Payload())
	}

	// use signature to generate signed tx
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	signedTx, err := rawTx.WithSignature(types.NewEIP155Signer(big.NewInt(int64(chainID))), sig)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to generate signed tx")
	}
	return rawTx, signedTx, nil
}
