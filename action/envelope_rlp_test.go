package action

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/protobuf/proto"
	"github.com/iotexproject/go-pkgs/crypto"
	"github.com/iotexproject/go-pkgs/hash"
	"github.com/iotexproject/iotex-address/address"
	"github.com/iotexproject/iotex-proto/golang/iotextypes"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/iotexproject/iotex-core/test/identityset"
)

func TestRlpEnvelope(t *testing.T) {
	require := require.New(t)

	eb, _ := createEnvelope()
	evlp, ok := eb.(*envelope)
	require.True(ok)

	tx := envelopeRLP{
		envelope: *evlp,
		chainID:  17,
	}
	require.Nil(tx.Serialize())
	require.Equal(hash.ZeroHash256, tx.Hash())

	proto := tx.Proto()
	require.NoError(tx.LoadProto(proto))
	tx.Action().SetEnvelopeContext(SealedEnvelope{Envelope: &tx})
	require.Equal(evlp.Version(), tx.Version())
	require.Equal(evlp.Nonce(), tx.Nonce())
	require.Equal(evlp.GasLimit(), tx.GasLimit())
	require.Equal(evlp.GasPrice(), tx.GasPrice())
	require.Equal(evlp.Action(), tx.Action())
	require.EqualValues(17, tx.chainID)

	proto.Action = &iotextypes.ActionCore_GrantReward{}
	require.Contains(
		tx.LoadProto(proto).Error(),
		"no applicable action to handle proto type *iotextypes.ActionCore_GrantReward")
}

func TestRlpDecodeVerify(t *testing.T) {
	require := require.New(t)

	rlpTests := []struct {
		raw    string
		chain  uint32
		nonce  uint64
		limit  uint64
		price  string
		amount string
		to     string
		isTsf  bool
		data   bool
		hash   string
		pubkey string
		pkhash string
	}{
		{
			"f86e8085e8d4a51000825208943141df3f2e4415533bb6d6be2a351b2db9ee84ef88016345785d8a0000808224c6a0204d25fc0d7d8b3fdf162c6ee820f888f5533b1c382d79d5cbc8ec1d9091a9a8a016f1a58d7e0d0fd24be800f64a2d6433c5fcb31e3fc7562b7fbe62bc382a95bb",
			4689,
			0,
			21000,
			"1000000000000",
			"100000000000000000",
			"io1x9qa70ewgs24xwak66lz5dgm9ku7ap80vw3070",
			true,
			false,
			"eead45fe6b510db9ed6dce9187280791c04bbaadd90c54a7f4b1f75ced382ff1",
			"041ba784140be115e8fa8698933e9318558a895c75c7943100f0677e4d84ff2763ff68720a0d22c12d093a2d692d1e8292c3b7672fccf3b3db46a6e0bdad93be17",
			"87eea07540789af85b64947aea21a3f00400b597",
		},
		{
			"f8ab0d85e8d4a5100082520894ac7ac39de679b19aae042c0ce19facb86e0a411780b844a9059cbb0000000000000000000000003141df3f2e4415533bb6d6be2a351b2db9ee84ef000000000000000000000000000000000000000000000000000000003b9aca008224c5a0fac4e25db03c99fec618b74a962d322a334234696eb62c7e5b9889132ff4f4d7a02c88e451572ca36b6f690ce23ff9d6695dd71e888521fa706a8fc8c279099a61",
			4689,
			13,
			21000,
			"1000000000000",
			"0",
			"io143av880x0xce4tsy9sxwr8avhphq5sghum77ct",
			false,
			true,
			"7467dd6ccd4f3d7b6dc0002b26a45ad0b75a1793da4e3557cf6ff2582cbe25c9",
			"041ba784140be115e8fa8698933e9318558a895c75c7943100f0677e4d84ff2763ff68720a0d22c12d093a2d692d1e8292c3b7672fccf3b3db46a6e0bdad93be17",
			"87eea07540789af85b64947aea21a3f00400b597",
		},
		{
			"f9024f2e830f42408381b3208080b901fc608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555061019c806100606000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063445df0ac146100465780638da5cb5b14610064578063fdacd576146100ae575b600080fd5b61004e6100dc565b6040518082815260200191505060405180910390f35b61006c6100e2565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6100da600480360360208110156100c457600080fd5b8101908080359060200190929190505050610107565b005b60015481565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141561016457806001819055505b5056fea265627a7a72315820e54fe55a78b9d8bec22b4d3e6b94b7e59799daee3940423eb1aa30fe643eeb9a64736f6c634300051000328224c5a0439310c2d5509fc42486171b910cf8107542c86e23202a3a8ba43129cabcdbfea038966d36b41916f619c64bdc8c3ddcb021b35ea95d44875eb8201e9422fd98f0",
			4689,
			46,
			8500000,
			"1000000",
			"0",
			EmptyAddress,
			false,
			true,
			"b676128dae841742e3ab6e518acb30badc6b26230fe870821d1de08c85823067",
			"049c6567f527f8fc98c0875d3d80097fcb4d5b7bfe037fc9dd5dbeaf563d58d7ff17a4f2b85df9734ecdb276622738e28f0b7cf224909ab7b128c5ca748729b0d2",
			"1904bfcb93edc9bf961eead2e5c0de81dcc1d37d",
		},
	}

	for _, v := range rlpTests {
		encoded, err := hex.DecodeString(v.raw)
		require.NoError(err)

		// decode received RLP tx
		tx := types.Transaction{}
		require.NoError(rlp.DecodeBytes(encoded, &tx))

		// extract signature and recover pubkey
		w, r, s := tx.RawSignatureValues()
		recID := uint32(w.Int64()) - 2*v.chain - 8
		sig := make([]byte, 64, 65)
		rSize := len(r.Bytes())
		copy(sig[32-rSize:32], r.Bytes())
		sSize := len(s.Bytes())
		copy(sig[64-sSize:], s.Bytes())
		sig = append(sig, byte(recID))

		// recover public key
		rawHash := types.NewEIP155Signer(big.NewInt(int64(v.chain))).Hash(&tx)
		pubkey, err := crypto.RecoverPubkey(rawHash[:], sig)
		require.NoError(err)
		require.Equal(v.pubkey, pubkey.HexString())
		require.Equal(v.pkhash, hex.EncodeToString(pubkey.Hash()))

		// convert to our Execution
		pb := convertToNativeProto(&tx, v.isTsf)
		pb.Core.ChainID = v.chain
		pb.SenderPubKey = pubkey.Bytes()
		pb.Signature = sig

		// send on wire
		bytes, err := proto.Marshal(pb)
		require.NoError(err)

		// receive from API
		proto.Unmarshal(bytes, pb)
		selp := SealedEnvelope{}
		require.NoError(selp.LoadProto(pb))
		var (
			elp   = selp.Envelope
			rlpTx rlpTransaction
		)
		require.True(elp.IsRLP())
		if v.isTsf {
			tsf, ok := elp.Action().(*Transfer)
			require.True(ok)
			rlpTx = tsf
		} else {
			ex, ok := elp.Action().(*Execution)
			require.True(ok)
			rlpTx = ex
		}

		// verify against original tx
		require.Equal(v.nonce, rlpTx.Nonce())
		require.Equal(v.price, rlpTx.GasPrice().String())
		require.Equal(v.limit, rlpTx.GasLimit())
		require.Equal(v.to, rlpTx.Recipient())
		require.Equal(v.amount, rlpTx.Amount().String())
		require.Equal(v.data, len(rlpTx.Payload()) > 0)
		h := selp.Hash()
		require.Equal(v.hash, hex.EncodeToString(h[:]))
		require.Equal(pubkey, selp.SrcPubkey())
		require.Equal(sig, selp.signature)

		// verify signature
		require.NoError(Verify(selp))

		// not allowed to sign RLP-encoded tx
		_, err = Sign(selp.Envelope, identityset.PrivateKey(27))
		require.Equal(ErrAction, errors.Cause(err))
	}
}

func convertToNativeProto(tx *types.Transaction, isTsf bool) *iotextypes.Action {
	pb := iotextypes.Action{
		Core: &iotextypes.ActionCore{
			Version:  1,
			Nonce:    tx.Nonce(),
			GasLimit: tx.Gas(),
			GasPrice: tx.GasPrice().String(),
		},
	}

	if isTsf {
		tsf := &Transfer{}
		tsf.nonce = tx.Nonce()
		tsf.gasLimit = tx.Gas()
		tsf.gasPrice = tx.GasPrice()
		tsf.amount = tx.Value()
		ioAddr, _ := address.FromBytes(tx.To().Bytes())
		tsf.recipient = ioAddr.String()
		tsf.payload = tx.Data()

		pb.Core.Action = &iotextypes.ActionCore_Transfer{
			Transfer: tsf.Proto(),
		}
	} else {
		ex := &Execution{}
		ex.nonce = tx.Nonce()
		ex.gasLimit = tx.Gas()
		ex.gasPrice = tx.GasPrice()
		ex.amount = tx.Value()
		if tx.To() != nil {
			ioAddr, _ := address.FromBytes(tx.To().Bytes())
			ex.contract = ioAddr.String()
		}
		ex.data = tx.Data()

		pb.Core.Action = &iotextypes.ActionCore_Execution{
			Execution: ex.Proto(),
		}
	}
	return &pb
}
