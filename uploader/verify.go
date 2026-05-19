// Package uploader — remote CAR verification for dedup safety.
//
// After phase 4, VerifyRemoteCAR and VerifyRemoteMeta delegate to the
// ipfar-sdk which provides multi‑gateway fallback and CAR parsing.
package uploader

import (
	"context"

	"github.com/LWDJD/ipfar-sdk/ipfar"
	"github.com/LWDJD/ipfar-uploader/arweave"
)

// VerifyRemoteCAR downloads key portions of a remote CAR file from Arweave
// and validates it using the SDK's CAR parser.
//
// The primary gateway is tried first; if it fails the SDK falls back to
// public gateways (ipfar.DefaultFallbackGateways).
//
// Checks performed (when raw data is reachable):
//  1. CAR version == 2
//  2. HasIndex == true
//  3. Root CID matches expectedRootCID
//  4. Index passes ValidateIndex (boundary sanity)
//
// Returns (true, nil) when the CAR passes every check.
func VerifyRemoteCAR(ctx context.Context, gateway *arweave.GatewayClient, txID string, expectedRootCID string) (bool, error) {
	return ipfar.VerifyRemoteCAR(ctx, gateway.GatewayClient, txID, expectedRootCID, nil)
}

// VerifyRemoteMeta downloads the raw metadata transaction from Arweave and
// validates that its root_cid and data_txid match the expected values.
//
// Multi-gateway fallback is handled by the SDK.  The remote data may be
// plain JSON or base64url-encoded JSON (chunked upload stores data
// base64url-encoded).  Both forms are tried.
//
// Returns true if the remote metadata is valid and matches the expected
// rootCID and dataTXID.
func VerifyRemoteMeta(ctx context.Context, gateway *arweave.GatewayClient, txID, expectedRootCID, expectedDataTXID string) (bool, error) {
	return ipfar.VerifyRemoteMeta(ctx, gateway.GatewayClient, txID, expectedRootCID, expectedDataTXID, nil)
}
