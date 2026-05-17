// Package cmd provides the CLI interface for ipfar-uploader.
package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LWDJD/ipfar-uploader/arweave"
	"github.com/LWDJD/ipfar-uploader/uploader"
)

var (
	walletPath string
	gatewayURL string
	useBundle  bool
	method     string
	bundleSize int
	powWorkers int
)

// Run parses command-line arguments and executes the appropriate command.
// ctx is used for cancellation (e.g. SIGINT).
func Run(ctx context.Context) error {
	if len(os.Args) < 2 {
		printUsage()
		return fmt.Errorf("no command specified")
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "file":
		return runFile(ctx, args)
	case "dir":
		return runDir(ctx, args)
	case "wallet":
		return runWallet(args)
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "version", "-v", "--version":
		fmt.Println("ipfar-uploader v0.1.0")
		return nil
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func runFile(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("file", flag.ExitOnError)
	fs.StringVar(&walletPath, "wallet", "", "Path to Arweave JWK wallet file (required)")
	fs.StringVar(&gatewayURL, "gateway", "https://arweave.net", "Arweave gateway URL")
	fs.BoolVar(&useBundle, "bundle", false, "Use ANS-104 bundle upload (shorthand for --method bundle)")
	fs.StringVar(&method, "method", "", "Upload method: raw, bundle, cross-bundle (overrides --bundle)")
	fs.IntVar(&bundleSize, "bundle-size", 0, "Max items per bundle (0 = all in one)")
	fs.IntVar(&powWorkers, "pow-workers", 0, "Number of parallel PoW workers (0 = auto)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	filePath := fs.Arg(0)
	if filePath == "" {
		return fmt.Errorf("file path required")
	}

	return uploadFile(ctx, filePath)
}

func runDir(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dir", flag.ExitOnError)
	fs.StringVar(&walletPath, "wallet", "", "Path to Arweave JWK wallet file (required)")
	fs.StringVar(&gatewayURL, "gateway", "https://arweave.net", "Arweave gateway URL")
	fs.BoolVar(&useBundle, "bundle", false, "Use ANS-104 bundle upload (shorthand for --method bundle)")
	fs.StringVar(&method, "method", "", "Upload method: raw, bundle, cross-bundle (overrides --bundle)")
	fs.IntVar(&bundleSize, "bundle-size", 0, "Max items per bundle (0 = all in one)")
	fs.IntVar(&powWorkers, "pow-workers", 0, "Number of parallel PoW workers (0 = auto)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	dirPath := fs.Arg(0)
	if dirPath == "" {
		return fmt.Errorf("directory path required")
	}

	return uploadDir(ctx, dirPath)
}

func runWallet(args []string) error {
	fs := flag.NewFlagSet("wallet", flag.ExitOnError)
	fs.StringVar(&walletPath, "wallet", "", "Path to save wallet file")
	generate := fs.Bool("generate", false, "Generate a new wallet")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *generate {
		return generateWallet(walletPath)
	}

	if walletPath == "" {
		return fmt.Errorf("wallet path required (use --wallet <path>)")
	}

	return showWallet(walletPath)
}

func uploadFile(ctx context.Context, filePath string) error {
	cfg, err := buildConfig()
	if err != nil {
		return err
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	fmt.Printf("Uploading file: %s\n", absPath)
	fmt.Printf("  Gateway: %s\n", cfg.Gateway.GatewayURL)
	fmt.Printf("  Bundle: %v\n", cfg.UseBundle)
	fmt.Printf("  Wallet: %s\n", cfg.Wallet.Address)
	fmt.Println()

	u := uploader.New(cfg)
	result, err := u.UploadFile(ctx, absPath)
	if err != nil {
		return err
	}

	printResult(result)
	return nil
}

func uploadDir(ctx context.Context, dirPath string) error {
	cfg, err := buildConfig()
	if err != nil {
		return err
	}

	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	fmt.Printf("Uploading directory: %s\n", absPath)
	fmt.Printf("  Gateway: %s\n", cfg.Gateway.GatewayURL)
	fmt.Printf("  Bundle: %v\n", cfg.UseBundle)
	fmt.Printf("  Wallet: %s\n", cfg.Wallet.Address)
	fmt.Println()

	u := uploader.New(cfg)
	results, err := u.UploadDir(ctx, absPath)
	if err != nil {
		return err
	}

	successCount := 0
	for _, r := range results {
		printResult(r)
		if r.Error == nil {
			successCount++
		}
	}

	fmt.Printf("\n---\nTotal: %d files, %d succeeded, %d failed\n",
		len(results), successCount, len(results)-successCount)
	return nil
}

func buildConfig() (*uploader.Config, error) {
	if walletPath == "" {
		walletPath = os.Getenv("IPFAR_WALLET")
	}
	if walletPath == "" {
		return nil, fmt.Errorf("wallet is required. Use --wallet <path> or set IPFAR_WALLET env var")
	}

	wallet, err := arweave.LoadWalletFromFile(walletPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load wallet: %w", err)
	}

	cfg := uploader.NewDefaultConfig()
	cfg.Wallet = wallet
	cfg.Gateway = arweave.NewGatewayClient(gatewayURL)

	// --method overrides --bundle
	if method != "" {
		cfg.UseBundle = (method == "bundle" || method == "cross-bundle")
	} else {
		cfg.UseBundle = useBundle
	}
	cfg.BundleSize = bundleSize
	cfg.PoWWorkers = powWorkers

	return cfg, nil
}

func printResult(r *uploader.UploadResult) {
	fmt.Println()
	if r.Error != nil {
		fmt.Printf("❌ %s\n   Error: %v\n", r.FilePath, r.Error)
		return
	}

	fmt.Printf("✅ %s\n", r.FilePath)
	fmt.Printf("   Root CID:    %s\n", r.RootCID)
	fmt.Printf("   Data TXID:   %s\n", r.DataTXID)
	fmt.Printf("   Data Height: %d\n", r.DataHeight)
	if r.BundleTXID != "" {
		fmt.Printf("   Bundle TXID: %s\n", r.BundleTXID)
	}
	fmt.Printf("   Meta TXID:   %s\n", r.MetaTXID)
	fmt.Printf("   Size:        %d bytes\n", r.DataSize)
	fmt.Printf("   Method:      %s\n", r.Method)
	if r.PoW != "" {
		fmt.Printf("   PoW:         %s\n", r.PoW)
	}
}

func showWallet(path string) error {
	wallet, err := arweave.LoadWalletFromFile(path)
	if err != nil {
		return fmt.Errorf("failed to load wallet: %w", err)
	}

	fmt.Printf("Wallet Address: %s\n", wallet.Address)
	fmt.Printf("Owner (modulus): %s\n", truncate(wallet.Owner, 60))
	return nil
}

func generateWallet(path string) error {
	fmt.Println("Wallet generation is not implemented yet.")
	fmt.Println("Please use an existing Arweave wallet (JWK format).")
	fmt.Println("You can generate one using https://faucet.arweave.net or arweave.app")
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func printUsage() {
	fmt.Println(strings.TrimSpace(`
ipfar-uploader - IPFAR Arweave Upload Tool

USAGE:
  ipfar-uploader <command> [options]

COMMANDS:
  file     Upload a single file
  dir      Upload all files in a directory
  wallet   Show wallet info or generate new wallet
  help     Show this help

OPTIONS (for file/dir):
  --wallet <path>    Path to Arweave JWK wallet file
  --gateway <url>    Arweave gateway URL (default: https://arweave.net)
  --bundle           Use ANS-104 bundle upload (same-bundle, data_height=-1)
  --method <method>  Upload method: raw, bundle, cross-bundle
  --bundle-size <n>  Max items per bundle (0 = all in one)
  --pow-workers <n>  Number of parallel PoW workers (0 = auto)

EXAMPLES:
  ipfar-uploader file --wallet wallet.json myfile.png
  ipfar-uploader dir --wallet wallet.json --bundle ./myfiles/
  ipfar-uploader wallet --wallet wallet.json
`))
}
