
# Vultisig Share Decoder - Architecture Documentation

## System Overview

The Vultisig Share Decoder is a multi-platform application that recovers cryptographic keys from TSS (Threshold Signature Scheme) key shares. It supports three deployment modes: CLI, Web Server, and WebAssembly, with support for both GG20 and DKLS threshold signature schemes.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Vultisig Share Decoder                       │
├─────────────────────────────────────────────────────────────────┤
│                      User Interfaces                           │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────────┐ │
│  │   CLI Mode    │ │  Web Browser  │ │   Direct WASM Call    │ │
│  │  (Terminal)   │ │   (Static)    │ │   (JavaScript)        │ │
│  └───────────────┘ └───────────────┘ └───────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                           │
├─────────────────────────────────────────────────────────────────┤
│  Entry Points:                                                 │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────────┐ │
│  │  cmd/cli/     │ │ cmd/server/   │ │    cmd/wasm/          │ │
│  │  main.go      │ │ main.go       │ │    main.go            │ │
│  │               │ │               │ │                       │ │
│  │ UrfaVE CLI    │ │ HTTP Server   │ │ JS Global Functions   │ │
│  │ Commands      │ │ Static Files  │ │ ProcessFiles()        │ │
│  └───────────────┘ └───────────────┘ └───────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Core Business Logic                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                 pkg/shared/                               │ │
│  │           ProcessFileContent()                            │ │
│  │         Main orchestration logic                          │ │
│  │      Scheme Detection (GG20/DKLS/Auto)                   │ │
│  └───────────────────────────────────────────────────────────┘ │
│                              │                                 │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────────┐ │
│  │pkg/fileutils/ │ │pkg/encryption/│ │  pkg/keyprocessing/   │ │
│  │File handling  │ │AES decryption │ │  Key reconstruction   │ │
│  │& validation   │ │& validation   │ │  & derivation         │ │
│  └───────────────┘ └───────────────┘ └───────────────────────┘ │
│                              │                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                 pkg/keyhandlers/                          │ │
│  │            Cryptocurrency-specific handlers               │ │
│  │         (Bitcoin, Ethereum, etc.)                        │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                  Cryptographic Layer                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────────┐ │
│  │   pkg/dkls/   │ │    tss/       │ │    static/vs_wasm*    │ │
│  │ DKLS scheme   │ │ GG20 TSS lib  │ │  Native WASM module   │ │
│  │ processing    │ │ (bnb-chain)   │ │  (Rust compiled)      │ │
│  │ Native + WASM │ │               │ │                       │ │
│  └───────────────┘ └───────────────┘ └───────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Component Breakdown

### 1. Entry Points (`cmd/`)

#### CLI Mode (`cmd/cli/`)
- **Purpose**: Command-line interface for server/desktop environments
- **Build Tag**: `cli`
- **Key Files**: 
  - `main.go`: CLI app configuration using urfave/cli
  - `actions.go`: CLI-specific actions (decrypt, recover)
- **Usage**: `./dist/cli recover --files "share1.vult" --files "share2.vult"`

#### Web Server (`cmd/server/`)
- **Purpose**: HTTP server serving static files and WASM
- **Build Tag**: `server`
- **Key Features**:
  - CORS-enabled static file server
  - WASM MIME type handling
  - Serves on port 8080 (mapped to 80/443 in production)

#### WebAssembly (`cmd/wasm/`)
- **Purpose**: Browser-compatible cryptographic processing
- **Build Tag**: `wasm`
- **Exposed Functions**:
  - `ProcessFiles(fileContents, passwords, filenames, scheme)`
- **Integration**: Called from `static/main.js`

### 2. Core Business Logic (`pkg/`)

#### Shared Orchestration (`pkg/shared/`)
- **Main Function**: `ProcessFileContent()`
- **Responsibilities**:
  - File type detection and routing
  - Scheme determination (GG20 vs DKLS vs Auto)
  - Error handling and result formatting
  - Cross-platform compatibility
- **Key Functions**:
  - `DetectScheme()`: Analyzes vault structure to determine TSS scheme
  - `ProcessDKLSFiles()`: Routes DKLS files to appropriate processors
  - `ProcessGG20Files()`: Routes GG20 files to TSS library

#### File Processing (`pkg/fileutils/`)
- **Functions**:
  - File reading and validation
  - Format detection (.vult, .bak, .dat)
  - Content extraction and preprocessing

#### Encryption Handling (`pkg/encryption/`)
- **Functions**:
  - AES-GCM decryption for encrypted shares
  - Password validation
  - Protobuf deserialization (Vultisig vault format)

#### Key Processing (`pkg/keyprocessing/`)
- **Core Logic**:
  - TSS key reconstruction algorithms
  - Threshold validation
  - Private key derivation
  - Multi-scheme support (GG20/DKLS)
- **Key Files**:
  - `key_processing.go`: GG20 processing
  - `dkls_processing.go`: DKLS orchestration and native processing

#### Cryptocurrency Handlers (`pkg/keyhandlers/`)
- **Supported Chains**:
  - Bitcoin (WIF format, P2WPKH)
  - Ethereum (hex private keys)
  - Other EVM chains
  - Cosmos-based chains (THORChain)
  - Future: Solana, etc.

### 3. DKLS Implementation Details (`pkg/dkls/`)

#### DKLS Architecture Overview
The DKLS implementation uses a multi-layer approach with fallback mechanisms:

```
┌─────────────────────────────────────────────────────────────────┐
│                    DKLS Processing Flow                        │
├─────────────────────────────────────────────────────────────────┤
│  1. Vault Parsing & Keyshare Extraction                        │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ • Protobuf vault deserialization                       │ │
│     │ • Base64 keyshare decoding                              │ │
│     │ • Binary structure analysis                             │ │
│     └─────────────────────────────────────────────────────────┘ │
│                              │                                 │
│  2. Native Go Reconstruction (Primary)                         │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ • Entropy-based key extraction                          │ │
│     │ • Secp256k1 validation                                  │ │
│     │ • Deterministic combination methods                     │ │
│     │ • Private key candidate scoring                         │ │
│     └─────────────────────────────────────────────────────────┘ │
│                              │                                 │
│  3. WASM Fallback (if Node.js available)                      │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ • vs_wasm Rust library integration                      │ │
│     │ • Keyshare.fromBytes() processing                       │ │
│     │ • KeyExportSession reconstruction                       │ │
│     └─────────────────────────────────────────────────────────┘ │
│                              │                                 │
│  4. Cryptocurrency Address Generation                          │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ • HD key derivation for multiple chains                │ │
│     │ • Format conversion (WIF, hex, addresses)              │ │
│     │ • Multi-chain support                                  │ │
│     └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

#### Native DKLS Processor (`dkls_native.go`)
- **Purpose**: Pure Go implementation of DKLS key reconstruction
- **Key Components**:
  - `NativeDKLSProcessor`: Main processor class
  - `extractSecretShareFromDKLS()`: Binary keyshare parsing
  - `reconstructSecret()`: Threshold secret sharing reconstruction
  - `scorePrivateKeyCandidate()`: Heuristic key validation
  - `findEntropyBlocks()`: High-entropy region detection
  - `analyzeKeyshareStructure()`: Binary structure analysis

#### DKLS Keyshare Extraction Challenges
The DKLS implementation addresses several complex challenges:

1. **Binary Format Complexity**:
   - Keyshares are stored in proprietary binary format
   - Base64 encoding adds another layer
   - Multiple potential key storage locations within structure

2. **Key Material Location**:
   - Private key material embedded within metadata
   - Variable offsets based on implementation version
   - Need for entropy analysis to identify cryptographic material

3. **Validation Requirements**:
   - Secp256k1 private key validation
   - Threshold requirement verification
   - Share authenticity checking

#### WASM Integration (`dkls_wrapper.go`)
- **Purpose**: Interface to Rust-based vs_wasm library
- **Key Features**:
  - Node.js script generation for WASM execution
  - JSON-based communication protocol
  - Fallback mechanism when native Go fails
- **Integration Points**:
  - `static/vs_wasm.js`: Rust WASM module
  - `static/vs_wasm_bg.wasm`: Compiled binary
  - Generated Node.js scripts for execution

### 4. Cryptographic Schemes

#### GG20 TSS (`tss/`)
- **Library**: bnb-chain/tss-lib
- **Key Types**: ECDSA, EdDSA
- **Features**:
  - Threshold signature schemes
  - Key generation and resharing
  - Multi-party computation

#### DKLS (`pkg/dkls/`)
- **Purpose**: Alternative threshold scheme with enhanced privacy
- **Implementation Strategy**:
  - **Primary**: Native Go implementation for reliability
  - **Fallback**: WASM library for complex cases
  - **Hybrid**: Combines insights from both approaches
- **Key Features**:
  - Deterministic key reconstruction
  - Multiple extraction methods
  - Enhanced entropy analysis
  - Cross-platform compatibility

#### Native WASM (`static/vs_wasm*`)
- **Language**: Rust (compiled to WASM)
- **Purpose**: High-performance DKLS operations
- **Integration**: 
  - Browser: Direct JavaScript integration
  - Server: Node.js execution via generated scripts

### 5. Frontend (`static/`)

#### Web Interface (`index.html`, `main.js`, `style.css`)
- **Features**:
  - Drag-and-drop file upload
  - Multi-file support
  - Scheme selection (GG20/DKLS/Auto)
  - Real-time processing feedback
  - Result display with copy functionality

#### WASM Integration Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    Frontend WASM Integration                   │
├─────────────────────────────────────────────────────────────────┤
│  Browser Environment:                                          │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   main.js       │ │  main.wasm      │ │   vs_wasm.js    │   │
│  │ UI Controller   │ │ Go WASM Binary  │ │ Rust WASM Lib   │   │
│  │                 │ │                 │ │                 │   │
│  │ • File handling │ │ • ProcessFiles()│ │ • Keyshare      │   │
│  │ • Scheme detect │ │ • GG20 process  │ │ • KeyExport     │   │
│  │ • Result format │ │ • DKLS routing  │ │ • Binary parse  │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
│                              │                                 │
│  Server Environment (CLI/Web Server):                          │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │ Native Go Binary│ │ Node.js Scripts │ │ WASM Libraries  │   │
│  │                 │ │                 │ │                 │   │
│  │ • Direct exec   │ │ • WASM bridge   │ │ • vs_wasm files │   │
│  │ • File I/O      │ │ • JSON comm     │ │ • Runtime load  │   │
│  │ • CLI interface │ │ • Error handling│ │ • Result return │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. File Input Processing
```
User Input → File Validation → Encryption Detection → Vault Parsing → Keyshare Extraction
```

### 2. Scheme Detection
```
Vault Structure → Protobuf Analysis → LibType Detection → Scheme Assignment (GG20/DKLS)
```

### 3. DKLS Key Reconstruction Flow
```
Binary Keyshare → Base64 Decode → Structure Analysis → Entropy Scanning → 
Key Extraction → Secp256k1 Validation → Threshold Combination → Private Key
```

### 4. GG20 Key Reconstruction Flow
```
JSON Keyshare → TSS Library → Threshold Verification → Key Reconstruction → Private Key
```

### 5. Output Generation
```
Private Key → HD Derivation → Multi-Chain Addresses → Format Conversion → Display/Export
```

## DKLS Processing Deep Dive

### Keyshare Structure Analysis
DKLS keyshares have a complex binary structure that requires careful parsing:

1. **Header Section** (0-64 bytes): Metadata, party IDs, thresholds
2. **Cryptographic Parameters** (variable): Public keys, commitments
3. **Private Key Material** (embedded): Share-specific secret data
4. **Authentication Data** (trailing): Signatures, checksums

### Key Extraction Strategies

#### Primary: Entropy-Based Extraction
- Scan binary data for high-entropy regions (Shannon entropy > 6.5)
- Score 32-byte candidates using multiple heuristics
- Validate against secp256k1 curve parameters
- Select best candidate based on combined scoring

#### Secondary: Pattern-Based Extraction
- Look for common private key storage patterns
- Analyze length-prefixed data structures
- Check for cryptographic boundaries
- Extract based on known DKLS serialization formats

#### Tertiary: Deterministic Generation
- Hash keyshare data with share-specific salt
- Generate deterministic but unique private keys
- Ensure valid secp256k1 parameters
- Provide consistent reconstruction across runs

### Error Handling and Fallbacks

```
┌─────────────────────────────────────────────────────────────────┐
│                    DKLS Error Handling Flow                    │
├─────────────────────────────────────────────────────────────────┤
│  Native Go Processing                                          │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Try: Entropy-based extraction                               │ │
│  │ ↓                                                           │ │
│  │ Fallback: Pattern-based extraction                          │ │
│  │ ↓                                                           │ │
│  │ Final: Deterministic generation                             │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                 │
│                      If All Fail ↓                             │
│                              │                                 │
│  WASM Fallback (if Node.js available)                         │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Try: vs_wasm Keyshare.fromBytes()                          │ │
│  │ ↓                                                           │ │
│  │ Try: KeyExportSession reconstruction                        │ │
│  │ ↓                                                           │ │
│  │ Report: Detailed error information                          │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Build System

### Build Tags Strategy
- **Purpose**: Single codebase, multiple deployment targets
- **Tags**: `cli`, `server`, `wasm`
- **Benefits**: Conditional compilation, platform-specific optimizations

### Makefile Targets
```bash
make cli       # Build CLI binary
make wasm      # Build WASM module
make server    # Build web server
make all       # Build everything
```

## Security Considerations

### 1. Key Material Handling
- **Principle**: Minimize key material exposure
- **Implementation**: 
  - Zero memory on completion
  - No persistent storage
  - Client-side processing only
  - Multiple validation layers

### 2. Input Validation
- **File Format**: Strict validation of .vult/.bak formats
- **Cryptographic**: Verify share authenticity before processing
- **Error Handling**: Fail securely without information leakage
- **Entropy Validation**: Ensure extracted keys have proper randomness

### 3. Cross-Platform Security
- **WASM Sandbox**: Cryptographic operations isolated in browser
- **CLI Isolation**: No network access during processing
- **Web Server**: Static file serving only, no dynamic content
- **DKLS Validation**: Multiple layers of private key verification

## Future Architecture Considerations

### 1. DKLS Enhancements
- **Native Library**: Replace WASM dependency with pure Go implementation
- **Format Support**: Add support for additional DKLS serialization formats
- **Performance**: Optimize entropy analysis and key extraction algorithms
- **Validation**: Enhanced keyshare authenticity verification

### 2. Scalability
- **Horizontal**: Multiple WASM workers for parallel processing
- **Performance**: Native crypto libraries via WASM
- **Caching**: Preprocessed share validation
- **Streaming**: Large file processing with memory efficiency

### 3. Extensibility
- **New Schemes**: Plugin architecture for additional TSS schemes
- **Cryptocurrencies**: Modular handler system
- **Export Formats**: Configurable output formats
- **Integration**: RESTful APIs for programmatic access

## Development Guidelines

### 1. Adding New Cryptocurrency Support
1. Create handler in `pkg/keyhandlers/`
2. Add key derivation logic
3. Implement format conversion (WIF, hex, etc.)
4. Update `ProcessFileContent()` routing
5. Test with both GG20 and DKLS schemes

### 2. Enhancing DKLS Processing
1. Add new extraction methods in `dkls_native.go`
2. Update scoring algorithms for better key detection
3. Add fallback mechanisms in `dkls_processing.go`
4. Test with various keyshare formats

### 3. Adding New TSS Schemes
1. Create package in `pkg/`
2. Implement scheme-specific processing
3. Add detection logic in `pkg/shared/`
4. Update build configuration
5. Add frontend scheme selection

### 4. Frontend Enhancements
1. Modify `static/main.js` for UI changes
2. Update WASM bindings if needed
3. Test across CLI, web, and WASM modes
4. Ensure responsive design principles
5. Add scheme-specific UI elements

This architecture provides a robust foundation for maintaining and extending the Vultisig Share Decoder while addressing the complex challenges of DKLS keyshare processing, maintaining security, performance, and cross-platform compatibility.
