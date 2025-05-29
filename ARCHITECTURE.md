
# Vultisig Share Decoder - Architecture Documentation

## System Overview

The Vultisig Share Decoder is a multi-platform application that recovers cryptographic keys from TSS (Threshold Signature Scheme) key shares. It supports three deployment modes: CLI, Web Server, and WebAssembly.

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
  - Scheme determination (GG20 vs DKLS)
  - Error handling and result formatting
  - Cross-platform compatibility

#### File Processing (`pkg/fileutils/`)
- **Functions**:
  - File reading and validation
  - Format detection (.vult, .bak, .dat)
  - Content extraction and preprocessing

#### Encryption Handling (`pkg/encryption/`)
- **Functions**:
  - AES decryption for encrypted shares
  - Password validation
  - Protobuf deserialization (Vultisig vault format)

#### Key Processing (`pkg/keyprocessing/`)
- **Core Logic**:
  - TSS key reconstruction algorithms
  - Threshold validation
  - Private key derivation
  - Multi-scheme support (GG20/DKLS)

#### Cryptocurrency Handlers (`pkg/keyhandlers/`)
- **Supported Chains**:
  - Bitcoin (WIF format, P2WPKH)
  - Ethereum (hex private keys)
  - Other EVM chains
  - Future: Cosmos, Solana, etc.

### 3. Cryptographic Schemes

#### GG20 TSS (`tss/`)
- **Library**: bnb-chain/tss-lib
- **Key Types**: ECDSA, EdDSA
- **Features**:
  - Threshold signature schemes
  - Key generation and resharing
  - Multi-party computation

#### DKLS (`pkg/dkls/`)
- **Purpose**: Alternative threshold scheme
- **Features**:
  - Native Go implementation
  - Different security model than GG20
  - Binary format processing

#### Native WASM (`static/vs_wasm*`)
- **Language**: Rust (compiled to WASM)
- **Purpose**: High-performance cryptographic operations
- **Integration**: Called from Go WASM via JavaScript bridge

### 4. Frontend (`static/`)

#### Web Interface (`index.html`, `main.js`, `style.css`)
- **Features**:
  - Drag-and-drop file upload
  - Multi-file support
  - Scheme selection (GG20/DKLS)
  - Real-time processing feedback
  - Result display with copy functionality

#### WASM Integration
- **Files**:
  - `main.wasm`: Go-compiled WASM binary
  - `wasm_exec.js`: Go WASM runtime
  - `vs_wasm.js`, `vs_wasm_bg.wasm`: Rust WASM module

## Data Flow

### 1. File Input Processing
```
User Input → File Validation → Encryption Detection → Content Extraction
```

### 2. Scheme Detection
```
File Content → Format Analysis → Scheme Determination (GG20/DKLS/Auto)
```

### 3. Key Reconstruction
```
TSS Shares → Threshold Validation → Cryptographic Reconstruction → Private Key
```

### 4. Output Generation
```
Private Key → Cryptocurrency Format → Display/Export (WIF, Hex, etc.)
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

### 2. Input Validation
- **File Format**: Strict validation of .vult/.bak formats
- **Cryptographic**: Verify share authenticity before processing
- **Error Handling**: Fail securely without information leakage

### 3. Cross-Platform Security
- **WASM Sandbox**: Cryptographic operations isolated in browser
- **CLI Isolation**: No network access during processing
- **Web Server**: Static file serving only, no dynamic content

## Future Architecture Considerations

### 1. Scalability
- **Horizontal**: Multiple WASM workers for parallel processing
- **Performance**: Native crypto libraries via WASM
- **Caching**: Preprocessed share validation

### 2. Extensibility
- **New Schemes**: Plugin architecture for additional TSS schemes
- **Cryptocurrencies**: Modular handler system
- **Export Formats**: Configurable output formats

### 3. Integration Points
- **APIs**: RESTful endpoints for programmatic access
- **Mobile**: React Native bridge for mobile apps
- **Hardware**: HSM integration for enterprise use

## Development Guidelines

### 1. Adding New Cryptocurrency Support
1. Create handler in `pkg/keyhandlers/`
2. Add key derivation logic
3. Implement format conversion (WIF, hex, etc.)
4. Update `ProcessFileContent()` routing

### 2. Adding New TSS Schemes
1. Create package in `pkg/`
2. Implement scheme-specific processing
3. Add detection logic in `pkg/shared/`
4. Update build configuration

### 3. Frontend Enhancements
1. Modify `static/main.js` for UI changes
2. Update WASM bindings if needed
3. Test across CLI, web, and WASM modes
4. Ensure responsive design principles

This architecture provides a solid foundation for maintaining and extending the Vultisig Share Decoder while preserving security, performance, and cross-platform compatibility.
