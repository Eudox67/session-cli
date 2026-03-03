# Session CLI

A command-line interface (CLI) for interacting with the Session messaging network. This tool allows you to send and receive messages securely and anonymously without a GUI.

## About

Session CLI is a lightweight, efficient, and cross-platform client for the Session network. It provides a simple way to manage your Session account and communicate with others from the comfort of your terminal.

## Requirements

- **Free Pascal Compiler (FPC):** A recent version (3.2.0 or later) is required for compilation.
- **Dependencies:**
  - `libzmq` (ZeroMQ) for networking.
  - `libsodium` (cryptographic libraries).
  - `libsession-util`, `libsession-crypto`, `libsession-onionreq`, `libsession-config` (Oxen/Session libraries).
- **Libraries for Linux:**
  - `libssl-dev`
  - `libcrypto-dev`
  - `libzmq3-dev`

## Installation

### From Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/Eudox67/session-cli.git
    cd session-cli
    ```
2.  Compile the project using the provided `Makefile`:
    ```bash
    make build
    ```
    The compiled binary will be placed in the `bin/` directory.

### Running Tests

To compile and run the test suite:
```bash
make tests
./bin/test_all
```

## Usage

Start the CLI by running the binary:
```bash
./bin/session-cli
```
Refer to the command-line help (`./bin/session-cli --help`) for more information on available commands and options.

## Credits & Acknowledgments

This project would not be possible without the excellent work of:

- **The Session Team:** For creating the Session messaging network and the underlying protocols.
- **The ZeroMQ Team:** For providing the powerful `libzmq` messaging library.
- **DJMaster:** For the Free Pascal bindings to ZeroMQ (`zmq.pas`), enabling ZeroMQ usage in Pascal projects.
- **The Free Pascal Team:** For the robust and efficient compiler.

## Project Structure

- `src/`: Core source code and library units.
- `tests/`: Unit tests and integration tests.
- `bin/`: Compilation output directory (ignored by version control).

## License

See [LICENSE.md](LICENSE.md)
