# Wazuh Installation Assistant Documentation

This folder contains the technical documentation for the Wazuh installation assistant, Wazuh Passwords Tool, and Wazuh Certs Tool (hereinafter referred to as the Installation Assistant tools). The documentation is organized into the following guides:

- **Development Guide**: Instructions for building and testing the Installation Assistant tools.
- **Reference Manual**: Detailed information about the Installation Assistant tools configuration and usage.

## Requirements

To work with this documentation, you need **mdBook** installed. For installation instructions, refer to the [mdBook documentation](https://rust-lang.github.io/mdBook/).

## Usage

- To build the documentation, run:

  ```bash
  ./build.sh
  ```

  The output will be generated in the `book` directory.

- To serve the documentation locally for preview, run:

  ```bash
  ./server.sh
  ```

  The documentation will be available at [http://127.0.0.1:3000](http://127.0.0.1:3000).
