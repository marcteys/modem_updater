# nRF91 Modem Updater using `probe-rs`

## Summary

This is a tool to update the nRF91 modem firmware using the `probe-rs` crate. It provides both a CLI and library interface. Used in production on the [nRF9160 Feather](https://www.circuitdojo.com/products/nrf9160-feather) and [nRF9151 Feather](https://www.circuitdojo.com/products/nrf9151-feather).

Validated working on:

- nRF9160
- nRF9151
- nRF9161

## CLI Usage

To verify the modem firmware, run:

```bash
cargo run --bin updater -- verify <path_to_firmware_zip>
```

To program and verify the modem firmware, run:

```bash
cargo run --bin updater -- program <path_to_firmware_zip>
```

## Acknowledgements

This project is based on the work of [**@maxd-nordic**](https://github.com/maxd-nordic) in the [pyOCD](https://github.com/pyocd/pyOCD/blob/5166025ae5da5e093d6cfe2b26cae5e1334476e4/pyocd/target/family/target_nRF91.py#L629) project.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT) at your option.