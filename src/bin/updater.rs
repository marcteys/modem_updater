// Copyright 2025 Jared Wolff
//
// Licensed under the Apache License, Version 2.0 (the "Apache License")
// with the following modification; you may not use this file except in
// compliance with the Apache License and the following modification to it:
// Section 6. Trademarks. is deleted and replaced with:
//
// 6. Trademarks. This License does not grant permission to use the trade
//    names, trademarks, service marks, or product names of the Licensor
//    and its affiliates, except as required to comply with Section 4(c) of
//    the License and to reproduce the content of the NOTICE file.
//
// You may obtain a copy of the Apache License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the Apache License with the above modification is
// distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the Apache License for the specific
// language governing permissions and limitations under the Apache License.
//
// Alternatively, you may use this file under the terms of the MIT license,
// which is:
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use std::{thread, time::Duration};

use chrono::Utc;
use modem_updater::ModemUpdater;
use probe_rs::{
    probe::{list::Lister, DebugProbeSelector},
    Permissions,
};

fn print_usage() {
    println!("Modem Updater Usage:");
    println!("  updater <operation> <firmware_path>");
    println!("\nOperations:");
    println!("  verify   - Verify firmware at the specified path");
    println!("  program  - Program and verify firmware at the specified path");
    println!("\nExample:");
    println!("  updater program _bin/mfw_nrf91x1_2.0.2.zip");
}

fn main() {
    env_logger::init();

    // Check if any arguments were provided
    if std::env::args().len() < 3 {
        print_usage();
        std::process::exit(1);
    }

    let lister = Lister::new();
    let mut probe;

    // First argument is the operation (verify or program)
    let operation = std::env::args().nth(1).expect("Operation not provided!");

    // Get second arguement as path to firmware
    let path = std::env::args()
        .nth(2)
        .expect("Firmware path not provided!");

    // Get probe with timeout
    let start = Utc::now().timestamp_millis();
    loop {
        probe = match lister.open(DebugProbeSelector {
            vendor_id: 0x2e8a,
            product_id: 0x000c,
            serial_number: None,
        }) {
            Ok(p) => p,
            Err(_e) => {
                let now = Utc::now().timestamp_millis();
                if now > start + 2000 {
                    panic!("Unable to get probe!");
                } else {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }
        };

        break;
    }

    // Set speed
    probe.set_speed(12000).unwrap();

    // Attach
    let mut session = match probe.attach("nRF9160_xxAA", Permissions::new().allow_erase_all()) {
        Ok(s) => s,
        Err(e) => panic!("Unable to attach to probe! Error: {}", e),
    };

    // Get updater
    let mut updater = ModemUpdater::new(&mut session);

    if operation == "verify" {
        updater.verify(&path).unwrap();
    } else if operation == "program" {
        updater.program_and_verify(&path).unwrap();
    } else {
        println!("\nError: Unknown operation '{}'", operation);
        print_usage();
        std::process::exit(1);
    }
}
