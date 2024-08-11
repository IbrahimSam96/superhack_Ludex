// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;
import {Script} from "forge-std/Script.sol";

import {RiscZeroCheats} from "risc0/test/RiscZeroCheats.sol";
import {console} from "forge-std/console.sol";

// import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {LudexProtocol} from "../contracts/LudexProtocol.sol";
import {Elf} from "./Elf.sol"; // auto-generated contract after running `cargo build`.

contract EvenNumberTest is RiscZeroCheats, Test {
    LudexProtocol public ludex;

    function setUp() public {
        IRiscZeroVerifier verifier = deployRiscZeroVerifier();
        ludex = new LudexProtocol(
            address(0x1b60611eA0f3DBeeD2aF58E72c081d05DB9E8FE0),
            address(0x1b60611eA0f3DBeeD2aF58E72c081d05DB9E8FE0),
            verifier
        );
    }

    function test_Prove() public {
        uint256 lobbyPassword = 12345;
        (bytes memory journal, bytes memory seal) = prove(
            Elf.IS_EVEN_PATH,
            abi.encode(lobbyPassword)
        );
        console.log(abi.decode(journal, (uint256)));
        console.logBytes(seal);
        console.logBytes(journal);

        ludex.joinChallenge(lobbyPassword, seal);
    }
}
