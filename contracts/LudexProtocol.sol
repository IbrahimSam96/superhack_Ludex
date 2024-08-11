//SPDX-License-Identifier: MIT

pragma solidity ^0.8.9;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.

/**
 * @dev Custom Errors for Ludex Protocol
 * @notice variableCheck parameter used for identifying which check failed based on order of declaration.
 */
error Ludex__CreateNewChallengeError(uint256 variableCheck);
error Ludex__LockChallengeError(uint256 variableCheck);
error Ludex__CancelChallengeError(uint256 variableCheck);
error Ludex__ResolveChallengeError(uint256 variableCheck);

error Ludex__JoinChallengeError(uint256 variableCheck);
error Ludex__LeaveChallengeError(uint256 variableCheck);

error Ludex__VerifiedError();
error Ludex__PayoutError();
error Ludex__PayoutToAddressError();
error Ludex__TransferFailedErorr();
error Ludex__GetChallengeError();

/**
 * @title Ludex Protocol Smart Contract
 * @author Ludex team Twitter: @ludex
 * @dev This contract is the main contract for the Ludex Protocol
 * @notice This contract is used to create, join, leave, lock, cancel and resolve challenges
 */
contract LudexProtocol is ReentrancyGuard, AccessControlDefaultAdminRules {
    // Enums
    enum ChallengeState {
        Open,
        Locked,
        Canceled,
        Resolved
    }
    // Structs

    struct Payout {
        address to;
        uint256 amount;
    }

    struct Challenge {
        bytes32 id;
        address payable mediator;
        address payable[] players;
        uint256 entryAmount;
        uint256 limit;
        ChallengeState state;
        bool verified;
        bool isNative;
        address tokenAddress;
        uint256 providerAmount;
        uint256 mediatorAmount;
        uint256 out;
    }
    // mappings

    mapping(bytes32 => Challenge) private s_challenges;
    // Variables
    uint256 private s_challengeCount = 0;
    address payable private s_providerVault;

    // Events
    event CreatedChallenge(bytes32 indexed id, uint256 _ludexId);
    event LockedChallenge(bytes32 indexed id);
    event CanceledChallenge(bytes32 indexed id);
    event ResolvedChallenge(bytes32 indexed id, Payout[] _payment);
    event JoinedChallenge(bytes32 indexed id, address indexed _player);
    event LeftChallenge(bytes32 indexed id, address indexed _player);
    // Roles

    bytes32 public constant ADMIN = keccak256("ADMIN");

    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable verifier;
    /// @notice Image ID of the only zkVM binary to accept verification from.
    ///         The image ID is similar to the address of a smart contract.
    ///         It uniquely represents the logic of that guest program,
    ///         ensuring that only proofs generated from a pre-defined guest program
    ///         (in this case, checking if a password is correct) are considered valid.
    bytes32 public constant imageId = ImageID.IS_EVEN_ID;

    /**
     * @dev Constructor (Initializor).
     * @notice Constructor is used to set the provider vault address and grant ADMIN role to the admin address. It also sets the initial default admin role to the deployer.
     * @param _providerVault Provider's vault address where provider rake will be transfered
     * @param _adminAddress Admin address to grant ADMIN role
     */
    constructor(
        address _providerVault,
        address _adminAddress,
        IRiscZeroVerifier _verifier
    ) AccessControlDefaultAdminRules(300, msg.sender) {
        s_providerVault = payable(_providerVault);
        _grantRole(ADMIN, _adminAddress);
        verifier = _verifier;
    }

    /// @dev Creates a challenge and adds it to the challenges mapping and increases the challenge count.
    /// @param _ludexId The Ludex id for the challenge (only used for emitting CreatedChallenge event)
    /// @param _mediator The address that will resolve the challenge
    /// @param _entryAmount Challenge entry amount (wei)
    /// @param _limit Challenge player limit
    /// @param _verified If the challenge is verified
    /// @param _isNative If the challenge is native
    /// @param _tokenAddress ERC20 token for the challenge (if not native)
    /// @param _providerAmount Provider fee for the challenge (wei)
    /// @param _mediatorAmount Mediator fee for the challenge  (wei)
    /// @param _out Challenge (verifier)
    ///  Emits a {CreatedChallenge} event.
    /// Requirements:
    /// - `msg.sender` must have ADMIN role
    /// - `_isNative == false` `_tokenAddress` cannot be empty
    /// - `_entryAmount` must be greater than 0
    /// - `_limit` must be greater than 0

    function createChallenge(
        uint256 _ludexId,
        address payable _mediator,
        uint256 _entryAmount,
        uint256 _limit,
        bool _verified,
        bool _isNative,
        address _tokenAddress,
        uint256 _providerAmount,
        uint256 _mediatorAmount,
        uint256 _out
    ) external onlyRole(ADMIN) nonReentrant {
        // Creating Callenge checks for valid inputs (token, limit, amount)
        bool tokenCheck = _isNative == false && _tokenAddress == address(0);
        bool numberCheck = _entryAmount < 0 && _limit < 1;

        if (tokenCheck) {
            revert Ludex__CreateNewChallengeError(0);
        }

        if (numberCheck) {
            revert Ludex__CreateNewChallengeError(1);
        }

        bytes32 id = keccak256(
            abi.encodePacked(address(this), s_challengeCount)
        );
        // create challenge
        s_challenges[id] = Challenge(
            id,
            _mediator,
            new address payable[](0),
            _entryAmount,
            _limit,
            ChallengeState.Open,
            _verified,
            _isNative,
            _tokenAddress,
            _providerAmount,
            _mediatorAmount,
            _out
        );

        s_challengeCount++;

        emit CreatedChallenge(id, _ludexId);
    }

    /// @dev Joins a challenge and adds the player to the challenge. If the challenge is verified, it verifies the proof.
    /// @param _id The id of the challenge

    ///  Emits a {JoinedChallenge} event.
    /// Requirements:
    /// - `challenge state` must be Open
    /// - `challenge players` length must be less than the challenge limit
    /// - `msg.value` must be equal to the challenge entry amount
    /// - `msg.sender` must not be in the challenge players array

    function joinChallenge(
        // bytes32 _id,
        uint256 lobbyPassword,
        bytes calldata seal
    ) external payable nonReentrant {
        // Challenge memory challenge = s_challenges[_id];
        // Checking Challenge State, player Limit, Amount, Double Entry
        // bool stateCheck = challenge.state == ChallengeState.Open;
        // bool limitCheck = challenge.players.length < challenge.limit;

        // bool amountCheck = false;
        // bool doubleEntryCheck = false;

        // Checks if player is already in the challenge
        // for (uint256 i = 0; i < challenge.players.length; i++) {
        //     if (challenge.players[i] == msg.sender) {
        //         doubleEntryCheck = true;
        //     }
        // }

        // Checks native cahllenge msg.value == challenge entry amount || ERC20 allowance >= challenge entry amount
        // if (challenge.isNative) {
        //     amountCheck = msg.value == challenge.entryAmount;
        // } else {
        //     ERC20 _tokenInterface = ERC20(challenge.tokenAddress);
        //     uint256 amountAllowance = _tokenInterface.allowance(
        //         msg.sender,
        //         address(this)
        //     );
        //     amountCheck = amountAllowance >= challenge.entryAmount;
        // }

        // if (!stateCheck) {
        //     revert Ludex__JoinChallengeError(0);
        // }

        // if (!limitCheck) {
        //     revert Ludex__JoinChallengeError(1);
        // }

        // if (!amountCheck) {
        //     revert Ludex__JoinChallengeError(2);
        // }

        // if (doubleEntryCheck) {
        //     revert Ludex__JoinChallengeError(3);
        // }

        // If the challenge is verified; Verify if proof is valid
        // if (challenge.verified) {
        bytes memory journal = abi.encode(lobbyPassword);
        verifier.verify(seal, imageId, sha256(journal));
        // }

        // Transfer ERC20 token entry amount from user to contract
        // if (!challenge.isNative) {
        //     ERC20 _tokenInterface = ERC20(challenge.tokenAddress);
        //     bool success = _tokenInterface.transferFrom(
        //         msg.sender,
        //         address(this),
        //         challenge.entryAmount
        //     );
        //     if (!success) {
        //         revert Ludex__TransferFailedErorr();
        //     }
        // }

        // Adds player to the challenge
        // s_challenges[_id].players.push(payable(msg.sender));

        // emit JoinedChallenge(_id, msg.sender);
    }

    /// @dev Leave a challenge, removes the player from the challenge and send / transfer the entry amount back to the player.
    /// @param _id The id of the challenge
    ///  Emits a {LeftChallenge} event.
    /// Requirements:
    /// - `challenge state` must be Open
    /// - `msg.sender` must be in the challenge players array

    function leaveChallenge(bytes32 _id) public nonReentrant {
        Challenge memory challenge = s_challenges[_id];
        // Checks
        bool stateCheck = challenge.state == ChallengeState.Open;
        bool playerCheck = false;

        // Checks if player is already in the challenge
        for (uint256 i = 0; i < challenge.players.length; i++) {
            if (challenge.players[i] == msg.sender) {
                playerCheck = true;
            }
        }

        if (!stateCheck) {
            revert Ludex__LeaveChallengeError(0);
        }

        if (!playerCheck) {
            revert Ludex__LeaveChallengeError(1);
        }

        // Removes player from the challenge
        for (uint256 i = 0; i < challenge.players.length; i++) {
            if (challenge.players[i] == msg.sender) {
                s_challenges[_id].players[i] = s_challenges[_id].players[
                    s_challenges[_id].players.length - 1
                ];
                s_challenges[_id].players.pop();
            }
        }

        // Sends native || transfers token amount from contract back to player
        if (challenge.isNative) {
            (bool success, ) = msg.sender.call{value: challenge.entryAmount}(
                ""
            );
            if (!success) {
                revert Ludex__TransferFailedErorr();
            }
        } else {
            ERC20 _tokenInterface = ERC20(challenge.tokenAddress);
            bool success = _tokenInterface.transfer(
                msg.sender,
                challenge.entryAmount
            );
            if (!success) {
                revert Ludex__TransferFailedErorr();
            }
        }
        emit LeftChallenge(_id, msg.sender);
    }

    /// @dev Locks challenge and prevents further players from joining.
    /// @param _id The id of the challenge
    ///  Emits a {LockedChallenge} event.
    /// Requirements:
    /// - `msg.sender` must have ADMIN role
    /// - `challenge state` must be Open
    /// - `challenge players` length must be greater than 1

    function lockChallenge(bytes32 _id) public onlyRole(ADMIN) nonReentrant {
        Challenge memory challenge = s_challenges[_id];

        bool stateCheck = challenge.state == ChallengeState.Open;
        bool playerCheck = challenge.players.length > 1;

        if (!stateCheck) {
            revert Ludex__LockChallengeError(0);
        }

        if (!playerCheck) {
            revert Ludex__LockChallengeError(1);
        }

        // Lock the challenge
        s_challenges[_id].state = ChallengeState.Locked;
        emit LockedChallenge(_id);
    }

    /// @notice Resolves a challenge and pays the player(s), mediator and provider.
    /// @param _id The id of the challenge
    /// @param _mediatorVault Mediator's vault address where rake will go
    /// @param _payment The array of payout(s) for the challenge
    ///  Emits a {ResolvedChallenge} event.
    /// Requirements:
    /// - `msg.sender` must be challenge mediator
    /// - `challenge state` must be Locked
    /// - `_payment` Checks if payout addresse(s) are in the challenge players array
    /// - `_payment` Checks if total amount of payouts is equal to the total amount of the entry fees - total provider rake - total mediator rake

    function resolveChallenge(
        bytes32 _id,
        address payable _mediatorVault,
        Payout[] calldata _payment
    ) external nonReentrant {
        Challenge memory challenge = s_challenges[_id];

        // Checks
        bool stateCheck = challenge.state == ChallengeState.Locked;
        bool mediatorCheck = challenge.mediator == msg.sender;

        if (!stateCheck) {
            revert Ludex__ResolveChallengeError(0);
        }

        if (!mediatorCheck) {
            revert Ludex__ResolveChallengeError(1);
        }

        // _payout array check; Checks if all the payouts addresses are in the challenge players array
        bool payoutCheck = false;
        uint256 total = 0;
        for (uint256 i = 0; i < _payment.length; i++) {
            // increment total for payout amount check
            total += _payment[i].amount;

            // check if all the to addresses exist in the current in game player array
            bool playerCheck = false;
            for (uint256 j = 0; j < challenge.players.length; j++) {
                if (_payment[i].to == challenge.players[j]) {
                    playerCheck = true;
                    break;
                }
            }

            if (!playerCheck) {
                revert Ludex__PayoutToAddressError();
            }
        }
        // _payout array check; Checks if total amount of payouts is equal to the total amount of the entry fees - total provider rake - total mediator rake
        if (
            total +
                (challenge.players.length * challenge.providerAmount) +
                (challenge.players.length * challenge.mediatorAmount) ==
            (challenge.players.length * challenge.entryAmount)
        ) {
            payoutCheck = true;
        }

        if (!payoutCheck) {
            revert Ludex__PayoutError();
        }

        // Loop through the _payment array and pay the players. Sends tokens || transfers tokens from contract to player
        for (uint256 i = 0; i < _payment.length; i++) {
            if (challenge.isNative) {
                (bool success, ) = _payment[i].to.call{
                    value: _payment[i].amount
                }("");
                if (!success) {
                    revert Ludex__TransferFailedErorr();
                }
            } else {
                ERC20 _tokenInterface = ERC20(challenge.tokenAddress);
                bool success = _tokenInterface.transfer(
                    _payment[i].to,
                    _payment[i].amount
                );
                if (!success) {
                    revert Ludex__TransferFailedErorr();
                }
            }
        }

        // Pays the mediator vault
        if (challenge.isNative) {
            (bool success, ) = _mediatorVault.call{
                value: challenge.players.length * challenge.mediatorAmount
            }("");
            if (!success) {
                revert Ludex__TransferFailedErorr();
            }
        } else {
            ERC20 _tokenInterface = ERC20(challenge.tokenAddress);
            bool success = _tokenInterface.transfer(
                _mediatorVault,
                challenge.players.length * challenge.mediatorAmount
            );
            if (!success) {
                revert Ludex__TransferFailedErorr();
            }
        }

        // Pays the provider vault
        if (challenge.isNative) {
            (bool success, ) = s_providerVault.call{
                value: challenge.players.length * challenge.providerAmount
            }("");
            if (!success) {
                revert Ludex__TransferFailedErorr();
            }
        } else {
            ERC20 _tokenInterface = ERC20(challenge.tokenAddress);
            bool success = _tokenInterface.transfer(
                s_providerVault,
                challenge.players.length * challenge.providerAmount
            );
            if (!success) {
                revert Ludex__TransferFailedErorr();
            }
        }

        // Resolve challenge state
        s_challenges[_id].state = ChallengeState.Resolved;

        emit ResolvedChallenge(_id, _payment);
    }

    /// @dev Cancels challenge and sends / transfers the entry amount back to the players.
    /// @param _id The id of the challenge
    ///  Emits a {CanceledChallenge} event.
    /// Requirements:
    /// - `msg.sender` must have ADMIN role
    /// - `challenge state` must be Locked || Open
    function cancelChallenge(bytes32 _id) public onlyRole(ADMIN) nonReentrant {
        Challenge memory challenge = s_challenges[_id];
        // Checks
        bool stateCheck = challenge.state == ChallengeState.Locked ||
            challenge.state == ChallengeState.Open;

        if (!stateCheck) {
            revert Ludex__CancelChallengeError(0);
        }
        // Sends native tokens || transfers ERC20 tokens back to players
        for (uint256 i = 0; i < challenge.players.length; i++) {
            if (challenge.isNative) {
                (bool success, ) = challenge.players[i].call{
                    value: challenge.entryAmount
                }("");
                if (!success) {
                    revert Ludex__TransferFailedErorr();
                }
            } else {
                ERC20 _tokenInterface = ERC20(challenge.tokenAddress);
                bool success = _tokenInterface.transfer(
                    challenge.players[i],
                    challenge.entryAmount
                );
                if (!success) {
                    revert Ludex__TransferFailedErorr();
                }
            }
        }

        // Cancel challenge
        s_challenges[_id].state = ChallengeState.Canceled;

        emit CanceledChallenge(_id);
    }

    // Setters

    /// @dev Sets the provider vault address
    /// @param _providerVault Provider's vault address where provider rake will go
    /// Requirements:
    /// - `msg.sender` must have DEFAULT_ADMIN_ROLE role
    function setProviderVault(
        address payable _providerVault
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        s_providerVault = _providerVault;
    }

    // View / Getter functions
    function getChallenge(bytes32 id) public view returns (Challenge memory) {
        bool ChallengeExists = s_challenges[id].mediator != address(0);
        if (!ChallengeExists) {
            revert Ludex__GetChallengeError();
        }
        return s_challenges[id];
    }

    function getChallengeCount() public view returns (uint256) {
        return s_challengeCount;
    }

    function getProviderVault() public view returns (address payable) {
        return s_providerVault;
    }

    // Helper Functions
    /// @dev These functions are used to verify the proof of the challenge
    function getTrimmedNumber(
        uint256 num,
        uint256 digits
    ) public pure returns (uint256) {
        uint256 numDigits = getNumDigits(num);
        if (numDigits > digits) {
            return num / (10 ** (numDigits - digits));
        }
        return num;
    }

    function getNumDigits(uint256 num) public pure returns (uint256) {
        if (num == 0) {
            return 1;
        }
        return uint256(log10(num)) + 1;
    }

    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }
}
