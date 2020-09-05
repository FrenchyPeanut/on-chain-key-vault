// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

import './KeyVault.sol';
import './CloneFactory.sol';
import '@nomiclabs/buidler/console.sol';

contract KeyVaultFactory is CloneFactory {

    KeyVault[] public keyVaultAddresses;
    event KeyVaultDeployed(KeyVault keyVault_);

    address public vaultTarget;
    address private owner;

    mapping(address => KeyVault) userVaults;
    mapping(address => bool) hasVault;

    modifier onlyOwner() {
        require(owner == msg.sender, 'The caller must be the owner.');
        _;
    }

    constructor() public {
        owner = msg.sender;
    }

    /**
     * @dev Set the target contract for cloning
     * @param _vaultTarget address of the original smart-contract to use for cloning
     */
    function setLibraryAddress(address _vaultTarget) external onlyOwner {
        vaultTarget = _vaultTarget;
    }

    /**
     * @dev Create a new user vault
     * @param _sharedKey encrypted message of the secret key with the user derived wallet public-key
     * @param _salt salt used for signature and HD wallet derivation
     */
    function createVault(string calldata _sharedKey, string calldata _salt) external {
        require(!hasVault[msg.sender], 'Cannot deploy another keyVault.');
        KeyVault keyvault = KeyVault(
            createClone(vaultTarget)
        );
        keyvault.initialize(msg.sender, _sharedKey, _salt);

        keyVaultAddresses.push(keyvault);
        emit KeyVaultDeployed(keyvault);
        userVaults[msg.sender] = keyvault;
        hasVault[msg.sender] = true;
    }

    /**
     * @dev Return the addresses of the user vaults created through the factory
     */
    function getKeyVaults() external view returns (KeyVault[] memory) {
        return keyVaultAddresses;
    }

    /**
     * @dev Return the vault address for a specific user
     * @param _userAddress address of the user to search
     */
    function getUserKeyVaults(address _userAddress) external view returns (KeyVault) {
        return userVaults[_userAddress];
    }
}