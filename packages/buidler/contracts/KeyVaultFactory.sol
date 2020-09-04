// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

import './KeyVault.sol';
import './CloneFactory.sol';
import '@nomiclabs/buidler/console.sol';

contract KeyVaultFactory is CloneFactory {

    KeyVault[] public keyVaultAddresses;
    event KeyVaultDeployed(KeyVault metaCoin);

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

    function setLibraryAddress(address _vaultTarget) external onlyOwner {
        vaultTarget = _vaultTarget;
    }

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

    function getKeyVaults() external view returns (KeyVault[] memory) {
        return keyVaultAddresses;
    }

    function getUserKeyVaults(address _userAddress) external view returns (KeyVault) {
        return userVaults[_userAddress];
    }
}