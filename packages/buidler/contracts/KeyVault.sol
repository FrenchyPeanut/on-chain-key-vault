// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

import '@nomiclabs/buidler/console.sol';

contract KeyVault {

    string public salt;

    uint256 public totalUsers;

    bool public initialized;

    mapping(address => string) userKeys;

    mapping(address => bool) whitelistedUsers; // Mapping to store addresses of vault ownership

    mapping(string => string) secretValues; // Mapping of the secrets

    modifier onlyOwners() {
        require(whitelistedUsers[msg.sender], 'The caller must be a whitelisted member.');
        _;
    }

    // constructor(string memory _sharedKey, string memory _salt) public {
    //     whitelistedUsers[msg.sender] = true;
    //     userKeys[msg.sender] = _sharedKey;
    //     salt = _salt;
    //     totalUsers = add(totalUsers, 1);
    // }

    constructor() public {
        initialized = true;
    }

    function initialize(address firstOwner, string memory _sharedKey, string memory _salt) public {
        require(!initialized, 'The contract must not be initialized beforehand.');
        
        require(firstOwner != address(0), 'Cannot add zero address.');
        whitelistedUsers[firstOwner] = true;
        userKeys[firstOwner] = _sharedKey;
        salt = _salt;
        totalUsers = add(totalUsers, 1);
        initialized = true;
    }


    function addUserKey(address _newUserAddress, string memory _newUserEncryptedSharedKey) public onlyOwners returns (bool) {
        require(_newUserAddress != address(0), 'Cannot use zero-address.');
        userKeys[_newUserAddress] = _newUserEncryptedSharedKey;
        whitelistedUsers[_newUserAddress] = true;
        totalUsers = add(totalUsers, 1);
        return true;
    }

    function removeUser(address _userAddressToRemove) public onlyOwners returns (bool)
    {
        require(_userAddressToRemove != address(0), 'Cannot use zero-address.');
        require(whitelistedUsers[_userAddressToRemove], 'The caller must be a whitelisted member.');
        whitelistedUsers[_userAddressToRemove] = false;
        totalUsers = sub(totalUsers, 1);
        return true;
    }

    function setSecret(string memory _secretName, string memory _encryptedSecret) public onlyOwners returns (bool) {
        require(bytes(secretValues[_secretName]).length == 0, 'A secret has already been added.');
        secretValues[_secretName] = _encryptedSecret;
        return true;
    }

    function getSecret(string memory _secretName) public view returns (string memory) {
        return secretValues[_secretName];
    }

    function getWhitelistedUserStatus(address _address) public view returns (bool) {
        return whitelistedUsers[_address];
    }

    function getUserKeys(address _address) public view returns (string memory) {
        return userKeys[_address];
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256){
        require((a + b) >= a, 'SafeMath: Addition overflow');
        uint256 c = a + b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256){
        require(b <= a, 'SafeMath: Subtraction underflow.');
        uint256 c = a - b;
        return c;
    }

}
