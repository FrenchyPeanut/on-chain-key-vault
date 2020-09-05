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

    constructor() public {
        initialized = true;
    }

    /**
     * @dev Initialize the contract for cloning
     * @param firstOwner name of the secret message to add
     * @param _sharedKey encrypted message of the secret key with the user derived wallet public-key
     * @param _salt salt used for signature and HD wallet derivation
     */
    function initialize(address firstOwner, string memory _sharedKey, string memory _salt) public {
        require(!initialized, 'The contract must not be initialized beforehand.');
        require(firstOwner != address(0), 'Cannot add zero address.');
        whitelistedUsers[firstOwner] = true;
        userKeys[firstOwner] = _sharedKey;
        salt = _salt;
        totalUsers = add(totalUsers, 1);
        initialized = true;
    }

    /**
     * @dev Authorize a new user to use the vault
     * @param _newUserAddress address of the user to whitelist
     * @param _newUserEncryptedSharedKey encrypted message of the secret key with the user derived wallet public-key
     */
    function addUserKey(address _newUserAddress, string memory _newUserEncryptedSharedKey) public onlyOwners returns (bool) {
        require(_newUserAddress != address(0), 'Cannot use zero-address.');
        userKeys[_newUserAddress] = _newUserEncryptedSharedKey;
        whitelistedUsers[_newUserAddress] = true;
        totalUsers = add(totalUsers, 1);
        return true;
    }

    /**
     * @dev Remove a user right from the vault
     * @param _userAddressToRemove address to remove from the vault
     */
    function removeUser(address _userAddressToRemove) public onlyOwners returns (bool)
    {
        require(_userAddressToRemove != address(0), 'Cannot use zero-address.');
        require(whitelistedUsers[_userAddressToRemove], 'The caller must be a whitelisted member.');
        whitelistedUsers[_userAddressToRemove] = false;
        totalUsers = sub(totalUsers, 1);
        userKeys[_userAddressToRemove] = '';
        return true;
    }

    /**
     * @dev Set a secret message
     * @param _secretName name of the secret message to add
     * @param _encryptedSecret encrypted message to add
     */
    function setSecret(string memory _secretName, string memory _encryptedSecret) public onlyOwners returns (bool) {
        require(bytes(secretValues[_secretName]).length == 0, 'A secret has already been added.');
        secretValues[_secretName] = _encryptedSecret;
        return true;
    }

    /**
     * @dev Return a secret message
     * @param _secretName name of the secret message to retrieve
     */
    function getSecret(string memory _secretName) public view returns (string memory) {
        return secretValues[_secretName];
    }

    /**
     * @dev Return the whitelisting status of a specific user
     * @param _address address of the user to search
     */
    function getWhitelistedUserStatus(address _address) public view returns (bool) {
        return whitelistedUsers[_address];
    }

    /**
     * @dev Return the encrypted secret key message of a specific user
     * @param _address address of the user to search
     */
    function getUserKeys(address _address) public view returns (string memory) {
        return userKeys[_address];
    }

    /**
     * @dev Return the salt
     */
    function getSalt() public view returns (string memory) {
        return salt;
    }

    /**
     * @dev SafeMath for addition
     * @param a first parameter
     * @param b second parameter
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256){
        require((a + b) >= a, 'SafeMath: Addition overflow');
        uint256 c = a + b;
        return c;
    }

    /**
     * @dev SafeMath for subtraction
     * @param a first parameter
     * @param b second parameter
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256){
        require(b <= a, 'SafeMath: Subtraction underflow.');
        uint256 c = a - b;
        return c;
    }

}
