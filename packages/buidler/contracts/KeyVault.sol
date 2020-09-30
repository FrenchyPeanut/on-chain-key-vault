// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

import '@nomiclabs/buidler/console.sol';

contract KeyVault {

    string public salt;

    uint256 public totalUsers;

    bool public initialized;

    struct userData {
        string userDerivedPublicKey;
        string userEncryptedKey;
        uint256 userVaultVersion;
        bool isWhitelisted;
        uint256 userIndex;
    }
    uint256 public vaultVersion;
    // uint256 public blockNumber;
    // uint256 public renewalBlockLimit;
    uint public timestamp;
    uint256 public renewalTimestamp;

    mapping(address => userData) userDataMapping;

    mapping(uint => address) userWhitelistedIndexMapping;

    mapping(string => string) secretValues; // Mapping of the secrets

    modifier onlyOwners() {
        require(userDataMapping[msg.sender].isWhitelisted, 'The caller must be a whitelisted member.');
        _;
    }

    modifier stillActive() {
        // require(block.number < blockNumber, 'The Vault is no longer active');
        require(block.timestamp < timestamp, 'The Vault is no longer active.');
        _;
    }

    modifier hasVersion() {
        require(vaultVersion == userDataMapping[msg.sender].userVaultVersion, 'The user is not up-to-date with the vault version.');
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
     * @param _userDerivedPublicKey public-key of the user derived wallet
     */
    function initialize(address firstOwner, string memory _sharedKey, string memory _salt, string memory _userDerivedPublicKey) public {
        require(!initialized, 'The contract must not be initialized beforehand.');
        require(firstOwner != address(0), 'Cannot add zero address.');

        vaultVersion = 1;

        userDataMapping[firstOwner].userVaultVersion = vaultVersion;
        userDataMapping[firstOwner].userDerivedPublicKey = _userDerivedPublicKey;
        userDataMapping[firstOwner].isWhitelisted = true;
        userDataMapping[firstOwner].userEncryptedKey = _sharedKey;
        userDataMapping[firstOwner].userIndex = totalUsers;
        
        salt = _salt;
        userWhitelistedIndexMapping[totalUsers] = firstOwner;
        totalUsers = add(totalUsers, 1);
        // renewalBlockLimit = 210000; // Approximately 6500-7000 blocks per day
        // blockNumber = add(block.number, renewalBlockLimit);
        renewalTimestamp = 60*60*24*30; // Approximately 30 days
        timestamp = add(block.timestamp, renewalTimestamp);
        initialized = true;
    }

    /**
     * @dev Authorize a new user to use the vault
     * @param _newUserAddress address of the user to whitelist
     * @param _newUserEncryptedSharedKey encrypted message of the secret key with the user derived wallet public-key
     * @param _userDerivedPublicKey public-key of the user derived wallet
     */
    function addUserKey(address _newUserAddress, string memory _newUserEncryptedSharedKey, string memory _userDerivedPublicKey) public onlyOwners stillActive hasVersion returns (bool) {
        require(_newUserAddress != address(0), 'Cannot use zero-address.');

        userDataMapping[_newUserAddress].userIndex = totalUsers;
        userWhitelistedIndexMapping[totalUsers] = _newUserAddress;
        totalUsers = add(totalUsers, 1);

        userDataMapping[_newUserAddress].userVaultVersion = vaultVersion;
        userDataMapping[_newUserAddress].isWhitelisted = true;
        userDataMapping[_newUserAddress].userEncryptedKey = _newUserEncryptedSharedKey;
        userDataMapping[_newUserAddress].userDerivedPublicKey = _userDerivedPublicKey;

        return true;
    }

    /**
     * @dev Remove a user right from the vault
     * @param _userAddressToRemove address to remove from the vault
     */
    function removeUser(address _userAddressToRemove) public onlyOwners stillActive hasVersion returns (bool) {
        require(_userAddressToRemove != address(0), 'Cannot use zero-address.');
        require(userDataMapping[_userAddressToRemove].isWhitelisted, 'The user to remove must be a whitelisted member.');

        userDataMapping[_userAddressToRemove].userEncryptedKey = ''; // We set it as empty for the front-end behavior
        userDataMapping[_userAddressToRemove].isWhitelisted = false;

        if(totalUsers != userDataMapping[_userAddressToRemove].userIndex) { // We are not removing the last value
            userDataMapping[userWhitelistedIndexMapping[totalUsers]].userIndex = userDataMapping[_userAddressToRemove].userIndex;
            userWhitelistedIndexMapping[userDataMapping[_userAddressToRemove].userIndex] = userWhitelistedIndexMapping[totalUsers];
        }

        delete userDataMapping[_userAddressToRemove];
        delete userWhitelistedIndexMapping[totalUsers];
        totalUsers = sub(totalUsers, 1);

        return true;
    }

    /**
     * @dev Set a secret message
     * @param _secretName name of the secret message to add
     * @param _encryptedSecret encrypted message to add
     */
    function setSecret(string memory _secretName, string memory _encryptedSecret) public onlyOwners stillActive hasVersion returns (bool) {
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
        return userDataMapping[_address].isWhitelisted;
    }

    /**
     * @dev Return the vault version of a specific user
     * @param _address address of the user to search
     */
    function getUserVaultVersion(address _address) public view returns (uint256) {
        return userDataMapping[_address].userVaultVersion;
    }

    /**
     * @dev Return the encrypted secret key message of a specific user
     * @param _address address of the user to search
     */
    function getUserKeys(address _address) public view returns (string memory) {
        return userDataMapping[_address].userEncryptedKey;
    }

    /**
     * @dev Return the vault salt
     */
    function getSalt() public view returns (string memory) {
        return salt;
    }

    /**
     * @dev SafeMath for addition
     * @param a first parameter
     * @param b second parameter
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        require((a + b) >= a, 'SafeMath: Addition overflow');
        uint256 c = a + b;
        return c;
    }

    /**
     * @dev SafeMath for subtraction
     * @param a first parameter
     * @param b second parameter
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, 'SafeMath: Subtraction underflow.');
        uint256 c = a - b;
        return c;
    }

    /**
     * @dev Return address of whitelisted user based on index
     * @param _index index parameter
     */
    function getWhitelistedUser(uint256 _index) public view onlyOwners returns (address) {
        require(_index <= totalUsers, 'Out of bound.');
        return userWhitelistedIndexMapping[_index];
    }

    /**
     * @dev Renew a user encrypted shared-key
     * @param _userAddress address of the user to update
     * @param _newUserEncryptedSharedKey encrypted message of the secret key with the user derived wallet public-key
     */
    function renewUser(address _userAddress, string memory _newUserEncryptedSharedKey) public onlyOwners stillActive hasVersion returns (bool) {
        require(userDataMapping[_userAddress].isWhitelisted, 'The renewed address must be whitelisted.');
        require(userDataMapping[_userAddress].userVaultVersion < vaultVersion, 'The updated user must have a lower vault version.');
        userDataMapping[_userAddress].userVaultVersion = vaultVersion;
        userDataMapping[_userAddress].userEncryptedKey = _newUserEncryptedSharedKey;
        return true;
    }

    /**
     * @dev Return the derived public-key of a vault user
     * @param _userAddress address of the user to retrieve
     */
    function getUserDerivedPublicKey(address _userAddress) public view returns (string memory) {
        return userDataMapping[_userAddress].userDerivedPublicKey;
    }

    /**
     * @dev Renew a time-locked vault
     * @param _newUserEncryptedSharedKey encrypted message of the secret key with the user derived wallet public-key
     */
    function renewVault(string memory _newUserEncryptedSharedKey) public onlyOwners returns (bool) {
        require(userDataMapping[msg.sender].userVaultVersion == vaultVersion, 'The user must have the current version of the vault.');
        // require(block.number > blockNumber, 'The vault must be deprecated.');
        require(block.timestamp > timestamp, 'The vault must be deprecated.');

        vaultVersion = add(vaultVersion, 1);
        // blockNumber = add(block.number, renewalBlockLimit);
        timestamp = add(block.timestamp, renewalTimestamp);
        userDataMapping[msg.sender].userVaultVersion = vaultVersion;
        userDataMapping[msg.sender].userEncryptedKey = _newUserEncryptedSharedKey;

        return true;
    }
}
