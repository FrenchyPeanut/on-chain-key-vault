pragma solidity ^0.6.0;

import '@nomiclabs/buidler/console.sol';

contract KeyVault {

    uint256 public totalUsers;

    mapping(address => string) userKeys; // Jarvis required naming

    mapping(address => bool) whitelistedUsers; // Mapping to store addresses of vault ownership

    mapping(string => string) secretValues; // Mapping of the secrets

    modifier onlyOwners() {
        require(whitelistedUsers[msg.sender], 'The caller must be a whitelisted member.');
        _;
    }

    constructor(string memory _sharedKey) public {
        whitelistedUsers[msg.sender] = true;
        userKeys[msg.sender] = _sharedKey;
        require((totalUsers + 1) >= totalUsers, "SafeMath: addition overflow");
        totalUsers ++;
    }


    function addUserKey(address _newUserAddress, string memory _newUserEncryptedSharedKey) public onlyOwners returns (bool) {
        require(_newUserAddress != address(0), 'Cannot use zero-address.');
        userKeys[_newUserAddress] = _newUserEncryptedSharedKey;
        whitelistedUsers[_newUserAddress] = true;
        require((totalUsers + 1) >= totalUsers, "Addition overflow.");
        totalUsers ++;
        return true;
    }

    function removeUser(address _userAddressToRemove) public onlyOwners returns (bool)
    {
        require(_userAddressToRemove != address(0), 'Cannot use zero-address.');
        require(whitelistedUsers[_userAddressToRemove], 'The caller must be a whitelisted member.');
        whitelistedUsers[_userAddressToRemove] = false;
        require((totalUsers - 1) <= totalUsers, "Subtraction underflow.");
        totalUsers --;
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

}
