import { ethers } from '@nomiclabs/buidler';
const log = console.log;

async function main() {
  const vault = await ethers.getContract('KeyVault');
  const factory = await ethers.getContract('KeyVaultFactory');

  let keyVault = await vault.deploy();
  await keyVault.deployed();
  let keyVaultFactory = await factory.deploy();
  await keyVaultFactory.deployed();
  await keyVaultFactory.setLibraryAddress(keyVault.address);

  log(keyVault.address);
  log(keyVaultFactory.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
