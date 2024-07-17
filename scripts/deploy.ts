import { ethers } from 'hardhat';



async function deployContracts(): Promise<void> {
  const [deployer] = await ethers.getSigners();

  console.log('Deploying contracts with the account:', deployer.address);

  const Verifier = await ethers.getContractFactory('Halo2Verifier');
  const verifier = await Verifier.deploy();

  const CreditsAttestation = await ethers.getContractFactory('CarbonCreditsContract');
  const creditsAttestation = await CreditsAttestation.deploy(verifier);

  console.log('Verifier deployed to:', verifier.target);
  console.log('CarbonCreditsContract deployed to:', creditsAttestation.target);

}

deployContracts()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
