import { ethers as HH } from 'hardhat';
import { Contract } from 'ethers';
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import data from '../prover/evmInputs.json';
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
chai.use(chaiAsPromised);
const { expect } = chai;

// Load environment variables from .env file
describe('CarbonCreditsContract', function () {
  let creditsAttestation: Contract;
  var addr1: SignerWithAddress; // 

  var proof = data.proof;
  //var proof2 = proof.substring(0, 2) + 'B' + proof.substring(3);
  var instances = data.instances;
  console.log("This is the vaid proof: ", proof);
  //console.log("This is the invalid proof: ", proof2);
  //console.log("These are the instances: ", instances);


  beforeEach(async function () {
    // Deploy Verifier contract
    const Verifier = await HH.getContractFactory('Halo2Verifier');
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    // Deploy CreditsAttestation contract
    const CreditsAttestation = await HH.getContractFactory('CarbonCreditsContract');
    creditsAttestation = await CreditsAttestation.deploy(verifier) as unknown as Contract;
    await creditsAttestation.waitForDeployment();

    const signers = await HH.getSigners(); // get the signer for addr1
    addr1 = signers[0];
  });

  it('should allow user to claim credit after a valid proof is submitted', async function () {
    // Submit a valid proof
    const tx = await creditsAttestation.claimCredits(proof, instances);
    //console.log(tx);
    await expect(tx.wait()).to.not.be.reverted;
    //const receipt = await tx.wait();

    const receipt = await HH.provider.getTransactionReceipt(tx.hash);
    let totalGasUsed: BigInt = BigInt(0);
    if (receipt !== null) {
        totalGasUsed = receipt.gasUsed;
    }

    console.log('Gas used:', totalGasUsed.toString());
    var events = await creditsAttestation.queryFilter("ProofSubmitted");
    expect(events.length).to.equal(1);
    expect(events.length).to.equal(1);
    events.forEach(event => {
      if ('args' in event) {
        const proof = event.args.proof;
        const maxCharactersToShow = 100;
        const portionToLog = proof.length > maxCharactersToShow
          ? proof.substring(0, maxCharactersToShow) + '...'
          : proof;
        console.log(`\n Verification Event: 
          User: ${event.args.submitter}
          Instances (decimal): ${event.args.instances}
          Proof (Partial): ${portionToLog}`);
      }
    });

    // Check if user balance has increased
    const balance = await creditsAttestation.balances(addr1.address);
    expect(balance).to.be.above(0);
  });

  /*
  it('should NOT allow user to claim credit after an invalid proof is submitted', async function () {
    // Submit an invalid proof
    const tx = await creditsAttestation.claimCredits(proof2, instances);
    await expect(tx.wait()).to.eventually.be.rejected;
    //await expect(tx.wait()).to.be.reverted;
    // Check if user balance has not increased
    const balance = await creditsAttestation.balances(addr1.address);
    expect(balance).to.equal(0);
  });
  */


});