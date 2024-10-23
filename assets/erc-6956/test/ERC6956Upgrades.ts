import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { createHash } from 'node:crypto';
import { StandardMerkleTree } from "@openzeppelin/merkle-tree";
import { ERC6956Authorization, ERC6956Role, merkleTestAnchors, NULLADDR, createAttestation} from "./commons";
import { IERC6956AttestationLimitedInterfaceId, IERC6956InterfaceId, IERC6956FloatableInterfaceId, IERC6956ValidAnchorsInterfaceId} from "./commons";
import { FloatState } from "./ERC6956Full";

export async function minimalAttestationExample() {
  // #################################### PRELIMINARIES
  /*const merkleTestAnchors = [
      ['0x' + createHash('sha256').update('TestAnchor123').digest('hex')],
      ['0x' + createHash('sha256').update('TestAnchor124').digest('hex')],
      ['0x' + createHash('sha256').update('TestAnchor125').digest('hex')],
      ['0x' + createHash('sha256').update('TestAnchor126').digest('hex')],
      ['0x' + createHash('sha256').update('SaltLeave').digest('hex')] // shall never be used on-chain!
      ]
  const merkleTree = StandardMerkleTree.of(merkleTestAnchors, ["bytes32"]);*/

  // #################################### ACCOUNTS
  // Alice shall get the NFT, oracle signs the attestation off-chain 
  const [alice, oracle] = await ethers.getSigners();

  // #################################### CREATE AN ATTESTATION
  const to = alice.address;
  const anchor = merkleTestAnchors[0][0];
  // const proof = merkleTree.getProof([anchor]);
  const attestationTime = Math.floor(Date.now() / 1000.0); // Now in seconds UTC

  const validStartTime = 0;
  const validEndTime = attestationTime + 15 * 60; // 15 minutes valid from attestation

  // Hash and sign. In practice, oracle shall only sign when Proof-of-Control is established!
  const messageHash = ethers.solidityPackedKeccak256(["address", "bytes32", "uint256", 'uint256', "uint256", "bytes32[]"], [to, anchor, attestationTime, validStartTime, validEndTime, proof]);
  const sig = await oracle.signMessage(ethers.getBytes(messageHash));
  // Encode
  return ethers.AbiCoder.defaultAbiCoder().encode(['address', 'bytes32', 'uint256', 'uint256', 'uint256', 'bytes32[]', 'bytes'], [to, anchor, attestationTime,  validStartTime, validStartTime, proof, sig]);
}


  describe(`ERC6956 Upgrade tests`, function () {
    // Fixture to deploy the abnftContract contract and assign roles.
    // Besides owner there's user, minter and burner with appropriate roles.
    async function deployAbNftFixture() {

      // The address, users will interact with, will be stored here.
      let interfaceContractAddr: string | undefined = undefined;

      // Contracts are deployed using the first signer/account by default
      const [owner, maintainer, oracle, alice, bob, mallory, hacker, carl, gasProvider ] = await ethers.getSigners();
      const ImplContract = await ethers.getContractFactory("ERC6956Upgradeable");
      const logicContract = await ImplContract.deploy();

      const ERC6956Proxy = await ethers.getContractFactory("ERC6956Proxy");

      // Initialize the proxy with the implementation contract and the admin address
      const initializeData = new ethers.Interface(["function initialize(string, string)"])
      .encodeFunctionData("initialize", ["Asset-Bound NFT test upgradeable", "ABNFT"]);
      
      // The deployed proxy can then be used such as a normal ERC6956 contract
      const deployedProxy = await ERC6956Proxy.connect(owner).deploy(await logicContract.getAddress(), maintainer.address, initializeData);
      interfaceContractAddr = await deployedProxy.getAddress();     
      
      const abnftContract = await ethers.getContractAt("ERC6956", interfaceContractAddr);

      // Get the deployed contract, which may either be a proxy or the actual contract.
      //const abnftContract = await ethers.getContractAt("ERC6956", await interfaceContract!.getAddress());
      await abnftContract.connect(owner).updateMaintainer(maintainer.address, true);
      await expect(abnftContract.connect(maintainer).updateOracle(oracle.address, true))
        .to.emit(abnftContract, "OracleUpdate")
        .withArgs(oracle.address, true);


      return { abnftContract, logicContract, owner, maintainer, oracle, alice, bob, mallory, hacker, carl, gasProvider };
    }

    async function deployABTandMintTokenToAlice() {
      // Contracts are deployed using the first signer/account by default
      const {abnftContract, logicContract, owner, maintainer, oracle, alice, bob, mallory, hacker, carl, gasProvider} = await deployAbNftFixture();
    
      const anchor = merkleTestAnchors[0][0];
      const mintAttestationAlice = await createAttestation(alice.address, anchor, oracle); // Mint to alice

      await expect(abnftContract.connect(gasProvider)["transferAnchor(bytes)"](mintAttestationAlice))
      .to.emit(abnftContract, "Transfer") // Standard ERC721 event
      .withArgs(NULLADDR, alice.address, 1);

      return { abnftContract, logicContract, owner, maintainer, oracle, mintAttestationAlice, anchor, alice, bob, mallory, hacker, carl, gasProvider };
    }    

    async function upgradeContract(proxyAddr:string, wallet, newContractName: string) {

      // deploy the full contract with wallet - it really shouldn't matter which wallet deploys it..
      const ERC6956FullUpgradeable = await ethers.getContractFactory(newContractName);
      const newLogicContract = await ERC6956FullUpgradeable.deploy();
      const abNftUpgradeable = await ethers.getContractAt("ERC6956Upgradeable", proxyAddr);
      return abNftUpgradeable.connect(wallet).upgradeToAndCall(await newLogicContract.getAddress(), "0x");
    }

    it("ERC721 transfer works after ERC6956->ERC6956 upgrade", async function () {
      const {abnftContract, owner, maintainer, oracle, alice, bob, mallory, hacker, carl, gasProvider} = await deployABTandMintTokenToAlice();
      
      // Verify token is indeed owned by alice
      expect(await abnftContract.ownerOf(1)).to.equal(alice.address);

      const anchor = merkleTestAnchors[1][0];
      const mintAttestationBob = await createAttestation(bob.address, anchor, oracle); // Mint to bob

      expect(await abnftContract["transferAnchor(bytes)"](mintAttestationBob))
      .to.emit(abnftContract, "Transfer") // Standard ERC721 event
      .withArgs(NULLADDR, bob.address, 2)     

      // We have the standard ERC-6956 deployed. 
      await expect(abnftContract["safeTransferFrom(address,address,uint256)"](bob.address, alice.address, 2))
      .to.be.revertedWith("ERC6956-E5"); // token not transferable

      // Standard ERC-6956 does not allow ERC-721-like transfers.
      // So lets upgrade the contract to the ERC6956Full
      // Then it will be possible, when anchors are floating.

      // So far, we interact with the ERC6956 ABI - so lets get really into the upgradeable ABI    
      await upgradeContract(await abnftContract.getAddress(), maintainer, "ERC6956FullUpgradeable")

      const abNftAsFull = await ethers.getContractAt("ERC6956Full", await abnftContract.getAddress());

      // it is still at the same address, something the ERC6956Proxy ensures
      expect(await abNftAsFull.getAddress()).to.equal(await abnftContract.getAddress());

      // check if tokenId 2 is floating
      expect(await abNftAsFull.floating(anchor)).to.be.false;
      // Check it's still owned by bob
      expect(await abNftAsFull.ownerOf(2)).to.equal(bob.address);

      // Per default, ERC6956Full does not allow anybody to set tokens floating
      // Hence, the maintainer needs to allow it first.
      // This allows OWNER_AND_ASSET to start floating, and the issuer (so the contract via maintainer) to stop floating
      await expect(abNftAsFull.connect(maintainer).updateFloatingAuthorization(ERC6956Authorization.OWNER_AND_ASSET, ERC6956Authorization.ISSUER))
      .to.emit(abNftAsFull, "FloatingAuthorizationChange")
      .withArgs(ERC6956Authorization.OWNER_AND_ASSET, ERC6956Authorization.ISSUER, maintainer.address);

      // Finally, Bob can set the NFT to be floating
      await expect(await abNftAsFull.connect(bob).float(anchor, FloatState.Floating))
      .to.emit(abNftAsFull, "FloatingStateChange")
      .withArgs(anchor, 2, FloatState.Floating, bob.address);


      // Finally, Bob can transfer his precious NFT via normal ERC-721 safeTransferFrom
      await expect(abNftAsFull.connect(bob)["safeTransferFrom(address,address,uint256)"](bob.address, alice.address, 2))
      .to.emit(abNftAsFull, "Transfer")
      .withArgs(bob.address, alice.address, 2);

      // Check its now really owned by alice
      expect(await abnftContract.ownerOf(2)).to.equal(alice.address);


    });


  });