import hardhat from "hardhat";
const { ethers } = hardhat;
import fs from "fs";

async function main() {
  console.log("Deploying PosthumousRelease...");

  const [owner, t1, t2, t3, t4, t5, beneficiary] = await ethers.getSigners();

  const Contract = await ethers.getContractFactory("PosthumousRelease");
  const contract = await Contract.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("Contract deployed at:", address);

  await contract.connect(owner).createVault(
    "QmExampleHash123",
    "ipfs://QmExampleHash123",
    1, 3,
    beneficiary.address,
    "My Digital Legacy"
  );
  console.log("Vault #0 created");

  const trustees = [t1, t2, t3, t4, t5];
  const names = ["Dr. Smith", "Prof. Lee", "Sarah J.", "Mark D.", "Elena V."];
  for (let i = 0; i < trustees.length; i++) {
    await contract.connect(owner).addTrustee(
      0, trustees[i].address, names[i],
      ethers.keccak256(ethers.toUtf8Bytes(`share_${i}`))
    );
    console.log("Trustee added:", names[i]);
  }

  await contract.connect(t1).confirmDeath(0);
  await contract.connect(t2).confirmDeath(0);
  await contract.connect(t3).confirmDeath(0);
  console.log("Death confirmed by 3 trustees");

  await contract.connect(t1).submitShare(0, "ENCRYPTED_SHARE_1");
  await contract.connect(t2).submitShare(0, "ENCRYPTED_SHARE_2");
  await contract.connect(t3).submitShare(0, "ENCRYPTED_SHARE_3");
  console.log("Shares submitted - Vault RELEASED!");

  const artifactPath = "./artifacts/contracts/PosthumousRelease.sol/PosthumousRelease.json";
  const artifact = JSON.parse(fs.readFileSync(artifactPath));
  fs.mkdirSync("./frontend/src", { recursive: true });
  fs.writeFileSync("./frontend/src/deployment.json", JSON.stringify({
    contractAddress: address,
    abi: artifact.abi
  }, null, 2));
  console.log("Saved deployment.json to frontend/src/");
}

main().catch((e) => { console.error(e); process.exit(1); });