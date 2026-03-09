import { expect } from "chai";
import hardhat from "hardhat";
const { ethers } = hardhat;
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("PosthumousRelease", function () {
  let contract, owner, t1, t2, t3, t4, t5, beneficiary, other;

  beforeEach(async function () {
    [owner, t1, t2, t3, t4, t5, beneficiary, other] = await ethers.getSigners();
    const C = await ethers.getContractFactory("PosthumousRelease");
    contract = await C.deploy();
    await contract.waitForDeployment();
  });

  async function makeVault(days = 365) {
    return contract.connect(owner).createVault(
      "QmHash", "ipfs://QmHash", days, 3, beneficiary.address, "Test"
    );
  }

  async function addTrustees(vaultId = 0) {
    const trustees = [t1, t2, t3, t4, t5];
    for (let i = 0; i < trustees.length; i++) {
      await contract.connect(owner).addTrustee(
        vaultId, trustees[i].address, `T${i}`,
        ethers.keccak256(ethers.toUtf8Bytes(`s${i}`))
      );
    }
  }

  it("creates a vault correctly", async () => {
    await makeVault();
    const v = await contract.getVault(0);
    expect(v.owner).to.equal(owner.address);
    expect(v.status).to.equal(0);
  });

  it("adds trustees", async () => {
    await makeVault();
    await addTrustees();
    const list = await contract.getTrustees(0);
    expect(list.length).to.equal(5);
  });

  it("confirms death and changes status at threshold", async () => {
    await makeVault();
    await addTrustees();
    // Check vault is still Active after adding trustees
    const vBefore = await contract.getVault(0);
    expect(vBefore.status).to.equal(0); // Active

    await contract.connect(t1).confirmDeath(0);
    await contract.connect(t2).confirmDeath(0);
    await contract.connect(t3).confirmDeath(0);
    const v = await contract.getVault(0);
    expect(v.status).to.equal(1); // DeathReported
  });

  it("releases vault when threshold shares submitted", async () => {
    await makeVault();
    await addTrustees();
    await contract.connect(t1).confirmDeath(0);
    await contract.connect(t2).confirmDeath(0);
    await contract.connect(t3).confirmDeath(0);
    await contract.connect(t1).submitShare(0, "S1");
    await contract.connect(t2).submitShare(0, "S2");
    await contract.connect(t3).submitShare(0, "S3");
    expect((await contract.getVault(0)).status).to.equal(2); // Released
  });

  it("blocks share submission before death confirmed", async () => {
    await makeVault();
    await addTrustees();
    await expect(contract.connect(t1).submitShare(0, "S1"))
      .to.be.revertedWith("Release conditions not met");
  });

  it("allows share submission after timelock expires", async () => {
    await makeVault(1);
    await addTrustees();
    await time.increase(2 * 24 * 60 * 60);
    await expect(contract.connect(t1).submitShare(0, "S1"))
      .to.emit(contract, "TimelockTriggered");
  });

  it("owner can cancel vault", async () => {
    await makeVault();
    await contract.connect(owner).cancelVault(0);
    expect((await contract.getVault(0)).status).to.equal(3); // Cancelled
  });

  it("rejects non-trustee confirmations", async () => {
    await makeVault();
    await addTrustees();
    await expect(contract.connect(other).confirmDeath(0))
      .to.be.revertedWith("Not a trustee");
  });
});
