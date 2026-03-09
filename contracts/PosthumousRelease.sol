// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract PosthumousRelease {

    enum VaultStatus { Active, DeathReported, Released, Cancelled }

    struct Vault {
        address owner;
        string  encryptedDataHash;
        string  encryptedDataURI;
        uint256 timelockExpiry;
        uint8   threshold;
        uint8   totalShares;
        uint8   sharesSubmitted;
        VaultStatus status;
        address beneficiary;
        uint256 createdAt;
        string  description;
    }

    struct Trustee {
        address addr;
        string  name;
        bool    hasSubmittedShare;
        bool    hasConfirmedDeath;
        bytes32 shareCommitment;
    }

    struct ShareSubmission {
        address trustee;
        string  encryptedShare;
        uint256 submittedAt;
    }

    uint256 public vaultCount;

    mapping(uint256 => Vault)                        public vaults;
    mapping(uint256 => Trustee[])                    public trustees;
    mapping(uint256 => mapping(address => bool))     public isTrustee;
    mapping(uint256 => mapping(address => uint256))  public trusteeIndex;
    mapping(uint256 => ShareSubmission[])            public shareSubmissions;
    mapping(uint256 => mapping(address => bool))     public hasSubmitted;
    mapping(uint256 => uint8)                        public deathConfirmations;

    event VaultCreated(uint256 indexed vaultId, address indexed owner, address beneficiary, uint256 timelockExpiry);
    event TrusteeAdded(uint256 indexed vaultId, address indexed trustee, string name);
    event DeathReported(uint256 indexed vaultId, address indexed reportedBy, uint8 confirmations);
    event ShareSubmitted(uint256 indexed vaultId, address indexed trustee, uint8 sharesNow);
    event VaultReleased(uint256 indexed vaultId, address indexed beneficiary, uint256 timestamp);
    event VaultCancelled(uint256 indexed vaultId, address indexed owner);
    event TimelockTriggered(uint256 indexed vaultId, uint256 expiredAt);

    modifier onlyOwner(uint256 vaultId) {
        require(msg.sender == vaults[vaultId].owner, "Not vault owner");
        _;
    }

    modifier onlyTrustee(uint256 vaultId) {
        require(isTrustee[vaultId][msg.sender], "Not a trustee");
        _;
    }

    modifier vaultExists(uint256 vaultId) {
        require(vaultId < vaultCount, "Vault does not exist");
        _;
    }

    modifier vaultActive(uint256 vaultId) {
        require(vaults[vaultId].status == VaultStatus.Active, "Vault not active");
        _;
    }

    function createVault(
        string memory encryptedDataHash,
        string memory encryptedDataURI,
        uint256 timelockDays,
        uint8 threshold,
        address beneficiary,
        string memory description
    ) external returns (uint256 vaultId) {
        require(threshold >= 1, "Threshold must be >= 1");
        require(beneficiary != address(0), "Invalid beneficiary");
        require(timelockDays >= 1, "Timelock must be at least 1 day");

        vaultId = vaultCount++;

        vaults[vaultId] = Vault({
            owner:             msg.sender,
            encryptedDataHash: encryptedDataHash,
            encryptedDataURI:  encryptedDataURI,
            timelockExpiry:    block.timestamp + (timelockDays * 1 days),
            threshold:         threshold,
            totalShares:       0,
            sharesSubmitted:   0,
            status:            VaultStatus.Active,
            beneficiary:       beneficiary,
            createdAt:         block.timestamp,
            description:       description
        });

        emit VaultCreated(vaultId, msg.sender, beneficiary, vaults[vaultId].timelockExpiry);
    }

    function addTrustee(
        uint256 vaultId,
        address trusteeAddr,
        string memory trusteeName,
        bytes32 shareCommitment
    ) external onlyOwner(vaultId) vaultActive(vaultId) {
        require(!isTrustee[vaultId][trusteeAddr], "Already a trustee");
        require(trusteeAddr != msg.sender, "Owner cannot be trustee");

        Vault storage v = vaults[vaultId];
        isTrustee[vaultId][trusteeAddr] = true;
        trusteeIndex[vaultId][trusteeAddr] = trustees[vaultId].length;

        trustees[vaultId].push(Trustee({
            addr:              trusteeAddr,

            
            name:              trusteeName,
            hasSubmittedShare: false,
            hasConfirmedDeath: false,
            shareCommitment:   shareCommitment
        }));

        v.totalShares++;

        emit TrusteeAdded(vaultId, trusteeAddr, trusteeName);
    }

    function cancelVault(uint256 vaultId) external onlyOwner(vaultId) vaultActive(vaultId) {
        vaults[vaultId].status = VaultStatus.Cancelled;
        emit VaultCancelled(vaultId, msg.sender);
    }

    function confirmDeath(uint256 vaultId) external onlyTrustee(vaultId) vaultExists(vaultId) {
    Vault storage v = vaults[vaultId];
    require(
        v.status == VaultStatus.Active || v.status == VaultStatus.DeathReported,
        "Vault not active"
    );

    uint256 idx = trusteeIndex[vaultId][msg.sender];
    Trustee storage t = trustees[vaultId][idx];
    require(!t.hasConfirmedDeath, "Already confirmed");

    t.hasConfirmedDeath = true;
    deathConfirmations[vaultId]++;

    emit DeathReported(vaultId, msg.sender, deathConfirmations[vaultId]);

    if (deathConfirmations[vaultId] >= v.threshold) {
        v.status = VaultStatus.DeathReported;
    }
}
    

    function submitShare(
        uint256 vaultId,
        string memory encryptedShare
    ) external onlyTrustee(vaultId) vaultExists(vaultId) {
        Vault storage v = vaults[vaultId];

        bool deathConfirmed = v.status == VaultStatus.DeathReported;
        bool timelockExpired = block.timestamp >= v.timelockExpiry;

        require(deathConfirmed || timelockExpired, "Release conditions not met");
        require(v.status != VaultStatus.Released, "Already released");
        require(v.status != VaultStatus.Cancelled, "Vault cancelled");
        require(!hasSubmitted[vaultId][msg.sender], "Share already submitted");

        if (timelockExpired && v.status == VaultStatus.Active) {
            v.status = VaultStatus.DeathReported;
            emit TimelockTriggered(vaultId, v.timelockExpiry);
        }

        hasSubmitted[vaultId][msg.sender] = true;
        uint256 idx = trusteeIndex[vaultId][msg.sender];
        trustees[vaultId][idx].hasSubmittedShare = true;

        shareSubmissions[vaultId].push(ShareSubmission({
            trustee:        msg.sender,
            encryptedShare: encryptedShare,
            submittedAt:    block.timestamp
        }));

        v.sharesSubmitted++;
        emit ShareSubmitted(vaultId, msg.sender, v.sharesSubmitted);

        if (v.sharesSubmitted >= v.threshold) {
            v.status = VaultStatus.Released;
            emit VaultReleased(vaultId, v.beneficiary, block.timestamp);
        }
    }

    function getVault(uint256 vaultId) external view vaultExists(vaultId) returns (Vault memory) {
        return vaults[vaultId];
    }

    function getTrustees(uint256 vaultId) external view vaultExists(vaultId) returns (Trustee[] memory) {
        return trustees[vaultId];
    }

    function getShareSubmissions(uint256 vaultId) external view vaultExists(vaultId) returns (ShareSubmission[] memory) {
        Vault memory v = vaults[vaultId];
        require(msg.sender == v.beneficiary || msg.sender == v.owner, "Not authorized");
        return shareSubmissions[vaultId];
    }

    function isTimelockExpired(uint256 vaultId) external view vaultExists(vaultId) returns (bool) {
        return block.timestamp >= vaults[vaultId].timelockExpiry;
    }

    function getDeathConfirmations(uint256 vaultId) external view vaultExists(vaultId) returns (uint8) {
        return deathConfirmations[vaultId];
    }
}
